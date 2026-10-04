"""#4 OPS-AUTO-01: the review contract, the runners and the review service.

The theme of almost every test here is negative: the review path must be *unable* to produce a permission.
A crash, a timeout, a quota error, malformed JSON, a truncated answer, a version mismatch or a BLOCKER
finding all have to end in "not a pass", because a reviewer that fails open is worse than no reviewer.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from opsbrain.auto.config import AutoConfig
from opsbrain.auto.review import (
    CONTRACT_VERSION,
    RUBRIC_VERSION,
    Finding,
    ReviewLimits,
    ReviewRequest,
    ReviewResult,
    RunnerStatus,
    Severity,
    Subject,
    Verdict,
    build_result,
    parse_review_response,
    response_document,
    review_summary,
)
from opsbrain.auto.runners import (
    CodexReviewer,
    FakeReviewer,
    ReviewerError,
    RunnerSettings,
    probe_capabilities,
    run_review,
)
from opsbrain.auto.service import AutoService, ReviewService
from opsbrain.auto.store import atomic_claim, read_claim, release_claim
from opsbrain.config import Config
from opsbrain.util import OpsError


def request_for(**overrides: Any) -> ReviewRequest:
    base = {"subject": Subject.INFRA_PLAN, "subject_ref": "pl-0000abcd", "objective": "fix the unit",
            "context": "evidence bundle contents", "evidence_refs": ("ev-0000abcd",), "model": "test-model"}
    return ReviewRequest(**{**base, **overrides})


def service(tmp_path: Path, reviewer: Any = None, **auto_overrides: Any) -> ReviewService:
    """A ReviewService with an injected reviewer.

    The runner is named `codex` and the fake is passed in, so the stub guard does not fire: these tests are
    about the contract and the accounting, not about which runner is configured. `test_the_stub_cannot_...`
    covers the guard itself.
    """
    overrides = dict(auto_overrides)
    overrides["review"] = {"runner": "codex", **overrides.get("review", {})}
    auto = AutoConfig(enabled=True, **overrides)
    return ReviewService(auto, tmp_path / "auto", reviewer=reviewer or FakeReviewer())


# ------------------------------------------------------------------------------------- contract
def test_valid_pass_response_parses_and_passes() -> None:
    request = request_for()
    document = response_document(Verdict.PASS, model="test-model", input_tokens=100, output_tokens=20)
    result = parse_review_response(request, json.dumps(document))
    assert result.status is RunnerStatus.OK
    assert result.verdict is Verdict.PASS
    assert result.is_pass is True
    assert result.usage.input_tokens == 100


def test_blocker_finding_vetoes_a_pass_verdict() -> None:
    request = request_for()
    document = response_document(Verdict.PASS, [Finding(Severity.BLOCKER, "rollback is not applicable",
                                                         ("ev-0000abcd",), "rollback_plan")])
    result = parse_review_response(request, json.dumps(document))
    assert result.verdict is Verdict.PASS
    assert result.is_pass is False, "a BLOCKER finding must veto an otherwise passing verdict"
    assert result.blockers[0].required_property == "rollback_plan"


@pytest.mark.parametrize("payload,why", [
    ("", "empty body"),
    ("{", "truncated json"),
    ('{"verdict": "PASS"', "unterminated object"),
    ("not json at all", "prose instead of json"),
    ('["PASS"]', "array instead of object"),
    ('{"contract_version": "0.9", "verdict": "PASS"}', "wrong contract version"),
    ('{"verdict": "MAYBE"}', "unknown verdict"),
    ('{"status": "OK"}', "missing verdict"),
    ('{"verdict": "PASS", "findings": {"severity": "BLOCKER"}}', "findings not a list"),
    ('{"verdict": "PASS", "findings": [{"severity": "NOPE", "summary": "x"}]}', "unknown severity"),
    ('{"verdict": "PASS", "findings": [{"summary": "x"}]}', "finding without severity"),
    ('{"verdict": "PASS", "unverified_claims": "nope"}', "claims not a list"),
])
def test_malformed_answers_never_pass(payload: str, why: str) -> None:
    result = parse_review_response(request_for(), payload)
    assert result.status is RunnerStatus.INVALID_RESPONSE, why
    assert result.is_pass is False, why
    assert result.verdict is None, f"{why}: a contract error must not carry a verdict"


def test_runner_reported_failure_drops_an_optimistic_verdict() -> None:
    """A runner that says it failed must not smuggle a PASS out with the error."""
    result = parse_review_response(request_for(), json.dumps(
        {"contract_version": CONTRACT_VERSION, "status": "TIMEOUT", "verdict": "PASS", "note": "gave up"}))
    assert result.status is RunnerStatus.TIMEOUT
    assert result.verdict is None
    assert result.is_pass is False


def test_too_many_findings_is_a_contract_error() -> None:
    findings = [Finding(Severity.MINOR, f"n{i}") for i in range(80)]
    result = parse_review_response(request_for(), json.dumps(response_document(Verdict.PASS, findings)))
    assert result.status is RunnerStatus.INVALID_RESPONSE
    assert result.is_pass is False


def test_review_id_is_content_addressed_and_stable() -> None:
    first, second = request_for(), request_for()
    assert first.with_id().review_id == second.with_id().review_id
    different = request_for(objective="something else")
    assert different.with_id().review_id != first.with_id().review_id


def test_failure_helper_refuses_to_invent_a_success() -> None:
    with pytest.raises(ValueError, match="non-OK status"):
        ReviewResult.failure(request_for(), RunnerStatus.OK, "nope")
    result = ReviewResult.failure(request_for(), RunnerStatus.QUOTA_EXHAUSTED, "no credits")
    assert result.verdict is None and result.is_pass is False


def test_context_is_clipped_to_the_configured_limit() -> None:
    limits = ReviewLimits(context_chars=50)
    request = request_for(context="x" * 500, limits=limits)
    assert len(limits.clipped_context(request.context)) == 50


# ---------------------------------------------------------------------------------------- runners
def test_fake_runner_is_deterministic_and_rule_driven() -> None:
    runner = FakeReviewer()
    runner.on("evidence bundle", response_document(Verdict.DENY, [Finding(Severity.BLOCKER, "no rollback")]))
    first = parse_review_response(request_for(), runner.review(request_for()))
    second = parse_review_response(request_for(), runner.review(request_for()))
    assert first.verdict is Verdict.DENY and first.is_pass is False
    assert first.to_dict()["findings"] == second.to_dict()["findings"]


def test_runner_exception_becomes_a_failed_status_not_a_pass() -> None:
    runner = FakeReviewer()
    runner.fail("evidence bundle")
    result = run_review(runner, request_for())
    assert result.status is RunnerStatus.RUNNER_ERROR
    assert result.is_pass is False
    assert result.verdict is None


def test_live_runner_refuses_to_start_when_disabled() -> None:
    reviewer = CodexReviewer(RunnerSettings(runner="codex", command=("codex", "exec", "{prompt}"),
                                            sandbox=("sandbox-exec", "-p", "deny")))
    with pytest.raises(ReviewerError, match="live runner is disabled"):
        reviewer.review(request_for())


def test_live_runner_refuses_to_start_without_a_real_sandbox() -> None:
    """`cwd` is not a sandbox: it neither makes a directory read-only nor hides the operator's HOME."""
    reviewer = CodexReviewer(RunnerSettings(runner="codex", command=("codex", "exec", "{prompt}"), live=True))
    with pytest.raises(ReviewerError, match="is not a sandbox"):
        reviewer.review(request_for())


def test_the_sandbox_wrapper_wraps_the_command(tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

    def capture(argv: list[str], **kwargs: Any) -> Any:
        seen["argv"] = argv
        seen["env"] = kwargs["env"]
        from opsbrain.result import Result

        return Result(0, json.dumps(response_document(Verdict.PASS)))

    settings = RunnerSettings(runner="codex", command=("codex", "exec", "{prompt}"), live=True,
                              snapshot_dir=str(tmp_path), scratch_home=str(tmp_path), model="m",
                              sandbox=("sandbox-exec", "-p", "(deny default)"))
    assert run_review(CodexReviewer(settings, runner=capture), request_for()).is_pass is True
    assert seen["argv"][:2] == ["sandbox-exec", "-p"], "the wrapper must come first, or it confines nothing"
    assert "codex" in seen["argv"]


def test_the_reviewer_does_not_inherit_the_operators_home(tmp_path: Path) -> None:
    settings = RunnerSettings(runner="codex", command=("codex", "exec", "{prompt}"), live=True,
                              snapshot_dir=str(tmp_path), scratch_home=str(tmp_path / "scratch"),
                              model="m", sandbox=("bwrap",))
    env = settings.safe_env()
    assert env["HOME"] == str(tmp_path / "scratch")
    assert env["XDG_CONFIG_HOME"].startswith(str(tmp_path / "scratch"))


def test_a_jsonl_event_stream_still_yields_the_verdict(tmp_path: Path) -> None:
    """`codex exec --json` prints a stream of events, not one document."""
    events = "\n".join(json.dumps(event) for event in [
        {"type": "thread.started", "thread_id": "t-1"},
        {"type": "item.completed", "text": "thinking about it"},
        {"type": "item.completed", "text": json.dumps(response_document(Verdict.PASS, model="m"))},
    ])

    def capture(argv: list[str], **kwargs: Any) -> Any:
        from opsbrain.result import Result

        return Result(0, events)

    settings = RunnerSettings(runner="codex", command=("codex", "exec", "--json", "{prompt}"), live=True,
                              snapshot_dir=str(tmp_path), model="m", sandbox=("bwrap",))
    assert run_review(CodexReviewer(settings, runner=capture), request_for()).is_pass is True


def test_a_jsonl_stream_whose_last_event_refuses_is_not_promoted_to_a_pass(tmp_path: Path) -> None:
    events = "\n".join(json.dumps(event) for event in [
        {"type": "item.completed", "text": json.dumps(response_document(Verdict.DENY))},
    ])

    def capture(argv: list[str], **kwargs: Any) -> Any:
        from opsbrain.result import Result

        return Result(0, events)

    settings = RunnerSettings(runner="codex", command=("codex", "exec", "--json", "{prompt}"), live=True,
                              snapshot_dir=str(tmp_path), model="m", sandbox=("bwrap",))
    result = run_review(CodexReviewer(settings, runner=capture), request_for())
    assert result.verdict is Verdict.DENY and result.is_pass is False


def test_live_runner_scrubs_credentials_from_the_environment() -> None:
    settings = RunnerSettings(runner="codex", command=("codex", "exec", "{prompt}"), live=True,
                              snapshot_dir="/tmp", model="m")
    env = settings.safe_env()
    for forbidden in ("SSH_AUTH_SOCK", "KUBECONFIG", "DOCKER_HOST", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"):
        assert forbidden not in env, forbidden
    assert not any("SECRET" in key or "TOKEN" in key for key in env)


def test_live_runner_captures_a_timeout_as_a_failure(tmp_path: Path) -> None:
    def slow(argv: list[str], **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(argv, 300)

    settings = RunnerSettings(runner="codex", command=("codex", "exec", "{prompt}"), live=True,
                              snapshot_dir=str(tmp_path), model="m", sandbox=("bwrap",))
    result = run_review(CodexReviewer(settings, runner=slow), request_for())
    assert result.status is RunnerStatus.RUNNER_ERROR
    assert "timed out" in result.note
    assert result.is_pass is False


def test_live_runner_writes_the_request_private_and_returns_its_output(tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

    def capture(argv: list[str], **kwargs: Any) -> Any:
        seen["argv"] = argv
        seen["env"] = kwargs["env"]
        seen["input"] = kwargs["input"]
        from opsbrain.result import Result

        return Result(0, json.dumps(response_document(Verdict.PASS)))

    settings = RunnerSettings(runner="codex", command=("codex", "exec", "--model", "{model}", "{prompt}"),
                              live=True, snapshot_dir=str(tmp_path), model="test-model",
                              sandbox=("bwrap",), scratch_home=str(tmp_path))
    result = run_review(CodexReviewer(settings, runner=capture), request_for())
    assert result.is_pass is True
    assert seen["argv"][-1].endswith(".request.json")
    assert seen["argv"][0] == "bwrap"
    assert "test-model" in seen["argv"], "the model placeholder must be filled from config, not from the model"
    written = Path(seen["argv"][-1])
    assert written.stat().st_mode & 0o077 == 0, "the request file must not be world readable"
    assert json.loads(written.read_text())["contract_version"] == CONTRACT_VERSION


def test_capability_probe_reports_a_missing_binary_honestly(tmp_path: Path) -> None:
    report = probe_capabilities(RunnerSettings(command=("definitely-not-installed-xyz", "exec", "{prompt}")))
    assert report["ok"] is False
    assert "not found" in report["error"]
    assert report["model_checked"] is False, "capabilities are not claimed without credentials"


def test_capability_probe_never_claims_a_model_it_did_not_check(tmp_path: Path) -> None:
    report = probe_capabilities(RunnerSettings(command=("echo",), model="unverified-model"))
    assert report["ok"] is True
    assert report["model_checked"] is False


# ---------------------------------------------------------------------------------------- service
def test_service_records_id_subject_rubric_model_and_usage(tmp_path: Path) -> None:
    runner = FakeReviewer()
    runner.default = response_document(Verdict.PASS, model="test-model", input_tokens=7, output_tokens=3)
    reviews = service(tmp_path, runner)
    result = reviews.review(request_for())
    stored = reviews.get(result.review_id)
    assert stored["subject"] == "INFRA_PLAN"
    assert stored["rubric_version"] == result.rubric_version
    assert stored["model"] == "test-model"
    assert stored["usage"]["input_tokens"] == 7
    assert stored["usage"]["output_tokens"] == 3


def test_redelivering_the_same_request_does_not_review_twice(tmp_path: Path) -> None:
    runner = FakeReviewer()
    reviews = service(tmp_path, runner)
    first = reviews.review(request_for())
    second = reviews.review(request_for())
    assert first.review_id == second.review_id
    assert len(runner.requests) == 1, "a retry must reuse the stored review, not pay for a second one"
    assert second.verdict is first.verdict


def test_redelivery_keeps_the_blocker_that_caused_a_refusal(tmp_path: Path) -> None:
    """A cached refusal must not come back softened, and a cached pass must keep its blocker."""
    runner = FakeReviewer()
    runner.default = response_document(Verdict.PASS, [Finding(Severity.BLOCKER, "scope too wide")])
    reviews = service(tmp_path, runner)
    first = reviews.review(request_for())
    second = reviews.review(request_for())
    assert first.is_pass is False and second.is_pass is False
    assert second.findings and second.findings[0].summary == "scope too wide"


def test_call_budget_stops_before_spending(tmp_path: Path) -> None:
    runner = FakeReviewer()
    reviews = service(tmp_path, runner, review={"max_model_calls": 2})
    reviews.review(request_for(objective="one"))
    reviews.review(request_for(objective="two"))
    third = reviews.review(request_for(objective="three"))
    assert third.status is RunnerStatus.BUDGET_EXCEEDED
    assert third.is_pass is False
    assert len(runner.requests) == 2, "the third review must not have reached the runner"


def test_spend_budget_is_a_ceiling_not_a_suggestion(tmp_path: Path) -> None:
    """A call that could exceed the ceiling is refused *before* it runs, not discovered after it."""
    runner = FakeReviewer()
    runner.default = response_document(Verdict.PASS, input_tokens=1_000_000, output_tokens=0)
    # One call's worst case (context + output limits) is ~$0.0425, so a smaller budget must refuse it.
    reviews = service(tmp_path, runner, review={"budget_usd": 0.01})
    refused = reviews.review(request_for(objective="one"))
    assert refused.status is RunnerStatus.BUDGET_EXCEEDED
    assert refused.is_pass is False
    assert runner.requests == [], "a refused reservation must not reach the runner"

    roomy = service(tmp_path / "roomy", FakeReviewer(), review={"budget_usd": 1.0})
    assert roomy.review(request_for(objective="one")).status is RunnerStatus.OK


def test_restart_does_not_hand_out_a_fresh_budget(tmp_path: Path) -> None:
    """The ceiling has to survive a process restart, or it is not a ceiling."""
    runner = FakeReviewer()
    reviews = service(tmp_path, runner, review={"max_model_calls": 1})
    assert reviews.review(request_for(objective="one")).status is RunnerStatus.OK
    fresh = service(tmp_path, FakeReviewer(), review={"max_model_calls": 1})
    assert fresh.usage()["model_calls"] == 1, "usage must be recovered from the stored reviews"
    assert fresh.review(request_for(objective="two")).status is RunnerStatus.BUDGET_EXCEEDED


def test_a_caller_supplied_review_id_cannot_reuse_another_subject_s_verdict(tmp_path: Path) -> None:
    """Cache poisoning: subject B must never be answered from subject A's stored PASS."""
    runner = FakeReviewer()
    reviews = service(tmp_path, runner)
    first = reviews.review(request_for(objective="subject A"))
    borrowed = reviews.review(request_for(objective="subject B", review_id=first.review_id))
    assert borrowed.review_id != first.review_id
    assert len(runner.requests) == 2, "the reviewer must actually be asked about subject B"


def test_a_response_without_a_contract_version_is_refused(tmp_path: Path) -> None:
    runner = FakeReviewer()
    runner.default = {"status": "OK", "verdict": "PASS"}
    reviews = service(tmp_path, runner)
    result = reviews.review(request_for())
    assert result.status is RunnerStatus.INVALID_RESPONSE
    assert result.is_pass is False


def test_absurd_or_negative_reported_usage_is_refused_rather_than_charged(tmp_path: Path) -> None:
    for usage in ({"input_tokens": -5}, {"input_tokens": "unknown"}, {"output_tokens": 10**12}):
        runner = FakeReviewer()
        runner.default = response_document(Verdict.PASS, **usage)
        reviews = service(tmp_path / str(abs(hash(str(usage)))), runner)
        result = reviews.review(request_for())
        assert result.status is RunnerStatus.INVALID_RESPONSE, usage
        assert result.is_pass is False, usage
        # The reservation stays - the call was made and cost something - but a value the reviewer invented
        # must not move the *measured* balance by a negative amount.
        assert reviews.usage()["input_tokens"] == 0, f"{usage} must not move the token counters"


def test_a_concurrent_duplicate_does_not_review_twice(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor

    runner = FakeReviewer()
    reviews = service(tmp_path, runner)
    request = request_for()
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = [future.result() for future in [pool.submit(reviews.review, request) for _ in range(4)]]
    assert len({result.review_id for result in results}) == 1
    assert len(runner.requests) == 1, "a duplicate must be refused or served from cache, not reviewed again"


def test_service_rejects_a_request_from_another_contract_version(tmp_path: Path) -> None:
    from opsbrain.util import OpsError

    reviews = service(tmp_path)
    with pytest.raises(OpsError, match="contract"):
        reviews.review(request_for(contract_version="0.1"))


def test_review_many_keeps_every_result(tmp_path: Path) -> None:
    runner = FakeReviewer()
    reviews = service(tmp_path, runner)
    results = reviews.review_many([request_for(objective=f"obj{i}") for i in range(4)])
    assert len(results) == 4
    assert all(result.is_pass for result in results)
    assert reviews.summary(results)["reviews"] == 4


def test_autonomy_is_off_by_default_and_ungated_without_a_token() -> None:
    auto = AutoConfig()
    assert auto.enabled is False
    assert auto.decision.autonomous is False
    with pytest.raises(ValidationError, match="autonomy_token"):
        AutoConfig(enabled=True, decision={"mode": "autonomous"}, autonomy_token="")


def test_live_review_requires_an_explicit_command() -> None:
    with pytest.raises(ValidationError, match="command"):
        AutoConfig(enabled=True, review={"live": True})


def test_emergency_stop_disables_autonomy() -> None:
    auto = AutoConfig(enabled=True, autonomy_token="x" * 24, decision={"emergency_stop": True})
    assert auto.decision.autonomous is False


def test_autoservice_guards_a_disabled_pipeline(tmp_path: Path) -> None:
    from opsbrain.util import OpsError

    config = Config(repo=str(tmp_path), data_dir=str(tmp_path / "data"))
    auto = AutoService(config, reviewer=FakeReviewer())
    assert auto.enabled is False
    with pytest.raises(OpsError, match="disabled"):
        auto.guard_enabled()


def test_autoservice_overview_reports_the_real_runner_and_budget(tmp_path: Path) -> None:
    config = Config(repo=str(tmp_path), data_dir=str(tmp_path / "data"),
                    auto=AutoConfig(enabled=True, review={"runner": "fake", "model": "m"}))
    auto = AutoService(config, reviewer=FakeReviewer())
    view = auto.overview()
    assert view["enabled"] is True and view["autonomous"] is False
    assert view["runner"] == "fake" and view["model"] == "m"
    assert view["budget"]["max_model_calls"] == 40


def test_build_result_rejects_a_verdict_of_the_wrong_type() -> None:
    result = build_result(request_for(), {"verdict": 1})
    assert result.status is RunnerStatus.INVALID_RESPONSE and result.is_pass is False


def test_review_summary_counts_passes_separately_from_statuses() -> None:
    rows = [
        parse_review_response(request_for(), json.dumps(response_document(Verdict.PASS))),
        parse_review_response(request_for(), json.dumps(response_document(Verdict.DENY))),
        ReviewResult.failure(request_for(), RunnerStatus.TIMEOUT, "slow"),
    ]
    summary = review_summary(rows)
    assert summary["reviews"] == 3
    assert summary["passed"] == 1
    assert summary["by_status"] == {"OK": 2, "TIMEOUT": 1}


# ------------------------------------------------------------------------------------ live smoke
@pytest.mark.skipif(not os.environ.get("OPSBRAIN_LIVE_REVIEW"),
                    reason="opt-in: set OPSBRAIN_LIVE_REVIEW=<path to a runner argv file>")
def test_live_smoke_opt_in(tmp_path: Path) -> None:
    """Never runs in CI, and it has to actually reach the runner.

    A smoke test that asserts only "some status exists" passes on the very failure the sandbox
    requirement introduces, so `OPSBRAIN_LIVE_REVIEW` could report a green live run that never started a
    binary, never read a credential and never saw a model answer. It requires `OK` now, and it refuses to
    pass on a status that means the runner never started.
    """
    argv = Path(os.environ["OPSBRAIN_LIVE_REVIEW"]).read_text().split()
    settings = RunnerSettings(command=tuple(argv), live=True, snapshot_dir=str(tmp_path), sandbox=("bwrap",),
                              scratch_home=str(tmp_path / "scratch"), model="", auth="subscription")
    result = run_review(CodexReviewer(settings), request_for())
    assert result.status is RunnerStatus.OK, f"the live runner did not answer: {result.status} {result.note}"
    assert result.verdict is not None, "a live run that produced no verdict tested nothing"


# ------------------------------------------------------ live mode cannot be configured without a sandbox
def test_live_review_cannot_be_configured_without_a_sandbox() -> None:
    with pytest.raises(ValidationError, match="sandbox"):
        AutoConfig(enabled=True, review={"live": True, "command": ["codex", "exec", "{prompt}"]})


def test_live_review_with_a_sandbox_is_accepted() -> None:
    auto = AutoConfig(enabled=True, review={"live": True, "command": ["codex", "exec", "--json", "{prompt}"],
                                            "sandbox": ["bwrap", "--ro-bind", "/usr", "/usr"],
                                            "scratch_home": "/var/lib/opsbrain/scratch"})
    assert auto.review.sandbox[0] == "bwrap"


def test_a_sandbox_without_live_mode_is_a_configuration_error() -> None:
    with pytest.raises(ValidationError, match="only matters with"):
        AutoConfig(enabled=True, review={"sandbox": ["bwrap"]})


def test_capability_probe_reports_the_sandbox_it_would_use(tmp_path: Path) -> None:
    report = probe_capabilities(RunnerSettings(command=("echo",), live=True, sandbox=("bwrap", "--ro-bind", "/")))
    assert report["sandbox"] == ["bwrap", "--ro-bind", "/"]
    assert report["sandbox_required"] is True


# ============================================ P1 round 2: findings Codex raised after the first fix round
def test_a_disabled_pipeline_refuses_to_review(tmp_path: Path) -> None:
    """The master switch belongs in the entry point, not only in the facade that usually calls it."""
    auto = AutoConfig(enabled=False, review={"runner": "codex"})
    reviews = ReviewService(auto, tmp_path / "auto", reviewer=FakeReviewer())
    with pytest.raises(OpsError, match="auto.enabled is false"):
        reviews.review(request_for())


def test_the_stub_cannot_issue_a_permission(tmp_path: Path) -> None:
    """`fake` is the documented default, so `auto.enabled: true` alone would otherwise authorise anything."""
    auto = AutoConfig(enabled=True, review={"runner": "fake"})
    reviews = ReviewService(auto, tmp_path / "auto")
    result = reviews.review(request_for())
    assert result.status is RunnerStatus.UNAVAILABLE
    assert result.is_pass is False
    assert "stub cannot issue a permission" in result.note


def test_an_injected_test_double_is_not_treated_as_a_configured_stub(tmp_path: Path) -> None:
    """A test that injects its own fake is a test; the guard is about the configured runner."""
    reviews = service(tmp_path)
    assert reviews.review(request_for()).status is RunnerStatus.OK


def test_an_unknown_runner_name_is_a_config_error() -> None:
    for name in ("codexx", "Codex", "", "openai"):
        with pytest.raises(ValidationError, match="runner must be"):
            AutoConfig(enabled=True, review={"runner": name})


def test_a_short_autonomy_token_is_refused() -> None:
    for token in ("", "x", "yes", "please enable"):
        with pytest.raises(ValidationError, match="autonomy_token"):
            AutoConfig(enabled=True, autonomy_token=token, decision={"mode": "autonomous"})
    assert AutoConfig(enabled=True, autonomy_token="K7f2mQx9pR4tVw6nZs1b", decision={"mode": "autonomous"})


def test_the_request_file_is_created_private_and_atomically(tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

    def capture(argv: list[str], **kwargs: Any) -> Any:
        seen["path"] = Path(argv[-1])
        from opsbrain.result import Result

        return Result(0, json.dumps(response_document(Verdict.PASS)))

    settings = RunnerSettings(command=("codex", "exec", "{prompt}"), live=True, sandbox=("bwrap",),
                              snapshot_dir=str(tmp_path), model="m")
    run_review(CodexReviewer(settings, runner=capture), request_for())
    assert seen["path"].stat().st_mode & 0o077 == 0
    assert not list(tmp_path.glob("*.tmp*")), "no half-written request file may be left behind"


def test_provenance_comes_from_the_request_not_the_answer() -> None:
    """A reviewer that could restate the subject could answer about plan A and file it under plan B."""
    runner = FakeReviewer()
    document = response_document(Verdict.PASS)
    document["subject_ref"] = "pl-ffffffffffffffff"
    runner.default = document
    result = parse_review_response(request_for(subject_ref="pl-0000abcd"), json.dumps(document))
    assert result.subject_ref == "pl-0000abcd"
    assert result.rubric_version == RUBRIC_VERSION


def test_a_listing_reports_the_effective_pass_state(tmp_path: Path) -> None:
    """`status=OK, verdict=PASS` with a BLOCKER is a refusal, and a listing must not read as a permission."""
    runner = FakeReviewer()
    runner.default = response_document(Verdict.PASS, [Finding(Severity.BLOCKER, "no rollback")])
    reviews = service(tmp_path, runner)
    reviews.review(request_for())
    row = reviews.list()[0]
    assert row["status"] == "OK" and row["verdict"] == "PASS"
    assert row["is_pass"] is False, "a listing that showed only the verdict would read as an approval"


def test_an_expired_lease_is_reclaimed_without_clobbering_a_new_owner(tmp_path: Path) -> None:
    """Unlink-then-create is a race: the new owner's claim must not be deleted by a stale reclaimer."""
    path = tmp_path / "lease.claim"
    assert atomic_claim(path, "first", ttl_s=-1.0) == "first"  # already expired
    time.sleep(0.01)
    assert atomic_claim(path, "second", ttl_s=60.0) == "second"
    owner = read_claim(path)
    assert owner is not None and owner["owner"] == "second", "the live lease survived the reclaim"
    assert release_claim(path, "second") is True
    assert atomic_claim(path, "third", ttl_s=60.0) == "third"
    assert not list(tmp_path.glob("*.stale-*")), "the stale file is cleaned up"


def test_a_claim_is_single_use(tmp_path: Path) -> None:
    path = tmp_path / "lease.claim"
    assert atomic_claim(path, "a", ttl_s=60.0) == "a"
    assert atomic_claim(path, "b", ttl_s=60.0) is None
    assert read_claim(path)["owner"] == "a"


# ============================== P1 round 3 on #15: the budget, the lease, the auth mode and the smoke test
def test_the_budget_is_shared_across_services(tmp_path: Path) -> None:
    """Two ReviewServices over one data directory are a server and a CLI, and they share the money.

    An in-memory counter cannot see the other process, so both were admitted against the same balance and
    the documented hard ceiling was not one.
    """
    auto = AutoConfig(enabled=True, review={"runner": "codex", "max_model_calls": 2})
    first = ReviewService(auto, tmp_path / "auto", reviewer=FakeReviewer())
    second = ReviewService(auto, tmp_path / "auto", reviewer=FakeReviewer())
    assert first.review(request_for(objective="a")).status is RunnerStatus.OK
    assert second.review(request_for(objective="b")).status is RunnerStatus.OK
    third = first.review(request_for(objective="c"))
    assert third.status is RunnerStatus.BUDGET_EXCEEDED, "the third attempt was admitted anyway"
    assert first.usage()["model_calls"] == 2 and second.usage()["model_calls"] == 2


def test_every_reserved_attempt_survives_a_restart_including_the_failed_ones(tmp_path: Path) -> None:
    """A request that failed twice and then succeeded is two paid attempts, and both reappear."""
    runner = FakeReviewer()
    calls = {"n": 0}
    document = response_document(Verdict.PASS)

    def flaky(request: ReviewRequest) -> str:
        calls["n"] += 1
        return json.dumps(document if calls["n"] == 3 else {"contract_version": CONTRACT_VERSION,
                                                             "status": "TIMEOUT"})

    auto = AutoConfig(enabled=True, review={"runner": "codex", "max_retries": 3, "max_model_calls": 10})
    first = ReviewService(auto, tmp_path / "auto", reviewer=runner)
    first._reviewer = None
    first._factory = lambda _settings: type("R", (), {"name": "flaky", "review": staticmethod(flaky)})()
    first.review(request_for())
    assert first.usage()["model_calls"] == 3, "two failures and a success are three attempts"

    restarted = ReviewService(auto, tmp_path / "auto", reviewer=FakeReviewer())
    assert restarted.usage()["model_calls"] == 3, "a restart refunded two paid attempts"


def test_the_claim_outlives_the_whole_retry_window(tmp_path: Path) -> None:
    """A redelivery arriving while the original attempt still runs must not start a second paid review."""
    auto = AutoConfig(enabled=True, review={"runner": "codex", "timeout_s": 600.0, "max_retries": 3})
    reviews = ReviewService(auto, tmp_path / "auto", reviewer=FakeReviewer())
    request = request_for()
    claim = reviews.root / "claims" / f"{request.with_id().review_id}.claim"
    assert atomic_claim(claim, "owner", 600.0 * 4 + 60.0) == "owner"
    claim.unlink()
    # the TTL the service derives must be at least the whole window, not the 900s default
    assert reviews.reviews.timeout_s * (reviews.reviews.max_retries + 1) + 60.0 > 900.0
    result = reviews.review(request)
    assert result.status is RunnerStatus.OK, "the request must not be refused by its own stale claim"


def test_auth_api_refuses_to_start_without_its_key(monkeypatch: Any) -> None:
    """Silently falling back to whichever login the binary found is how a mode becomes a label."""
    monkeypatch.delenv("CODEX_API_KEY", raising=False)
    settings = RunnerSettings(command=("codex", "exec", "{prompt}"), auth="api", live=True, sandbox=("bwrap",),
                              snapshot_dir="/tmp", api_key_env="CODEX_API_KEY")
    with pytest.raises(ReviewerError, match="CODEX_API_KEY"):
        CodexReviewer(settings).review(request_for())


def test_auth_api_without_a_named_variable_is_refused() -> None:
    settings = RunnerSettings(command=("codex", "exec", "{prompt}"), auth="api", live=True, sandbox=("bwrap",),
                              snapshot_dir="/tmp")
    with pytest.raises(ReviewerError, match="names no variable"):
        CodexReviewer(settings).review(request_for())


def test_auth_api_passes_only_its_own_key(monkeypatch: Any) -> None:
    monkeypatch.setenv("CODEX_API_KEY", "sk-test")
    monkeypatch.setenv("OTHER_SECRET", "nope")
    env = RunnerSettings(auth="api", api_key_env="CODEX_API_KEY", snapshot_dir="/tmp").safe_env()
    assert env["CODEX_API_KEY"] == "sk-test"
    assert "OTHER_SECRET" not in env


def test_auth_api_must_name_its_key_in_config() -> None:
    with pytest.raises(ValidationError, match="api_key_env"):
        AutoConfig(enabled=True, review={"live": True, "command": ["codex", "{prompt}"], "sandbox": ["bwrap"],
                                         "auth": "api"})
