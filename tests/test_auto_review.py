"""#4 OPS-AUTO-01: the review contract, the runners and the review service.

The theme of almost every test here is negative: the review path must be *unable* to produce a permission.
A crash, a timeout, a quota error, malformed JSON, a truncated answer, a version mismatch or a BLOCKER
finding all have to end in "not a pass", because a reviewer that fails open is worse than no reviewer.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from opsbrain.auto.config import AutoConfig
from opsbrain.auto.review import (
    CONTRACT_VERSION,
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
from opsbrain.config import Config


def request_for(**overrides: Any) -> ReviewRequest:
    base = {"subject": Subject.INFRA_PLAN, "subject_ref": "pl-0000abcd", "objective": "fix the unit",
            "context": "evidence bundle contents", "evidence_refs": ("ev-0000abcd",), "model": "test-model"}
    return ReviewRequest(**{**base, **overrides})


def service(tmp_path: Path, reviewer: Any = None, **auto_overrides: Any) -> ReviewService:
    auto = AutoConfig(enabled=True, **auto_overrides)
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
    reviewer = CodexReviewer(RunnerSettings(runner="codex", command=("codex", "exec", "{prompt}")))
    with pytest.raises(ReviewerError, match="live runner is disabled"):
        reviewer.review(request_for())


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
                              snapshot_dir=str(tmp_path), model="m")
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
                              live=True, snapshot_dir=str(tmp_path), model="test-model")
    result = run_review(CodexReviewer(settings, runner=capture), request_for())
    assert result.is_pass is True
    assert seen["argv"][-1].endswith(".request.json")
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


def test_spend_budget_stops_before_spending(tmp_path: Path) -> None:
    runner = FakeReviewer()
    runner.default = response_document(Verdict.PASS, input_tokens=1_000_000, output_tokens=0)
    reviews = service(tmp_path, runner, review={"budget_usd": 0.01})
    first = reviews.review(request_for(objective="one"))
    assert first.status is RunnerStatus.OK
    second = reviews.review(request_for(objective="two"))
    assert second.status is RunnerStatus.BUDGET_EXCEEDED
    assert second.is_pass is False


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
    """Never runs in CI. Existence of the file is the whole opt-in switch, so no secret lives here."""
    settings = RunnerSettings(command=tuple(Path(os.environ["OPSBRAIN_LIVE_REVIEW"]).read_text().split()),
                              live=True, snapshot_dir=str(tmp_path))
    result = run_review(CodexReviewer(settings), request_for())
    assert result.status is not None, "a live runner still has to answer with a status"
