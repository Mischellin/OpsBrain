"""#6 OPS-AUTO-03: the change plan and its preflight review.

The acceptance list for this issue is a list of ways a wrong plan can talk its way past a reviewer, and most
of them are already in the fixtures below: a drop-in in the wrong directory that still exits 0, a command
that succeeds without touching the target state, a base64 blob mistaken for evidence of encryption, and an
absence in one directory mistaken for proof of absence. A plan that gets any of those past a PASS has not
been reviewed, it has been agreed with.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from opsbrain.auto.config import AutoConfig
from opsbrain.auto.plan import ChangePlan, PlanError, ProposedChange, Reversibility, Risk
from opsbrain.auto.preflight import (
    REASON_BY_OUTCOME,
    Outcome,
    Preflight,
    declared_state_changing,
    split_probes,
)
from opsbrain.auto.review import Finding, Severity, Verdict, response_document
from opsbrain.auto.runners import FakeReviewer
from opsbrain.auto.service import ReviewService

DROP_IN = "/etc/systemd/system/logrotate.service.d/custom.conf"


def unit_change(target: str = "web-1", **overrides: Any) -> ProposedChange:
    base: dict[str, Any] = {"capability": "ansible.apply", "target": target,
                            "how": f"install a logrotate drop-in into {DROP_IN}",
                            "reversible": Reversibility.ROLLBACK,
                            "undo": f"rm -f {DROP_IN} && systemctl daemon-reload"}
    return ProposedChange(**{**base, **overrides})


def good_plan(**overrides: Any) -> ChangePlan:
    base: dict[str, Any] = {
        "objective": "logrotate stops on web-1",
        "diagnosis": "the timer is enabled but its drop-in directory is wrong, so the unit runs with the "
                     "distribution defaults and never rotates",
        "changes": [unit_change()],
        "evidence_refs": ["ev-0000abcd"],
        "versions": {"systemd": "252", "logrotate": "3.21.0"},
        "post_checks": ["systemctl show logrotate.service -p FragmentPath,DropInPaths",
                        "logrotate --debug /etc/logrotate.conf"],
        "preconditions": ["web-1 is reachable", "the current drop-in is captured"],
        "rollback": f"rm -f {DROP_IN} && systemctl daemon-reload && systemctl start logrotate.timer",
    }
    return ChangePlan.build(**{**base, **overrides})


def preflight(tmp_path: Path, reviewer: Any = None, plan: ChangePlan | None = None) -> Any:
    auto = AutoConfig(enabled=True)
    reviews = ReviewService(auto, tmp_path / "auto", reviewer=reviewer or FakeReviewer())
    return Preflight(auto, reviews, tmp_path / "auto"), (plan or good_plan())


# ----------------------------------------------------------------------------------- the plan shape
def test_a_plan_carries_the_whole_proposal() -> None:
    plan = good_plan()
    assert plan.id.startswith("pl-")
    assert plan.arguments_hash and plan.plan_hash
    assert plan.targets == ("web-1",)
    assert plan.blast() == ("web-1",)
    assert plan.reversibility is Reversibility.ROLLBACK
    assert plan.incomplete() == ()


def test_the_id_is_the_arguments_hash() -> None:
    plan = good_plan()
    assert plan.id == f"pl-{plan.arguments_hash[:16]}"


def test_changing_the_diagnosis_moves_the_plan_hash_but_not_the_arguments() -> None:
    """`arguments_hash` is what would run; `plan_hash` is the whole argument, reasoning included."""
    other = good_plan(diagnosis="a different explanation for the same edit")
    assert other.arguments_hash == good_plan().arguments_hash
    assert other.plan_hash != good_plan().plan_hash


def test_changing_how_moves_both_hashes() -> None:
    other = good_plan(changes=[unit_change(how="install the drop-in somewhere else entirely")])
    assert other.arguments_hash != good_plan().arguments_hash
    assert other.plan_hash != good_plan().plan_hash


def test_a_plan_without_a_diagnosis_is_refused() -> None:
    with pytest.raises(PlanError, match="diagnosis"):
        ChangePlan.build(objective="x", diagnosis="  ", changes=[unit_change()], rollback="undo")


def test_a_plan_without_changes_is_refused() -> None:
    with pytest.raises(PlanError, match="no changes"):
        ChangePlan.build(objective="x", diagnosis="y", changes=[], rollback="undo")


def test_a_vague_proposal_is_refused() -> None:
    with pytest.raises(PlanError, match="no `how`"):
        unit_change(how="   ")


def test_reversible_without_an_undo_is_refused() -> None:
    with pytest.raises(PlanError, match="names no undo"):
        unit_change(undo="")


def test_irreversible_without_a_reason_is_refused() -> None:
    with pytest.raises(PlanError, match="irreversible without a reason"):
        unit_change(reversible=Reversibility.IRREVERSIBLE, undo="", irreversible_reason="  ")


def test_irreversible_is_allowed_with_a_stated_reason() -> None:
    plan = good_plan(changes=[unit_change(reversible=Reversibility.IRREVERSIBLE, undo="",
                                        irreversible_reason="the old data volume is overwritten in place")],
                     rollback="", reversibility=Reversibility.IRREVERSIBLE)
    assert plan.irreversible is True
    assert "irreversible" in plan.render_for_reviewer()


def test_the_worst_reversibility_in_the_plan_wins() -> None:
    plan = good_plan(changes=[unit_change(), unit_change(target="web-2", reversible=Reversibility.IRREVERSIBLE,
                                                        undo="", irreversible_reason="destroys the state")],
                     rollback="", reversibility=None)
    assert plan.reversibility is Reversibility.IRREVERSIBLE


def test_a_missing_rollback_is_refused_when_the_plan_claims_to_be_reversible() -> None:
    with pytest.raises(PlanError, match="must name its rollback"):
        ChangePlan.build(objective="x", diagnosis="y", changes=[unit_change()], rollback="")


def test_targets_are_derived_when_the_author_forgets_them() -> None:
    plan = good_plan(targets=[])
    assert plan.targets == ("web-1",), "a plan that forgot its scope must not be judged against an empty one"


def test_a_plan_survives_a_round_trip_and_detects_tampering() -> None:
    plan = good_plan()
    reloaded = ChangePlan.from_dict(json.loads(json.dumps(plan.to_dict())))
    assert reloaded.plan_hash == plan.plan_hash
    assert reloaded.compute_plan_hash() == plan.compute_plan_hash()
    # `arguments_hash` covers the commands and the id derives from it, so a rewritten diagnosis leaves both
    # untouched. `plan_hash` is the only thing standing between that edit and an approval granted for the
    # reasoning it replaced.
    document = plan.to_dict()
    document["diagnosis"] = "something else entirely"
    with pytest.raises(PlanError, match="plan hash does not match"):
        ChangePlan.from_dict(document)


def test_a_forged_plan_id_is_refused() -> None:
    document = good_plan().to_dict()
    document["id"] = "pl-0000000000000000"
    with pytest.raises(PlanError, match="does not match its arguments hash"):
        ChangePlan.from_dict(document)


# --------------------------------------------------------------------------------- structural gaps
def test_a_plan_with_no_evidence_is_structurally_incomplete() -> None:
    plan = good_plan(evidence_refs=[])
    assert any("no evidence" in gap for gap in plan.incomplete())


def test_a_plan_with_no_versions_is_structurally_incomplete() -> None:
    plan = good_plan(versions={})
    assert any("component versions" in gap for gap in plan.incomplete())


def test_a_plan_with_no_post_checks_is_structurally_incomplete() -> None:
    plan = good_plan(post_checks=[])
    assert any("no post-check" in gap for gap in plan.incomplete())


def test_structural_gaps_beat_a_passing_reviewer(tmp_path: Path) -> None:
    """A reviewer can only judge the plan it read. If the plan has no evidence, PASS is about a fiction."""
    runner = FakeReviewer()
    runner.default = response_document(Verdict.PASS)
    engine, plan = preflight(tmp_path, runner, good_plan(evidence_refs=[], post_checks=[]))
    result = engine.run(plan)
    assert result.outcome is Outcome.INCOMPLETE
    assert result.approvable is False
    assert result.structural_gaps


# -------------------------------------------------------------------------------------- preflight
def test_a_clean_plan_with_a_passing_review_is_approvable(tmp_path: Path) -> None:
    runner = FakeReviewer()
    runner.default = response_document(Verdict.PASS, model="m")
    engine, plan = preflight(tmp_path, runner)
    result = engine.run(plan)
    assert result.outcome is Outcome.APPROVABLE
    assert result.approvable is True
    assert result.reason == "review_passed"
    assert result.verdict is Verdict.PASS


@pytest.mark.parametrize("verdict,outcome", [
    (Verdict.NEEDS_CHANGES, Outcome.NEEDS_CHANGES),
    (Verdict.NEEDS_EVIDENCE, Outcome.NEEDS_EVIDENCE),
    (Verdict.DENY, Outcome.DENIED),
])
def test_each_verdict_maps_to_its_own_outcome(tmp_path: Path, verdict: Verdict, outcome: Outcome) -> None:
    runner = FakeReviewer()
    runner.default = response_document(verdict)
    engine, plan = preflight(tmp_path, runner)
    result = engine.run(plan)
    assert result.outcome is outcome
    assert result.approvable is False
    assert result.reason == REASON_BY_OUTCOME[outcome]


@pytest.mark.parametrize("payload,why", [
    ("", "empty"),
    ("{", "truncated"),
    ('{"verdict": "PASS"}', "no contract_version"),
])
def test_a_malformed_answer_never_approves(tmp_path: Path, payload: str, why: str) -> None:
    runner = FakeReviewer()
    runner.default = payload
    engine, plan = preflight(tmp_path, runner)
    result = engine.run(plan)
    assert result.outcome is Outcome.REVIEW_FAILED, why
    assert result.approvable is False, why


def test_a_runner_crash_never_approves(tmp_path: Path) -> None:
    runner = FakeReviewer()
    runner.fail("CHANGE PLAN")
    engine, plan = preflight(tmp_path, runner)
    result = engine.run(plan)
    assert result.outcome is Outcome.REVIEW_FAILED
    assert result.approvable is False


def test_a_blocker_finding_vetoes_the_pass(tmp_path: Path) -> None:
    runner = FakeReviewer()
    runner.default = response_document(Verdict.PASS, [Finding(Severity.BLOCKER, "the rollback is not applicable")])
    engine, plan = preflight(tmp_path, runner)
    result = engine.run(plan)
    assert result.approvable is False
    assert result.findings[0]["severity"] == "BLOCKER"


# ------------------------------------------------------- regression: logrotate.d vs logrotate.service.d
def test_a_drop_in_in_the_wrong_directory_does_not_pass(tmp_path: Path) -> None:
    """The fixture from the issue: an apply that exits 0, into a directory systemd never reads.

    `logrotate.d` holds logrotate's own configuration. systemd reads `logrotate.service.d`. The command
    succeeds, the file exists, and the service is unaffected - which is why a post-check has to inspect the
    unit's effective drop-in chain rather than trust the exit code.
    """
    runner = FakeReviewer()
    runner.on("logrotate.d", response_document(Verdict.NEEDS_CHANGES, [
        Finding(Severity.BLOCKER, f"the plan writes to /etc/logrotate.d, but systemd reads {DROP_IN}",
                ("ev-0000abcd",), "correct_dropin_path")]))
    plan = good_plan(changes=[unit_change(how="install a logrotate drop-in into /etc/logrotate.d/custom.conf",
                                           undo="rm -f /etc/logrotate.d/custom.conf")],
                     post_checks=["test -f /etc/logrotate.d/custom.conf"])
    engine = Preflight(AutoConfig(enabled=True), ReviewService(AutoConfig(enabled=True), tmp_path / "auto",
                                                                reviewer=runner), tmp_path / "auto")
    result = engine.run(plan)
    assert result.outcome is Outcome.NEEDS_CHANGES
    assert result.approvable is False
    assert "systemd reads" in result.findings[0]["summary"]


def test_a_post_check_that_only_runs_the_command_is_visible_to_the_reviewer(tmp_path: Path) -> None:
    """`ansible-playbook --check` exiting 0 is not evidence that the service works afterwards."""
    runner = FakeReviewer()
    runner.on("ansible-playbook", response_document(Verdict.NEEDS_CHANGES, [
        Finding(Severity.MAJOR, "the only post-check runs the apply again; it never inspects the unit's "
                                "effective configuration")]))
    plan = good_plan(post_checks=["ansible-playbook common.yml --check --diff"])
    engine = Preflight(AutoConfig(enabled=True), ReviewService(AutoConfig(enabled=True), tmp_path / "auto",
                                                                reviewer=runner), tmp_path / "auto")
    result = engine.run(plan)
    assert result.approvable is False
    assert "never inspects" in result.findings[0]["summary"]


def test_base64_in_a_kubernetes_api_is_not_proof_of_encryption(tmp_path: Path) -> None:
    runner = FakeReviewer()
    runner.on("base64", response_document(Verdict.NEEDS_CHANGES, [
        Finding(Severity.MAJOR, "a base64 value in the API is encoding, not encryption; "
                                "show storageClass.encrypted: true or a CSI driver")]))
    plan = good_plan(diagnosis="the PVC is unencrypted, as shown by the base64 data in the API",
                     post_checks=["kubectl get pvc -o yaml"])
    engine = Preflight(AutoConfig(enabled=True), ReviewService(AutoConfig(enabled=True), tmp_path / "auto",
                                                                reviewer=runner), tmp_path / "auto")
    result = engine.run(plan)
    assert result.approvable is False
    assert "not encryption" in result.findings[0]["summary"]


def test_absence_in_one_directory_is_not_proof_of_absence(tmp_path: Path) -> None:
    runner = FakeReviewer()
    runner.on("the fix is absent", response_document(Verdict.NEEDS_EVIDENCE, next_checks=[
        "systemctl show logrotate.service -p DropInPaths",
        "ls -la /etc/systemd/system/logrotate.service.d/"]))
    plan = good_plan(diagnosis="the drop-in is missing, therefore the fix is absent")
    engine = Preflight(AutoConfig(enabled=True), ReviewService(AutoConfig(enabled=True), tmp_path / "auto",
                                                                reviewer=runner), tmp_path / "auto")
    result = engine.run(plan)
    assert result.outcome is Outcome.NEEDS_EVIDENCE
    assert result.requested_probes


# ------------------------------------------------------------------- probes: read-only vs experiment
def test_a_state_changing_request_is_not_filed_as_a_read_only_probe() -> None:
    read_only, acting = split_probes([
        "systemctl show logrotate.service -p FragmentPath",
        "journalctl -u logrotate.timer --since -1h",
        "restart logrotate.timer to see whether the symptom disappears",
    ])
    assert len(read_only) == 2
    assert acting == ("restart logrotate.timer to see whether the symptom disappears",)


@pytest.mark.parametrize("check,acting", [
    ("systemctl restart logrotate.timer", True),
    ("delete the unit to reproduce the failure", True),
    ("kubectl scale deploy/api --replicas=0", True),
    ("reboot the node", True),
    ("systemctl show logrotate.service", False),
    ("kubectl get pvc -o yaml", False),
    ("cat /etc/logrotate.conf", False),
])
def test_verbs_that_mark_a_request_as_an_experiment(check: str, acting: bool) -> None:
    _, acting_requests = split_probes([check])
    assert bool(acting_requests) is acting


def test_requested_experiments_are_reported_separately(tmp_path: Path) -> None:
    runner = FakeReviewer()
    runner.default = response_document(Verdict.NEEDS_EVIDENCE, next_checks=[
        "systemctl show logrotate.service -p DropInPaths",
        "restart the timer and watch whether the symptom clears"])
    engine, plan = preflight(tmp_path, runner)
    result = engine.run(plan)
    assert len(result.requested_probes) == 1
    assert len(result.state_changing_probes) == 1
    assert "restart" in result.state_changing_probes[0]


# ------------------------------------------------------------------------------- declaration & wiring
def test_a_plan_declares_its_state_changing_actions_in_advance() -> None:
    plan = good_plan(changes=[unit_change(), unit_change(target="web-2", state_changing=False)])
    assert declared_state_changing(plan) == ("ansible.apply:web-1",), "verification may act only on this set"


def test_preflight_records_its_outcome_for_later_audit(tmp_path: Path) -> None:
    runner = FakeReviewer()
    runner.default = response_document(Verdict.PASS)
    engine, plan = preflight(tmp_path, runner)
    result = engine.run(plan)
    stored = engine.get(plan.plan_hash)
    assert stored["outcome"] == Outcome.APPROVABLE.value
    assert stored["plan"] == plan.id
    assert stored["arguments_hash"] == plan.arguments_hash
    assert result.created > 0


def test_preflight_changes_nothing(tmp_path: Path) -> None:
    """Preflight is a review stage. It has no executor, and it accepts none."""
    runner = FakeReviewer()
    engine, plan = preflight(tmp_path, runner)
    engine.run(plan)
    assert not hasattr(engine, "exec")
    assert not hasattr(engine, "core")
    assert set(vars(engine)) == {"auto", "reviews", "store"}


def test_the_review_request_carries_the_plan_and_the_evidence(tmp_path: Path) -> None:
    runner = FakeReviewer()
    engine, plan = preflight(tmp_path, runner)
    request = engine.build_request(plan)
    assert "CHANGE PLAN" in request.context
    assert plan.objective in request.objective
    assert plan.id in request.subject_ref
    assert plan.evidence_refs[0] in request.evidence_refs


def test_a_risk_of_critical_is_carried_into_the_rendered_plan() -> None:
    plan = good_plan(risk=Risk.CRITICAL)
    assert "critical" in plan.render_for_reviewer()


# ------------------------------------------------------------------------------------- service wiring
def _config(tmp_path: Path, **auto: Any) -> Any:
    from opsbrain.config import Config

    return Config(repo=str(tmp_path), data_dir=str(tmp_path / "data"),
                  auto=AutoConfig(**{"enabled": True, **auto}))


def test_reviewing_a_plan_through_the_service_records_the_outcome(tmp_path: Path) -> None:
    from opsbrain.auto.service import AutoService

    runner = FakeReviewer()
    runner.default = response_document(Verdict.PASS)
    auto = AutoService(_config(tmp_path), reviewer=runner)
    answer = auto.review_plan(good_plan())
    assert answer["approvable"] is True
    assert answer["outcome"] == "approvable"
    assert auto.preflight_list()
    assert "preflight" in [entry.get("event") for entry in auto.audit.entries()]


def test_reviewing_a_plan_through_a_disabled_service_is_refused(tmp_path: Path) -> None:
    from opsbrain.auto.service import AutoService
    from opsbrain.util import OpsError

    auto = AutoService(_config(tmp_path, enabled=False), reviewer=FakeReviewer())
    with pytest.raises(OpsError, match="disabled"):
        auto.review_plan(good_plan())


def test_a_plan_survives_the_service_boundary(tmp_path: Path) -> None:
    from opsbrain.auto.service import AutoService

    auto = AutoService(_config(tmp_path), reviewer=FakeReviewer())
    assert auto.plan_summary(good_plan().to_dict())["plan"] == good_plan().id


def test_a_plan_whose_reasoning_was_rewritten_is_refused_even_when_the_hashes_look_consistent() -> None:
    plan = good_plan()
    document = plan.to_dict()
    document["diagnosis"] = "a justification invented after the approval was granted"
    assert document["id"] == plan.id, "the id is derived from arguments, and the commands did not change"
    with pytest.raises(PlanError, match="plan hash does not match"):
        ChangePlan.from_dict(document)
