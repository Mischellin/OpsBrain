"""#7 OPS-AUTO-04: the approval engine's truth table.

The engine is the only thing that may authorise a change, so the table below is the security boundary and
it is worth reading as one. Every row is a way the world can look "fine" - a green review, a fresh bundle,
a zero exit code - while the thing that matters is unknown, absent or contradicted.

Nothing here calls a model. That is asserted, not assumed: a decision that could be swayed by prose is
not a gate.
"""

from __future__ import annotations

from typing import Any

import pytest

from opsbrain.auto.config import AutoConfig
from opsbrain.auto.decision import ApprovalEngine, Decision, DecisionRecord, Inputs, Reason
from opsbrain.auto.evidence import Reason as EvidenceReason
from opsbrain.auto.preflight import Outcome
from opsbrain.auto.verify import CheckResult, CheckStatus, VerificationReport
from opsbrain.util import OpsError


def report(status: CheckStatus, *, reason: str = "") -> VerificationReport:
    return VerificationReport(change_id="chg-1", status=status, captured=1.0, evidence_refs=("ev-aaaaaaaabbbbbbbb",),
                             observation_s=60.0,
                             results=(CheckResult(check="systemd:unit-active", profile="systemd", target="web-1",
                                                  status=status, captured=1.0, detail="", reason=reason),))


def inputs(**overrides: Any) -> Inputs:
    base: dict[str, Any] = {
        "mode": "autonomous", "preflight_outcome": Outcome.APPROVABLE, "preflight_reason": "review_passed",
        "preflight_approvable": True, "evidence_reason": EvidenceReason.EVIDENCE_FRESH.value,
        "evidence_ids": ("ev-aaaaaaaabbbbbbbb",), "review_verdict": "PASS", "review_status": "OK",
        "policy_allows": True, "target_in_scope": True, "verification": report(CheckStatus.PASS),
        "policy_version": "v1",
    }
    return Inputs(**{**base, **overrides})


#: A well-formed token, because the engine refuses to act autonomously without one - and a test that
#: quietly omitted it would have been testing the wrong branch for the whole table.
TOKEN = "K7f2mQx9pR4tVw6nZs1b"


def engine(**config: Any) -> ApprovalEngine:
    return ApprovalEngine(AutoConfig(enabled=True, autonomy_token=TOKEN,
                                     decision={"mode": "autonomous", **config}))


def engine_manual(**config: Any) -> ApprovalEngine:
    return ApprovalEngine(AutoConfig(enabled=True, decision={"mode": "manual", **config}))


def decide(**overrides: Any) -> DecisionRecord:
    return engine().decide(inputs(**overrides), "pl-1", "ah-1")


# --------------------------------------------------------------------------- the positive path
def test_everything_in_order_approves_without_asking_anybody() -> None:
    record = decide()
    assert record.decision is Decision.APPROVE
    assert record.reason is Reason.POLICY_ALLOWS
    assert record.approvable is True
    assert record.policy_version == "v1"
    assert record.evidence_ids == ("ev-aaaaaaaabbbbbbbb",)


def test_a_human_approval_approves_even_in_manual_mode() -> None:
    record = decide(mode="manual", human_approved=True)
    assert record.decision is Decision.APPROVE
    assert record.reason is Reason.HUMAN_APPROVED


def test_a_human_approval_still_cannot_override_a_policy_denial() -> None:
    """`deny` is a deny. A human approving does not make it allowed."""
    assert decide(human_approved=True, policy_allows=False).decision is Decision.DENY


# ------------------------------------------------------------------------------------- the denials
def test_a_policy_denial_is_a_denial_in_every_mode() -> None:
    for mode in ("manual", "autonomous"):
        record = decide(mode=mode, policy_allows=False, human_approved=True)
        assert record.decision is Decision.DENY, mode
        assert record.reason is Reason.POLICY_FORBIDS, mode


def test_a_denying_review_is_a_denial() -> None:
    record = decide(review_verdict="DENY")
    assert record.decision is Decision.DENY
    assert record.reason is Reason.REVIEW_DENIED


def test_preflight_needing_changes_or_denying_is_a_denial() -> None:
    for outcome in (Outcome.NEEDS_CHANGES, Outcome.DENIED):
        assert decide(preflight_outcome=outcome).decision is Decision.DENY


def test_a_failed_verification_is_a_denial_not_a_pause() -> None:
    record = decide(verification=report(CheckStatus.FAIL, reason="unit is failed"))
    assert record.decision is Decision.DENY
    assert record.reason is Reason.VERIFICATION_FAILED


def test_destructive_work_stays_with_a_person() -> None:
    blocked = decide(destructive=True)
    assert blocked.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert blocked.reason is Reason.DESTRUCTIVE_REQUIRES_HUMAN
    # And even with autonomy on, the operator has to opt into destructive execution explicitly.
    strict = ApprovalEngine(AutoConfig(enabled=True, autonomy_token=TOKEN,
                                       decision={"mode": "autonomous", "allow_destructive": False}))
    assert strict.decide(inputs(destructive=True), "pl-1", "ah-1").decision is Decision.BLOCKED_AUTONOMOUSLY
    permissive = ApprovalEngine(AutoConfig(enabled=True, autonomy_token=TOKEN,
                                          decision={"mode": "autonomous", "allow_destructive": True}))
    assert permissive.decide(inputs(destructive=True), "pl-1", "ah-1").decision is Decision.APPROVE


# -------------------------------------------------------------------------------------- the blocks
def test_a_missing_review_blocks_and_never_assumes() -> None:
    record = decide(review_status="", review_verdict="")
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.REVIEW_MISSING


def test_missing_evidence_blocks() -> None:
    record = decide(evidence_reason="", evidence_ids=())
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.EVIDENCE_MISSING


@pytest.mark.parametrize("reason", [EvidenceReason.EVIDENCE_STALE.value, EvidenceReason.EVIDENCE_TAMPERED.value,
                                   EvidenceReason.EVIDENCE_FOREIGN_CHANGE.value,
                                   EvidenceReason.EVIDENCE_INCOMPLETE.value])
def test_unusable_evidence_blocks(reason: str) -> None:
    record = decide(evidence_reason=reason)
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.EVIDENCE_NOT_FRESH


def test_two_reviews_that_disagree_block_rather_than_pick_one() -> None:
    record = decide(review_verdict="PASS", secondary_review_status="OK", secondary_review_verdict="NEEDS_CHANGES")
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.VERDICT_DISAGREEMENT


def test_an_unknown_verification_is_not_a_good_one() -> None:
    record = decide(verification=report(CheckStatus.UNKNOWN, reason="no ActiveState"))
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.VERIFICATION_UNKNOWN


def test_checks_that_did_not_run_block() -> None:
    record = decide(verification=report(CheckStatus.NOT_RUN, reason="the unit start was not declared"))
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.VERIFICATION_NOT_RUN


def test_a_target_the_policy_does_not_cover_is_refused_not_assumed_allowed() -> None:
    record = decide(target_in_scope=False)
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.TARGET_NOT_IN_SCOPE


def test_emergency_stop_beats_everything() -> None:
    stopped = ApprovalEngine(AutoConfig(enabled=True, autonomy_token=TOKEN,
                                        decision={"mode": "autonomous", "emergency_stop": True}))
    record = stopped.decide(inputs(), "pl-1", "ah-1")
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.EMERGENCY_STOP


def test_revoked_autonomy_beats_everything() -> None:
    assert decide(autonomy_revoked=True).reason is Reason.AUTONOMY_REVOKED


def test_an_unknown_mode_is_refused_rather_than_guessed() -> None:
    for mode in ("yolo", "", "AUTO"):
        assert decide(mode=mode).reason is Reason.MODE_UNKNOWN


def test_manual_mode_does_not_decide_on_its_own() -> None:
    """`mode: manual` is not a weaker autonomous mode; it is the human's path."""
    record = engine_manual().decide(inputs(mode="manual"), "pl-1", "ah-1")
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.AUTONOMY_OFF


# ---------------------------------------------------------------------------------- retry vs block
@pytest.mark.parametrize("status", ["TIMEOUT", "RUNNER_ERROR", "QUOTA_EXHAUSTED", "BUDGET_EXCEEDED"])
def test_a_transient_runner_failure_is_a_retry(status: str) -> None:
    record = decide(review_status=status, review_verdict="")
    assert record.decision is Decision.RETRY
    assert record.reason is Reason.RETRYABLE_RUNNER_FAILURE
    assert record.next, "a retry must say what happens next"


def test_a_retry_stops_when_the_budget_runs_out() -> None:
    limited = ApprovalEngine(AutoConfig(enabled=True, autonomy_token=TOKEN,
                                        decision={"mode": "autonomous", "max_repair_cycles": 1}))
    record = limited.decide(inputs(review_status="TIMEOUT", review_verdict="", attempts=1), "pl-1", "ah-1")
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.RETRIES_EXHAUSTED
    assert record.attempts == 1


def test_evidence_the_reviewer_asked_for_is_a_retry_then_a_block() -> None:
    asking = decide(preflight_outcome=Outcome.NEEDS_EVIDENCE, preflight_reason="evidence_stale",
                    preflight_approvable=False)
    assert asking.decision is Decision.RETRY
    spent = decide(preflight_outcome=Outcome.NEEDS_EVIDENCE, preflight_reason="evidence_stale",
                   preflight_approvable=False, attempts=99)
    assert spent.decision is Decision.BLOCKED_AUTONOMOUSLY


def test_a_denied_review_is_never_retried() -> None:
    """Retrying a `deny` is how an autonomous loop becomes a loop."""
    assert decide(review_verdict="DENY", attempts=0).decision is Decision.DENY
    assert decide(review_verdict="DENY", attempts=99).decision is Decision.DENY


# -------------------------------------------------------------------------------- the record itself
def test_the_record_carries_reasons_versions_and_references() -> None:
    record = decide(evidence_ids=("ev-aaaaaaaabbbbbbbb", "ev-ccccccccdddddddd"), policy_version="v3")
    document = record.to_dict()
    assert document["reason"] == Reason.POLICY_ALLOWS.value
    assert document["policy_version"] == "v3"
    assert document["evidence_refs"] == ["ev-aaaaaaaabbbbbbbb", "ev-ccccccccdddddddd"]
    assert document["plan"] == "pl-1" and document["arguments_hash"] == "ah-1"
    assert document["verification"] == CheckStatus.PASS.value
    assert document["id"].startswith("dr-")


def test_an_approval_is_issued_only_for_an_approval(tmp_path: Any) -> None:
    from opsbrain.auto.approval import ApprovalBinding, ApprovalStore
    from opsbrain.util import OpsError

    store = ApprovalStore(tmp_path)
    issuing = ApprovalEngine(AutoConfig(enabled=True, autonomy_token=TOKEN), store)
    binding = ApprovalBinding(change_id="chg-1", subject="tofu.apply:proxmox", plan_hash="ph-1",
                              arguments_hash="ah-1", targets=("proxmox",), evidence_ids=("ev-aaaaaaaabbbbbbbb",),
                              policy_version="v1")
    # issued from an autonomous decision: a human-approved one in manual mode also qualifies
    assert issuing.issue("pl-1", "ah-1", binding, record=decide())
    blocked_dir = tmp_path / "blocked"
    blocked_dir.mkdir()
    blocked_engine = ApprovalEngine(AutoConfig(enabled=True, autonomy_token=TOKEN), ApprovalStore(blocked_dir))
    blocked = decide(verification=report(CheckStatus.FAIL))
    with pytest.raises(OpsError, match="refusing to issue"):
        blocked_engine.issue("pl-1", "ah-1", binding, record=blocked)
    assert not list(blocked_dir.glob("ap-*.json")), "a refused decision leaves nothing to spend"


def test_the_engine_has_no_way_to_be_persuaded() -> None:
    """The strongest property: the decision is a function of the inputs, and of nothing else.

    A model, a reviewer or a caller cannot hand the engine a `justification` and move the outcome, because
    there is no such parameter to hand.
    """
    import dataclasses

    fields = {field.name for field in dataclasses.fields(Inputs)}
    for absent in ("justification", "comment", "note", "message", "text", "explanation", "reason_text"):
        assert absent not in fields, f"Inputs accepts {absent!r}, which is a channel for prose"
    assert not hasattr(ApprovalEngine, "review"), "the engine must not run a review to decide"
    assert not hasattr(ApprovalEngine, "complete"), "the engine must not call a model to decide"


# ===================================================================== the gate: the executor may not skip the engine
def _autonomous_ops(ops: Any, tmp_path: Any, **decision: Any) -> tuple[Any, ApprovalEngine]:
    """An `OpsBrain` whose pipeline is on and autonomous, so the gate is actually installed."""
    from opsbrain.auto.approval import ApprovalStore
    from opsbrain.auto.decision import ApprovalEngine

    auto = type(ops.config.auto)(enabled=True, autonomy_token=TOKEN,
                                 decision={"mode": "autonomous", **decision})
    # `Config` is frozen too, so the pipeline is switched on by building a new one rather than by
    # assigning into it - which is also what an operator does when they edit the YAML.
    ops.config = ops.config.model_copy(update={"auto": auto})
    # One engine for both the gate and the issuing side: two ApprovalStores would each be looking at a
    # different directory, and the gate would refuse an approval it cannot see.
    engine = ApprovalEngine(auto, ApprovalStore(tmp_path / "approvals"))
    engine.install(ops.changes)
    return ops, engine


def test_a_hand_approval_does_not_open_the_autonomous_path(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The criterion this whole arrangement exists for: `opsbrain approve` must not bypass the engine.

    Without the gate, an operator approves by hand, the store says APPROVED, and the machinery built to
    decide is simply not consulted - the autonomous path is advisory while the human path is real.
    """
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1")
    ops.changes.approve(change.id, allow_dangerous=True)
    with pytest.raises(OpsError, match="no engine approval"):
        ops.changes.consume(change.id, "tofu.apply", "proxmox", needs_approval=True)


def test_an_engine_approval_opens_it(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from opsbrain.auto.approval import ApprovalBinding

    ops, engine = _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1")
    binding = ApprovalBinding(change_id=change.id, subject="tofu.apply:proxmox", plan_hash=change.hash,
                              arguments_hash="ah-1", targets=("proxmox",), evidence_ids=("ev-aaaaaaaabbbbbbbb",),
                              policy_version="v1")
    approval = engine.issue(change.id, change.hash, binding, record=decide())
    ops.changes.attach_approval(change.id, approval)
    assert ops.changes.consume(change.id, "tofu.apply", "proxmox", needs_approval=True).state == "applied"


def test_an_approval_issued_for_another_change_is_refused(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from opsbrain.auto.approval import ApprovalBinding

    ops, engine = _autonomous_ops(ops, tmp_path)
    mine = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1")
    theirs = ops.changes.create("tofu.apply", "prod", "y", "ph-2")
    binding = ApprovalBinding(change_id=theirs.id, subject="tofu.apply:prod", plan_hash=theirs.hash,
                              arguments_hash="ah-1", targets=("prod",), evidence_ids=("ev-aaaaaaaabbbbbbbb",),
                              policy_version="v1")
    ops.changes.attach_approval(mine.id, engine.issue(mine.id, mine.hash, binding, record=decide()))
    with pytest.raises(OpsError, match="was issued for"):
        ops.changes.consume(mine.id, "tofu.apply", "proxmox", needs_approval=True)


def test_a_stale_approval_no_longer_opens_the_gate(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The plan moved after the decision: the approval exists and the gate still refuses."""
    from opsbrain.auto.approval import ApprovalBinding

    ops, engine = _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1")
    binding = ApprovalBinding(change_id=change.id, subject="tofu.apply:proxmox", plan_hash="ph-original",
                              arguments_hash="ah-1", targets=("proxmox",), evidence_ids=("ev-aaaaaaaabbbbbbbb",),
                              policy_version="v1")
    ops.changes.attach_approval(change.id, engine.issue(change.id, change.hash, binding,
                                                                  record=decide()))
    ops.changes.update_hash(change.id, "ph-swapped")  # the plan was replaced after the decision
    with pytest.raises(OpsError, match="STALE"):
        ops.changes.consume(change.id, "tofu.apply", "proxmox", needs_approval=True)


def test_manual_mode_leaves_the_human_path_working(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The gate must not make the two-gate manual workflow impossible - that is the operator's escape hatch."""
    from opsbrain.auto.approval import ApprovalStore
    from opsbrain.auto.decision import ApprovalEngine

    ApprovalEngine(ops.config.auto, ApprovalStore(tmp_path / "approvals")).install(ops.changes)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1")
    ops.changes.approve(change.id, allow_dangerous=True)
    assert ops.changes.consume(change.id, "tofu.apply", "proxmox", needs_approval=True).state == "applied"
