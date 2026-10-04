"""#7 OPS-AUTO-04: the approval engine's truth table.

The engine is the only thing that may authorise a change, so the table below is the security boundary and
it is worth reading as one. Every row is a way the world can look "fine" - a green review, a fresh bundle,
a zero exit code - while the thing that matters is unknown, absent or contradicted.

Nothing here calls a model. That is asserted, not assumed: a decision that could be swayed by prose is
not a gate.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest

from opsbrain.auto.config import AutoConfig
from opsbrain.auto.decision import ApprovalEngine, Decision, DecisionRecord, Inputs, Reason
from opsbrain.auto.evidence import Reason as EvidenceReason
from opsbrain.auto.preflight import Outcome
from opsbrain.auto.verify import CheckResult, CheckStatus, VerificationReport
from opsbrain.util import OpsError


def report(status: CheckStatus, *, reason: str = "", change_id: str = "pl-1") -> VerificationReport:
    # `change_id` matches the plan the engine decides about: the engine now refuses a report that is
    # about some other change, so a mismatched fixture would be testing the wrong branch.
    return VerificationReport(change_id=change_id, status=status, captured=1.0, evidence_refs=("ev-aaaaaaaabbbbbbbb",),
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


def decide(change_id: str = "", **overrides: Any) -> DecisionRecord:
    """A decision over fully-populated inputs: a PASS nobody can resolve is not a PASS."""
    return engine().decide(inputs(**overrides), "pl-1", "ah-1", change_id=change_id,
                           review_ids=("rv-0000abcd",))


def decide_for(change: Any, by: ApprovalEngine | None = None, **overrides: Any) -> DecisionRecord:
    """A decision about one concrete change, carrying the same facts the binding will.

    `issue` now refuses a binding whose arguments, evidence or policy differ from the record's, so the
    decision and the approval have to be produced from the same change - which is the point.
    """
    from opsbrain.changes import digest

    arguments = digest({k: v for k, v in sorted(change.args.items())}) if change.args else ""
    # The report is about this change, or the engine correctly refuses a PASS from elsewhere.
    facts = {"verification": report(CheckStatus.PASS, change_id=change.id)}
    return (by or engine()).decide(inputs(**{**facts, **overrides}), change.id, arguments,
                                   change_id=change.id, review_ids=("rv-0000abcd",))


# --------------------------------------------------------------------------- the positive path
def test_everything_in_order_approves_without_asking_anybody() -> None:
    record = decide()
    assert record.decision is Decision.APPROVE
    assert record.reason is Reason.POLICY_ALLOWS
    assert record.approvable is True
    assert record.policy_version == "v1"
    assert record.evidence_ids == ("ev-aaaaaaaabbbbbbbb",)


def test_a_human_approval_approves_even_in_manual_mode() -> None:
    record = engine_manual().decide(inputs(mode="manual", human_approved=True), "pl-1", "ah-1",
                                    review_ids=("rv-0000abcd",))
    assert record.decision is Decision.APPROVE
    assert record.reason is Reason.HUMAN_APPROVED


def test_a_caller_cannot_choose_a_weaker_mode_than_the_operator_configured() -> None:
    """Claiming `manual` on an autonomous engine must not reach the human-approval branch.

    Otherwise the gate this module exists to keep shut is opened from the inside: submit `mode="manual"`
    with `human_approved=True`, take the manual branch, and the resulting engine approval satisfies the
    autonomous gate as if the engine had judged it.
    """
    record = decide(mode="manual", human_approved=True)
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.MODE_UNKNOWN
    assert "manual" in record.detail and "autonomous" in record.detail


def test_a_policy_denial_is_terminal_even_when_nobody_approved() -> None:
    """A forbidden change is `DENY` in every mode, not a block that reads like "ask a human"."""
    record = engine_manual().decide(inputs(mode="manual", human_approved=False, policy_allows=False),
                                    "pl-1", "ah-1", review_ids=("rv-0000abcd",))
    assert record.decision is Decision.DENY
    assert record.reason is Reason.POLICY_FORBIDS
    assert record.next == "no further action"


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
    blocked = strict.decide(inputs(destructive=True), "pl-1", "ah-1", review_ids=("rv-0000abcd",))
    assert blocked.decision is Decision.BLOCKED_AUTONOMOUSLY
    permissive = ApprovalEngine(AutoConfig(enabled=True, autonomy_token=TOKEN,
                                          decision={"mode": "autonomous", "allow_destructive": True}))
    allowed = permissive.decide(inputs(destructive=True), "pl-1", "ah-1", review_ids=("rv-0000abcd",))
    assert allowed.decision is Decision.APPROVE


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
    record = stopped.decide(inputs(), "pl-1", "ah-1", review_ids=("rv-0000abcd",))
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.EMERGENCY_STOP


def test_revoked_autonomy_beats_everything() -> None:
    assert decide(autonomy_revoked=True).reason is Reason.AUTONOMY_REVOKED


def test_an_unknown_mode_is_refused_rather_than_guessed() -> None:
    for mode in ("yolo", "", "AUTO"):
        assert decide(mode=mode).reason is Reason.MODE_UNKNOWN


def test_manual_mode_does_not_decide_on_its_own() -> None:
    """`mode: manual` is not a weaker autonomous mode; it is the human's path."""
    record = engine_manual().decide(inputs(mode="manual"), "pl-1", "ah-1", review_ids=("rv-0000abcd",))
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
    record = limited.decide(inputs(review_status="TIMEOUT", review_verdict="", attempts=1), "pl-1", "ah-1",
                            review_ids=("rv-0000abcd",))
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
    from opsbrain.auto.approval import ApprovalStore
    from opsbrain.changes import ChangeStore
    from opsbrain.util import OpsError

    store = ApprovalStore(tmp_path)
    changes = ChangeStore(tmp_path / "changes", 3600)
    issuing = ApprovalEngine(AutoConfig(enabled=True, autonomy_token=TOKEN), store)
    issuing.install(changes)
    change = changes.create("tofu.apply", "proxmox", "x", "ph-1")
    binding = bound_for(change)
    # issued from an autonomous decision: a human-approved one in manual mode also qualifies
    assert issuing.issue("pl-1", "ah-1", binding, record=decide_for(change))
    blocked_dir = tmp_path / "blocked"
    blocked_dir.mkdir()
    blocked_engine = ApprovalEngine(AutoConfig(enabled=True, autonomy_token=TOKEN), ApprovalStore(blocked_dir))
    blocked_engine.install(ChangeStore(tmp_path / "blocked-changes", 3600))
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
    from opsbrain.auto.approval import ApprovalStore  # noqa: F401  (used by the standalone tests)
    from opsbrain.auto.runners import FakeReviewer
    from opsbrain.auto.service import AutoService

    # runner `codex` with a stub reviewer injected: the default runner is named `fake`, and the stub guard
    # refuses to let a fake stand in for a paid reviewer. Naming it `codex` is what lets the pipeline be
    # exercised without spending a token.
    auto = type(ops.config.auto)(enabled=True, autonomy_token=TOKEN, review={"runner": "codex"},
                                 decision={"mode": "autonomous", **decision})
    # `Config` is frozen too, so the pipeline is switched on by building a new one rather than by
    # assigning into it - which is also what an operator does when they edit the YAML.
    ops.config = ops.config.model_copy(update={"auto": auto})
    # `Core` built the service and installed the gate from the *old* config, so both have to be rebuilt.
    # Leaving the old gate in place would have it answer from a config where the pipeline is switched
    # off, and the apply at the end of the end-to-end test would stop at the human prompt.
    ops.auto = AutoService(ops.config, reviewer=FakeReviewer())
    ops.auto.core = ops  # `Core` does this at construction; the rebuilt service needs it told
    # The service owns one engine and one approval store, and the gate is the same object that issues -
    # two engines over two directories would have the gate refuse an approval it cannot see.
    engine = ops.auto.engine()
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


def bound_for(change: Any, evidence_ids: Sequence[str] = ("ev-aaaaaaaabbbbbbbb",), **overrides: Any) -> Any:
    """A binding that actually matches the change it authorises.

    `arguments_hash` is derived exactly as the gate derives it. A hand-written constant only worked while
    the gate compared a partial dict and read absent fields as "unchanged" - which is what let a binding
    that named neither the arguments nor the evidence open the gate.
    """
    from opsbrain.auto.approval import ApprovalBinding
    from opsbrain.changes import digest

    fields: dict[str, Any] = {
        "change_id": change.id,
        "subject": f"{change.capability}:{change.target}",
        "plan_hash": change.hash,
        "arguments_hash": digest({k: v for k, v in sorted(change.args.items())}) if change.args else "",
        "targets": (change.target,),
        "evidence_ids": tuple(evidence_ids),
        "policy_version": "v1",
    }
    fields.update(overrides)
    return ApprovalBinding(**fields)


def test_an_engine_approval_opens_it(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    ops, engine = _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"})
    approval = engine.issue(change.id, change.hash, bound_for(change), record=decide_for(change))
    ops.changes.attach_approval(change.id, approval)
    assert ops.changes.consume(change.id, "tofu.apply", "proxmox", needs_approval=True).state == "applied"


def test_a_binding_that_names_neither_the_arguments_nor_the_evidence_is_refused(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Omitting a field is not the same as it being unchanged.

    The gate used to compare a dict the caller assembled field by field, and skip any it left out - so a
    binding that named only the plan and the subject passed a five-field check. Every field is now derived
    from the change, and issuance refuses a binding that disagrees with the record.
    """
    ops, engine = _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"})
    lazy = bound_for(change, arguments_hash="", evidence_ids=())
    with pytest.raises(OpsError, match="refusing to issue"):
        engine.issue(change.id, change.hash, lazy, record=decide_for(change))
    assert not change.engine_approval, "nothing was attached, so nothing can be executed under it"


def test_an_approval_stops_covering_a_change_whose_arguments_moved(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Correctly issued is not a permanent property: the change can still move under it."""
    ops, engine = _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"})
    ops.changes.attach_approval(change.id, engine.issue(change.id, change.hash, bound_for(change),
                                                        record=decide_for(change)))
    ops.changes.update_args(change.id, {"plan_file": ".opsbrain/j-deadbeef.tfplan"})
    with pytest.raises(OpsError, match="STALE"):
        ops.changes.consume(change.id, "tofu.apply", "proxmox", needs_approval=True)


def test_a_revoked_approval_does_not_open_the_gate(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """`get()` returns a revoked approval perfectly happily. The gate has to notice."""
    ops, engine = _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1")
    approval = engine.issue(change.id, change.hash, bound_for(change), record=decide_for(change))
    ops.changes.attach_approval(change.id, approval)
    assert engine.approvals is not None
    engine.approvals.revoke(approval)
    with pytest.raises(OpsError, match="revoked"):
        ops.changes.consume(change.id, "tofu.apply", "proxmox", needs_approval=True)


def test_a_spent_approval_does_not_open_a_second_run(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A lease is spent once. The gate must not treat a CONSUMED approval as authority again."""
    ops, engine = _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1")
    approval = engine.issue(change.id, change.hash, bound_for(change), record=decide_for(change))
    assert engine.approvals is not None
    from opsbrain.changes import digest

    binding_now = {"plan_hash": change.hash,
                   "arguments_hash": digest({k: v for k, v in sorted(change.args.items())})
                   if change.args else "",
                   "subject": f"{change.capability}:{change.target}", "targets": [change.target],
                   "evidence_ids": ["ev-aaaaaaaabbbbbbbb"], "policy_version": "v1"}
    engine.approvals.consume(approval, binding_now, owner="w", idempotency_key="k")
    ops.changes.attach_approval(change.id, approval)
    with pytest.raises(OpsError, match="consumed"):
        ops.changes.consume(change.id, "tofu.apply", "proxmox", needs_approval=True)


def test_an_approval_issued_for_another_change_is_refused(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    ops, engine = _autonomous_ops(ops, tmp_path)
    mine = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1")
    theirs = ops.changes.create("tofu.apply", "prod", "y", "ph-2")
    binding = bound_for(theirs)
    ops.changes.attach_approval(mine.id, engine.issue(mine.id, mine.hash, binding,
                                                      record=decide_for(theirs)))
    with pytest.raises(OpsError, match="was issued for"):
        ops.changes.consume(mine.id, "tofu.apply", "proxmox", needs_approval=True)


def test_a_stale_approval_no_longer_opens_the_gate(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The plan moved after the decision: the approval exists and the gate still refuses."""
    ops, engine = _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1")
    binding = bound_for(change, plan_hash="ph-original")
    ops.changes.attach_approval(change.id, engine.issue(change.id, change.hash, binding, record=decide_for(change)))
    ops.changes.update_hash(change.id, "ph-swapped")  # the plan was replaced after the decision
    with pytest.raises(OpsError, match="STALE"):
        ops.changes.consume(change.id, "tofu.apply", "proxmox", needs_approval=True)


def test_an_engine_that_was_never_installed_refuses_to_issue(tmp_path: Any) -> None:
    """An approval nothing will later check is not an approval.

    `issue` records what the decision rested on in the change store, and the gate compares against that
    record. An engine not installed in front of a store would issue an approval with no counterpart, so
    it says so instead of quietly producing one.
    """
    from opsbrain.auto.approval import ApprovalStore
    from opsbrain.changes import ChangeStore

    changes = ChangeStore(tmp_path / "changes", 3600)
    change = changes.create("tofu.apply", "proxmox", "x", "ph-1")
    engine = ApprovalEngine(AutoConfig(enabled=True, autonomy_token=TOKEN), ApprovalStore(tmp_path))
    with pytest.raises(OpsError, match="not installed"):
        engine.issue(change.id, change.hash, bound_for(change), record=decide_for(change))


def test_manual_mode_leaves_the_human_path_working(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The gate must not make the two-gate manual workflow impossible - that is the operator's escape hatch."""
    from opsbrain.auto.approval import ApprovalStore  # noqa: F401  (used by the standalone tests)

    ApprovalEngine(ops.config.auto, ApprovalStore(tmp_path / "approvals")).install(ops.changes)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1")
    ops.changes.approve(change.id, allow_dangerous=True)
    assert ops.changes.consume(change.id, "tofu.apply", "proxmox", needs_approval=True).state == "applied"


# ------------------------------------------------- fail-closed: a fact nobody established is not a fact
def test_policy_facts_are_not_affirmative_by_default() -> None:
    """A caller who never ran the policy lookup must not get an affirmative answer out of it.

    `policy_allows` and `target_in_scope` defaulted to `True`, so forgetting to map the policy result was
    indistinguishable from the policy having allowed the change.
    """
    blank = Inputs(mode="autonomous", preflight_outcome=Outcome.APPROVABLE, preflight_approvable=True,
                   evidence_ids=("ev-aaaaaaaabbbbbbbb",), review_verdict="PASS", review_status="OK",
                   policy_version="v1")
    record = engine().decide(blank, "pl-1", "ah-1", review_ids=("rv-0000abcd",))
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.POLICY_FORBIDS
    assert "unlooked-up policy" in record.detail


def test_a_target_nobody_classified_is_not_an_in_scope_target() -> None:
    blank = Inputs(mode="autonomous", preflight_outcome=Outcome.APPROVABLE, preflight_approvable=True,
                   evidence_ids=("ev-aaaaaaaabbbbbbbb",), review_verdict="PASS", review_status="OK",
                   policy_allows=True, policy_version="v1")
    record = engine().decide(blank, "pl-1", "ah-1", review_ids=("rv-0000abcd",))
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.TARGET_NOT_IN_SCOPE


def test_an_approval_with_no_evidence_reference_is_refused() -> None:
    """The default `evidence_fresh` reason with an empty list reached APPROVE with nothing to re-check."""
    record = decide(evidence_ids=())
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.EVIDENCE_MISSING
    assert "no evidence bundle" in record.detail


def test_a_pass_nobody_can_resolve_is_refused() -> None:
    record = engine().decide(inputs(), "pl-1", "ah-1", review_ids=())
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.REVIEW_MISSING
    assert "cannot be resolved" in record.detail


def test_approvable_means_the_field_said_yes_not_that_nobody_said() -> None:
    """An APPROVABLE outcome with an unestablished `approvable` is a plan nobody confirmed."""
    record = decide(preflight_approvable=None)
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.REVIEW_MISSING
    assert "approvability is None" in record.detail


def test_a_verification_report_from_another_change_is_not_proof_of_this_one() -> None:
    record = engine().decide(inputs(verification=report(CheckStatus.PASS, change_id="c-someoneelse")),
                             "pl-1", "ah-1", review_ids=("rv-0000abcd",))
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.VERIFICATION_UNKNOWN
    assert "c-someoneelse" in record.detail


def test_a_second_reviewer_that_failed_does_not_vanish() -> None:
    """A required extra review that timed out used to be ignored, and the primary review carried it."""
    record = decide(secondary_review_status="TIMEOUT")
    assert record.decision is Decision.RETRY
    assert record.reason is Reason.RETRYABLE_RUNNER_FAILURE
    assert "second reviewer" in record.detail


def test_a_second_reviewer_that_hard_failed_blocks() -> None:
    record = decide(secondary_review_status="UNAUTHORIZED")
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.REVIEW_FAILED


def test_two_reviews_that_agree_still_approve() -> None:
    """The secondary check is not a veto on everything - a passing pair must still get through."""
    record = decide(secondary_review_status="OK", secondary_review_verdict="PASS")
    assert record.decision is Decision.APPROVE


# ------------------------------------------------------------------ the paths that have to reach the gate
def test_a_policy_allow_mutation_still_works_with_the_gate_installed(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Nothing to approve when nothing is being asked for approval.

    `Core.gate` created the change and immediately consumed it with `needs_approval=False`. The engine gate
    was consulted anyway, demanded a decision record that could not exist yet, and every one-step
    policy-allow mutation raised instead of running.
    """
    from opsbrain.config import Access

    _autonomous_ops(ops, tmp_path)
    ops.require = lambda *_a, **_k: Access.ALLOW  # type: ignore[method-assign]
    change = ops.gate("tofu.unlock", "proxmox", None, summary="unlock", content_hash="h1")
    assert getattr(change, "state", None) == "applied"


def test_an_engine_approved_apply_does_not_stop_to_ask_a_human(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The end-to-end criterion: a decided change applies without a human in the loop.

    Issuance attaches an approval and leaves the change pending, which is the exact state the operator
    entry point used to treat as "a human must approve this" - so the autonomous path always ended in a
    prompt no matter what the engine had decided.
    """
    _ops, engine = _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    approval = engine.issue(change.id, change.hash, bound_for(change), record=decide_for(change, by=engine))
    ops.changes.attach_approval(change.id, approval)
    ops.exec.on(r"tofu apply", "@@OPSBRAIN-PLAN-MISMATCH " + "ab" * 32 + "@@\n", rc=78)
    out = ops.tofu_apply(change.id)
    assert out["plan_changed"] is True, "it got as far as the runner-side plan check"


def test_an_engine_approved_destructive_change_applies_without_a_human_flag(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """`auto.decision.allow_destructive` was decided on and then discarded at the point of use."""
    _ops, engine = _autonomous_ops(ops, tmp_path, allow_destructive=True)
    change = ops.changes.create("tofu.apply", "proxmox", "destroy", "ph-1", dangerous=True,
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    approval = engine.issue(change.id, change.hash, bound_for(change),
                            record=decide_for(change, by=engine, destructive=True))
    ops.changes.attach_approval(change.id, approval)
    ops.exec.on(r"tofu apply", "@@OPSBRAIN-PLAN-MISMATCH " + "ab" * 32 + "@@\n", rc=78)
    out = ops.tofu_apply(change.id)
    assert out["plan_changed"] is True, "the destructive check was satisfied by the engine's approval"


# ---------------------------------------------------------------------------- the end-to-end criterion
def _bundle(ops: Any, tmp_path: Any) -> str:
    """A real evidence bundle, collected through the service.

    The engine refuses a decision that cites no evidence, and preflight calls an `ev-` reference nobody can
    resolve a structural gap. Both are correct, so the end-to-end path has to carry actual observations
    rather than a plausible-looking id.
    """
    from opsbrain.auto.evidence import Observation, Provenance
    from opsbrain.util import now

    bundle = ops.auto.collect_evidence(
        "restart logrotate on web-1",
        [Observation(kind="log", target="web-1", capability="log.journal",
                     command_id="log.journal@web-1", collector="ssh:ops@10.0.0.42",
                     content="logrotate.timer: active (running)\n",
                     provenance=Provenance.OBSERVED, observed_at=now())],
        allowed=("log.journal",), targets=["web-1"], inventory_hash="inv-9f8e7d6c5b4a3928")
    return bundle["id"] if isinstance(bundle, dict) else bundle.id


def _plan_for_change(target: str = "proxmox", bundle_id: str = ""):
    """A complete, reviewable plan naming one target.

    `changes` cannot be empty - a plan with no changes is not a plan - so the shape here is the real one
    the pipeline sees, only with a single target so the refusal test can name a different one.
    """
    from opsbrain.auto.plan import ChangePlan, ProposedChange, Reversibility

    return ChangePlan.build(
        objective="restart logrotate on web-1",
        diagnosis="the timer is enabled but its drop-in directory is wrong, so the unit runs with the "
                  "distribution defaults and never rotates",
        changes=[ProposedChange(capability="ansible.apply", target=target,
                                how="install a logrotate drop-in", reversible=Reversibility.ROLLBACK,
                                undo="rm -f /etc/logrotate.d/web && systemctl daemon-reload")],
        evidence_refs=[bundle_id] if bundle_id else [], evidence_bundle=bundle_id, targets=[target],
        versions={"systemd": "252"},
        post_checks=["systemctl show logrotate.service -p FragmentPath,DropInPaths"],
        preconditions=["web-1 is reachable"], rollback="systemctl revert logrotate",
        created=1_700_000_000.0)


def test_a_decided_change_applies_without_any_human_step(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The whole point, end to end: plan → review → preflight → decision → approval → apply.

    Nothing here calls `opsbrain approve`. The engine decides, issues, and the executor's gate accepts the
    approval it issued - which is the only arrangement in which "autonomous" means anything.
    """
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path))
    reviewed = ops.auto.review_plan(plan)
    assert reviewed["outcome"] == "approvable", {"note": reviewed.get("note"),
                                                 "gaps": reviewed.get("structural_gaps")}
    decided = ops.auto.decide_change(change.id, plan.id)
    assert decided["decision"]["decision"] == "APPROVE", decided
    assert decided.get("approval", "").startswith("ap-")

    ops.exec.on(r"tofu apply", "Apply complete! Resources: 0 added, 1 changed, 0 destroyed.\n"
                                "@@OPSBRAIN-POSTPLAN 0@@\n")
    applied = ops.tofu_apply(change.id)
    assert applied["ok"] is True, applied


def test_a_change_against_a_target_the_plan_never_named_is_refused(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The review covers the targets the plan names, and nothing else."""
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "prod", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path))
    ops.auto.review_plan(plan)
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "BLOCKED_AUTONOMOUSLY"
    assert "prod" in out["decision"]["detail"]


def test_a_change_with_no_reviewed_plan_cannot_be_decided(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Deciding needs something to decide about. Silence is not consent."""
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1")
    with pytest.raises(OpsError, match="no preflight record"):
        ops.auto.decide_change(change.id, "pl-nonexistent")
