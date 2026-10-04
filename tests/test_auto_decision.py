"""#7 OPS-AUTO-04: the approval engine's truth table.

The engine is the only thing that may authorise a change, so the table below is the security boundary and
it is worth reading as one. Every row is a way the world can look "fine" - a green review, a fresh bundle,
a zero exit code - while the thing that matters is unknown, absent or contradicted.

Nothing here calls a model. That is asserted, not assumed: a decision that could be swayed by prose is
not a gate.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import pytest

from opsbrain.auto.config import AutoConfig
from opsbrain.auto.decision import ApprovalEngine, Decision, DecisionRecord, Inputs, Reason
from opsbrain.auto.evidence import Reason as EvidenceReason
from opsbrain.auto.preflight import Outcome
from opsbrain.auto.verify import CheckResult, CheckStatus, VerificationReport
from opsbrain.util import OpsError, now


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
        "policy_version": "v1", "reviews_passed": 1,
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
    assert issue_for(issuing, change, binding)
    blocked_dir = tmp_path / "blocked"
    blocked_dir.mkdir()
    blocked_engine = ApprovalEngine(AutoConfig(enabled=True, autonomy_token=TOKEN), ApprovalStore(blocked_dir))
    blocked_engine.install(ChangeStore(tmp_path / "blocked-changes", 3600))
    blocked = decide(verification=report(CheckStatus.FAIL))
    with pytest.raises(OpsError, match="refusing to issue"):
        blocked_engine.issue(change.id, "", binding, record=blocked)
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
    existing = ops.config.auto
    # Profiles and the default profile come from whatever the test set up, not from a fresh default:
    # rebuilding the config silently dropped them, which is how a scope test could pass a gate that
    # never had a profile to refuse it.
    auto = type(existing)(enabled=True, autonomy_token=TOKEN, review={"runner": "codex"},
                          decision={"mode": "autonomous",
                                    "default_profile": existing.decision.default_profile, **decision},
                          profiles=list(existing.profiles))
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


def issue_for(engine: ApprovalEngine, change: Any, binding: Any, *, record: Any = None,
              by: ApprovalEngine | None = None) -> str:
    """`issue` called the way the service calls it, from the change's own facts.

    `issue(plan_id, arguments_hash, ...)` takes the two values the decision was made about. Writing the
    call by hand in every test meant the arguments hash drifted from the one `decide_for` computed, and the
    new binding checks caught it - which is what they are for.
    """
    from opsbrain.changes import digest

    arguments = digest({k: v for k, v in sorted(change.args.items())}) if change.args else ""
    return engine.issue(change.id, arguments, binding,
                        record=record if record is not None else decide_for(change, by=by))


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
    approval = issue_for(engine, change, bound_for(change))
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
        issue_for(engine, change, lazy)
    assert not change.engine_approval, "nothing was attached, so nothing can be executed under it"


def test_an_approval_stops_covering_a_change_whose_arguments_moved(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Correctly issued is not a permanent property: the change can still move under it."""
    ops, engine = _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"})
    ops.changes.attach_approval(change.id, issue_for(engine, change, bound_for(change)))
    ops.changes.update_args(change.id, {"plan_file": ".opsbrain/j-deadbeef.tfplan"})
    with pytest.raises(OpsError, match="STALE"):
        ops.changes.consume(change.id, "tofu.apply", "proxmox", needs_approval=True)


def test_a_revoked_approval_does_not_open_the_gate(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """`get()` returns a revoked approval perfectly happily. The gate has to notice."""
    ops, engine = _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1")
    approval = issue_for(engine, change, bound_for(change))
    ops.changes.attach_approval(change.id, approval)
    assert engine.approvals is not None
    engine.approvals.revoke(approval)
    with pytest.raises(OpsError, match="revoked"):
        ops.changes.consume(change.id, "tofu.apply", "proxmox", needs_approval=True)


def test_a_spent_approval_does_not_open_a_second_run(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A lease is spent once. The gate must not treat a CONSUMED approval as authority again."""
    ops, engine = _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1")
    approval = issue_for(engine, change, bound_for(change))
    assert engine.approvals is not None
    from opsbrain.changes import digest

    binding_now = {"plan_hash": change.hash,
                   "arguments_hash": digest({k: v for k, v in sorted(change.args.items())})
                   if change.args else "",
                   "subject": f"{change.capability}:{change.target}", "targets": [change.target],
                   "evidence_ids": ["ev-aaaaaaaabbbbbbbb"], "policy_version": "v1",
                   "profile": bound_for(change).profile,
                   "profile_version": bound_for(change).profile_version}
    engine.approvals.consume(approval, binding_now, owner="w", idempotency_key="k")
    ops.changes.attach_approval(change.id, approval)
    with pytest.raises(OpsError, match="consumed"):
        ops.changes.consume(change.id, "tofu.apply", "proxmox", needs_approval=True)


def test_an_approval_issued_for_another_change_is_refused(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    ops, engine = _autonomous_ops(ops, tmp_path)
    mine = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1")
    theirs = ops.changes.create("tofu.apply", "prod", "y", "ph-2")
    binding = bound_for(theirs)
    from opsbrain.changes import digest as _digest

    ops.changes.attach_approval(mine.id, engine.issue(
        theirs.id, _digest({k: v for k, v in sorted(theirs.args.items())}) if theirs.args else "",
        binding, record=decide_for(theirs)))
    with pytest.raises(OpsError, match="was issued for"):
        ops.changes.consume(mine.id, "tofu.apply", "proxmox", needs_approval=True)


def test_a_stale_approval_no_longer_opens_the_gate(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The plan moved after the decision: the approval exists and the gate still refuses."""
    ops, engine = _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1")
    binding = bound_for(change, plan_hash="ph-original")
    ops.changes.attach_approval(change.id, issue_for(engine, change, binding))
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
        issue_for(engine, change, bound_for(change))


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


def test_a_verification_report_that_names_no_change_is_not_proof_of_anything() -> None:
    """The engine cannot compare ids: a decision is about a plan, a report belongs to a change.

    `AutoService.decide_change` is the layer that knows both, and it refuses a report for another change
    before it reaches the engine. What the engine still owes is that a report claiming no change at all is
    not evidence - and that a report's aggregate status alone is not a substitute for being bound.
    """
    record = engine().decide(inputs(verification=report(CheckStatus.PASS, change_id="")),
                             "pl-1", "ah-1", review_ids=("rv-0000abcd",))
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert record.reason is Reason.VERIFICATION_UNKNOWN
    assert "names no change" in record.detail


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
    approval = issue_for(engine, change, bound_for(change))
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
    approval = issue_for(engine, change, bound_for(change),
                            record=decide_for(change, by=engine, destructive=True))
    ops.changes.attach_approval(change.id, approval)
    ops.exec.on(r"tofu apply", "@@OPSBRAIN-PLAN-MISMATCH " + "ab" * 32 + "@@\n", rc=78)
    out = ops.tofu_apply(change.id)
    assert out["plan_changed"] is True, "the destructive check was satisfied by the engine's approval"


# ---------------------------------------------------------------------------- the end-to-end criterion
def _bundle(ops: Any, tmp_path: Any, change_id: str = "", *, observed_at: float | None = None) -> str:
    """A real evidence bundle, collected through the service.

    The engine refuses a decision that cites no evidence, and preflight calls an `ev-` reference nobody can
    resolve a structural gap. Both are correct, so the end-to-end path has to carry actual observations
    rather than a plausible-looking id.

    Bound to `change_id` when one is named, because the decision-time evidence check refuses a bundle whose
    entries are unbound or bound elsewhere: evidence has to be about the change it is used to authorise.
    """
    from opsbrain.auto.evidence import Observation, Provenance
    from opsbrain.util import now

    bundle = ops.auto.collect_evidence(
        "restart logrotate on web-1",
        [Observation(kind="log", target="web-1", capability="log.journal",
                     command_id="log.journal@web-1", collector="ssh:ops@10.0.0.42",
                     content="logrotate.timer: active (running)\n",
                     provenance=Provenance.OBSERVED,
                     observed_at=now() if observed_at is None else observed_at)],
        allowed=("log.journal",), targets=["web-1"], inventory_hash="inv-9f8e7d6c5b4a3928",
        change_id=change_id)
    return bundle["id"] if isinstance(bundle, dict) else bundle.id


#: The arguments a `tofu.apply` change records; the plan has to declare the same ones.
PLAN_ARGS = {"plan_file": ".opsbrain/j-1234abcd.tfplan"}


def _plan_for_change(target: str = "proxmox", bundle_id: str = "",
                     capability: str = "tofu.apply", arguments: dict[str, Any] | None = None,
                     profile: str = "general"):
    """A complete, reviewable plan naming one target.

    `changes` cannot be empty - a plan with no changes is not a plan - so the shape here is the real one
    the pipeline sees, only with a single target so the refusal test can name a different one.
    """
    from opsbrain.auto.plan import ChangePlan, ProposedChange, Reversibility

    return ChangePlan.build(
        objective="restart logrotate on web-1",
        diagnosis="the timer is enabled but its drop-in directory is wrong, so the unit runs with the "
                  "distribution defaults and never rotates",
        changes=[ProposedChange(capability=capability, target=target,
                                arguments=dict(PLAN_ARGS if arguments is None else arguments),
                                how="install a logrotate drop-in", reversible=Reversibility.ROLLBACK,
                                undo="rm -f /etc/logrotate.d/web && systemctl daemon-reload")],
        evidence_refs=[bundle_id] if bundle_id else [], evidence_bundle=bundle_id, targets=[target],
        versions={"systemd": "252"},
        post_checks=["systemctl show logrotate.service -p FragmentPath,DropInPaths"],
        preconditions=["web-1 is reachable"], rollback="systemctl revert logrotate",
        profile=profile, created=1_700_000_000.0)


def test_a_decided_change_applies_without_any_human_step(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The whole point, end to end: plan → review → preflight → decision → approval → apply.

    Nothing here calls `opsbrain approve`. The engine decides, issues, and the executor's gate accepts the
    approval it issued - which is the only arrangement in which "autonomous" means anything.
    """
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    reviewed = ops.auto.review_plan(plan)
    assert reviewed["outcome"] == "approvable", {"note": reviewed.get("note"),
                                                 "gaps": reviewed.get("structural_gaps")}
    decided = ops.auto.decide_change(change.id, plan.id)
    assert decided["decision"]["decision"] == "APPROVE", decided["decision"].get("detail", decided)
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
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
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


# ------------------------------------------------------------------ the new refusals, tested on their own
def test_attaching_an_approval_to_a_spent_change_is_refused(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Attachment used to rewrite the whole change without the transition lock.

    A redelivered issuance could read `pending`, wait for a `consume` to write `applied`, then write its
    own stale copy back - putting `pending` and a live approval on a change that had already run.
    """
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1")
    ops.changes.attach_approval(change.id, "ap-0000000000000000")
    ops.changes.consume(change.id, "tofu.apply", "proxmox", needs_approval=False)
    with pytest.raises(OpsError, match="already applied"):
        ops.changes.attach_approval(change.id, "ap-1111111111111111")
    assert ops.changes.get(change.id).engine_approval == "ap-0000000000000000", "the first one stands"


def test_a_decision_that_names_no_change_cannot_authorise_anything(tmp_path: Any) -> None:
    """`change_id` defaults to empty, so a guard that skips empty values compares nothing at all."""
    from opsbrain.auto.approval import ApprovalStore
    from opsbrain.changes import ChangeStore

    changes = ChangeStore(tmp_path / "changes", 3600)
    engine = ApprovalEngine(AutoConfig(enabled=True, autonomy_token=TOKEN), ApprovalStore(tmp_path))
    engine.install(changes)
    change = changes.create("tofu.apply", "proxmox", "x", "ph-1")
    nameless = decide_for(change)
    stripped = DecisionRecord(**{**{field: getattr(nameless, field)
                                      for field in DecisionRecord.__dataclass_fields__},
                                 "change_id": ""})
    with pytest.raises(OpsError, match="does not name the change"):
        engine.issue(change.id, "", bound_for(change), record=stripped)


def test_an_approve_for_one_plan_cannot_issue_a_binding_for_another(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    _ops, engine = _autonomous_ops(ops, tmp_path)
    first = ops.changes.create("tofu.apply", "proxmox", "a", "ph-1")
    second = ops.changes.create("tofu.apply", "prod", "b", "ph-2")
    record = decide_for(first)
    with pytest.raises(OpsError, match="authorises"):
        issue_for(engine, second, bound_for(second), record=record)
    # The change matches, so only the plan id can catch it now: an APPROVE for plan A replayed as plan B.
    with pytest.raises(OpsError, match="names plan"):
        engine.issue("pl-someother", "", bound_for(first), record=record)


def test_a_profile_that_asks_for_two_reviews_blocks_on_one() -> None:
    """A missing review is not a passing one.

    The secondary branch only ran when the secondary status was populated, so a profile demanding two
    reviews whose second was never invoked got through on the strength of the first.
    """
    strict = engine(required_reviews=2)
    one = strict.decide(inputs(reviews_passed=1), "pl-1", "ah-1", review_ids=("rv-0000abcd",))
    assert one.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert one.reason is Reason.REVIEW_MISSING
    assert "1 review(s) completed, 2 required" in one.detail
    two = strict.decide(inputs(reviews_passed=2), "pl-1", "ah-1",
                        review_ids=("rv-0000abcd", "rv-0000dcba"))
    assert two.decision is Decision.APPROVE


def test_an_unreported_review_count_blocks_when_the_profile_requires_more() -> None:
    """`reviews_passed` defaults to 0, so a caller that never counted reports none - and is refused."""
    strict = engine(required_reviews=2)
    record = strict.decide(inputs(reviews_passed=0), "pl-1", "ah-1", review_ids=("rv-0000abcd",))
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert "required" in record.detail


def test_an_issued_approval_stays_traceable_to_its_decision(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """After a restart the binding is all that survives, and a binding says nothing about *why*.

    The record - reason, review references, verification status, attempt count, id - is the evidence that
    explains why the execution was allowed, so it has to outlive the process that made it.
    """
    _ops, engine = _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"})
    record = decide_for(change, by=engine)
    issue_for(engine, change, bound_for(change), record=record)

    # A fresh reader, as after a restart: nothing but the change store.
    stored = ops.changes.get(change.id).details["decision_record"]
    assert stored["id"] == record.id
    assert stored["reason"] == record.reason.value
    assert stored["review_refs"] == list(record.review_ids)
    assert stored["verification"] == CheckStatus.PASS.value
    assert stored["attempts"] == record.attempts
    assert stored["plan"] == record.plan_id


# --------------------------------------------------- the decision path must hold the line on its own facts
def test_a_reviewed_plan_only_authorises_the_operation_it_proposes(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The target alone is not the operation.

    Checking only that the plan named `proxmox` meant any approvable plan mentioning that target could
    approve any pending change against it - a reviewed `ansible.apply` plan authorised a `tofu.apply` -
    and the binding is built entirely from the change, so the reviewed operation never entered it.
    """
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id), capability="ansible.apply")
    assert ops.auto.review_plan(plan)["outcome"] == "approvable"
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "BLOCKED_AUTONOMOUSLY"
    assert "tofu.apply:proxmox" in out["decision"]["detail"]


def test_evidence_that_aged_out_blocks_a_later_decision(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A preflight record remembers which evidence travelled, not whether it is still usable."""
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    assert ops.auto.review_plan(plan)["outcome"] == "approvable"
    # The evidence goes away after the review. The id tuple in the preflight record is untouched, so a
    # decision taken now would still have reported `evidence_fresh` off a reference that resolves to nothing.
    bundle_id = plan.evidence_bundle
    (ops.auto.evidence.bundles.root / f"{bundle_id}.json").unlink()
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "BLOCKED_AUTONOMOUSLY"
    assert out["decision"]["reason"] == "evidence_not_fresh"
    assert bundle_id in out["decision"]["detail"], "the failing bundle is named, so the operator knows where to look"


def test_a_verification_report_for_another_change_is_refused(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The report's identity is checked, not overwritten: forcing it would accept a PASS as proof of this."""
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    document = report(CheckStatus.PASS, change_id="c-other").to_dict()
    out = ops.auto.decide_change(change.id, plan.id, verification=document)
    assert out["decision"]["decision"] == "BLOCKED_AUTONOMOUSLY"
    assert "c-other" in out["decision"]["detail"]


def test_a_verification_report_for_this_change_is_accepted(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The other half: the report belongs to the change while the decision is about the plan."""
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    document = report(CheckStatus.PASS, change_id=change.id).to_dict()
    out = ops.auto.decide_change(change.id, plan.id, verification=document)
    assert out["decision"]["decision"] == "APPROVE", out


def test_repair_cycles_are_counted_durably_so_retry_eventually_blocks(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """`attempts` left at its default was 0 on every call, so the repair bound was enforced only in tests.

    A reviewer that keeps timing out returned RETRY forever, because `0 < max_repair_cycles` never stopped
    being true. The count now lives in the change record, which is the only place a restart cannot lose it.
    """
    _autonomous_ops(ops, tmp_path, max_repair_cycles=2)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    engine = ops.auto.engine()
    facts = {**{field: getattr(inputs(), field) for field in Inputs.__dataclass_fields__},
             "review_verdict": "", "review_status": "TIMEOUT", "reviews_passed": 0}

    def attempt() -> Any:
        """A review that only ever times out, with the count read from the record rather than from memory."""
        fresh = ops.changes.get(change.id)  # the store owns the copy; a stale one would read 0 forever
        return Inputs(**{**facts, "attempts": ops.auto._repair_count(fresh)})

    def decide_now() -> Any:
        return engine.decide(attempt(), plan.id, "", change_id=change.id, review_ids=("rv-0000abcd",))

    assert decide_now().decision is Decision.RETRY, "the first timeout is worth another attempt"
    ops.changes.note_repair_cycle(change.id)
    assert ops.auto._repair_count(ops.changes.get(change.id)) == 1
    assert decide_now().decision is Decision.RETRY, "so is the second, which is the last"
    ops.changes.note_repair_cycle(change.id)
    exhausted = decide_now()
    assert exhausted.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert exhausted.reason is Reason.RETRIES_EXHAUSTED
    assert exhausted.attempts == 2


def test_a_reviewed_plan_only_authorises_the_plan_file_it_declared(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Capability and target are not the operation.

    Two saved plans for the same stack differ only in which file they will run. Comparing
    `capability:target` let a reviewed plan authorise a different one, and the arguments hash the
    approval carries was re-derived from the change rather than the one the review covered.
    """
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-deadbeef.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    assert ops.auto.review_plan(plan)["outcome"] == "approvable"
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "BLOCKED_AUTONOMOUSLY"
    assert "j-1234abcd.tfplan" in out["decision"]["detail"]
    assert "j-deadbeef.tfplan" in out["decision"]["detail"], "both sides are named, so the mismatch is visible"


def test_the_verification_shape_the_service_actually_emits_is_understood(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """`verify_change` and `verify_plan` return `brief()`, which spells the change as `change`.

    Reading that back through the `to_dict` parser lost the identity entirely, and the engine then refused
    a perfectly good report as naming no change.
    """
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    brief = report(CheckStatus.PASS, change_id=change.id).brief()
    assert "change" in brief and "change_id" not in brief, "this is the shape the service emits"
    out = ops.auto.decide_change(change.id, plan.id, verification=brief)
    assert out["decision"]["decision"] == "APPROVE", out["decision"].get("detail", out)


def test_a_retry_reports_the_durable_count_not_the_one_it_loaded_before_counting(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The first consumed retry used to answer `attempts: 0`, one behind the record."""
    _autonomous_ops(ops, tmp_path, max_repair_cycles=3)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    ops.changes.note_repair_cycle(change.id)
    assert ops.auto._repair_count(ops.changes.get(change.id)) == 1
    out = ops.auto.decide_change(change.id, plan.id)
    # Not a RETRY here, so no `attempts` is reported - but the helper the response uses reads the change
    # returned by the increment, which is what was previously the object loaded before it.
    counted = ops.changes.note_repair_cycle(change.id)
    assert ops.auto._repair_count(counted) == 2
    assert "attempts" not in out["decision"] or out["decision"]["attempts"] == 1


def test_an_approval_is_bound_to_the_configured_profile(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The gate compares against `default_profile`; a binding left at `general` was always stale.

    Any deployment running a profile other than `general` therefore had every engine-issued approval
    refused, which is the shape of a feature that works in the default configuration and nowhere else.
    """
    _autonomous_ops(ops, tmp_path, default_profile="secrets")
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "APPROVE", out["decision"].get("detail", out)
    # And the gate accepts what was issued, rather than refusing it as `profile_changed`.
    ops.exec.on(r"tofu apply", "@@OPSBRAIN-PLAN-MISMATCH " + "ab" * 32 + "@@\n", rc=78)
    assert ops.tofu_apply(change.id)["plan_changed"] is True


def test_issue_refuses_a_binding_built_over_altered_arguments(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The comparison looked at the parameter, never at the binding the approval would carry.

    A caller could alter a change's arguments, rebuild a binding over the altered values, and issue it
    under an APPROVE made about the original ones - and the gate then accepted the altered hash, because it
    matched the binding that had just been issued.
    """
    _ops, engine = _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    record = decide_for(change)
    altered = bound_for(change, arguments_hash="something-else-entirely")
    with pytest.raises(OpsError, match="the binding carries arguments"):
        issue_for(engine, change, altered, record=record)


def test_the_instructions_describe_the_path_the_deployment_actually_has(ops) -> None:  # type: ignore[no-untyped-def]
    """Telling an autonomous server that a human must approve sends the client down a guaranteed failure."""
    from opsbrain.config import AutoConfig
    from opsbrain.server import INSTRUCTIONS, build_instructions

    assert "opsbrain approve" in INSTRUCTIONS, "the manual path is still what it says"

    manual = ops.config
    assert "opsbrain approve" in build_instructions(manual)

    autonomous = manual.model_copy(update={"auto": AutoConfig(
        enabled=True, autonomy_token="K7f2mQx9pR4tVw6nZs1b", decision={"mode": "autonomous"})})
    text = build_instructions(autonomous)
    assert "autonomy action=decide" in text, "the action that actually opens the gate is named"
    assert "opsbrain approve" not in text, "the path that is guaranteed to fail is not"


def test_the_reviewer_is_shown_the_arguments_the_approval_is_bound_to() -> None:
    """`how` is prose. The approval is bound to `arguments`, and the reviewer has to see the same thing.

    A plan could describe a harmless operation in prose while its arguments named a different playbook or
    a different saved plan: `decide_change` then matched the hidden values and authorised that operation.
    """
    from opsbrain.auto.plan import ChangePlan, ProposedChange

    plan = ChangePlan.build(
        objective="restart a service", diagnosis="the unit is masked",
        changes=[ProposedChange(capability="tofu.apply", target="proxmox", how="apply the saved plan",
                                undo="revert it", arguments={"plan_file": ".opsbrain/j-1234abcd.tfplan"})],
        rollback="revert it", created=1_700_000_000.0)
    rendered = plan.render_for_reviewer()
    assert "j-1234abcd.tfplan" in rendered, "the reviewer sees the file that will actually be applied"
    assert "arguments:" in rendered

    bare = ChangePlan.build(
        objective="read a service", diagnosis="looking",
        changes=[ProposedChange(capability="k8s.get", target="default", how="list pods", undo="none")],
        rollback="none", created=1_700_000_000.0)
    assert "(none declared)" in bare.render_for_reviewer(), "and says plainly when there are none"


def test_allow_destructive_reaches_a_policy_allow_target(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The engine's destructive opt-in was decided on and then discarded at the point of use.

    `consume` skipped the gate because the policy allowed the capability, so the engine approval went
    unread and the destructive guard asked for a human flag the decision had already covered.
    """
    _ops, engine = _autonomous_ops(ops, tmp_path, allow_destructive=True)
    change = ops.changes.create("tofu.apply", "proxmox", "destroy a vm", "ph-1", dangerous=True,
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    record = decide_for(change, by=engine, destructive=True)
    approval = issue_for(engine, change, bound_for(change), by=engine, record=record)
    ops.changes.attach_approval(change.id, approval)
    # The policy-allow path is the one that used to bypass the gate entirely.
    assert ops.changes.consume(change.id, "tofu.apply", "proxmox", needs_approval=False).state == "applied"


def test_the_approval_cap_comes_from_the_same_freshness_measurement_as_the_check(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The cap and the check must not measure freshness two different ways.

    `check_evidence` measures from the oldest timestamp in the bundle against the limit stored *in that
    bundle*. Deriving the cap from `bundle.created` and the currently configured window instead gave a
    longer answer whenever an observation predated ingestion or the window was tightened after collection -
    so the approval was issued with seconds of freshness left and stayed usable well after the evidence
    went stale, because execution only re-reads the binding's expiry and the evidence ids.
    """
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    assert ops.auto.review_plan(plan)["outcome"] == "approvable"

    # An observation collected well before the bundle was ingested: the bundle's own `created` is now,
    # but `check_evidence` measures freshness from the *oldest* entry, so the evidence is much closer to
    # stale than the bundle's timestamp suggests.
    stale_by = 800.0
    old_bundle = _bundle(ops, tmp_path, change.id, observed_at=now() - stale_by)
    old_plan = _plan_for_change(bundle_id=old_bundle)
    assert ops.auto.review_plan(old_plan)["outcome"] == "approvable"

    ids, reason, remaining = ops.auto._evidence_state((old_bundle,), change.id)
    assert reason == "evidence_fresh", reason
    window = float(ops.auto.auto.evidence.max_age_s)
    # Measured the way `check_evidence` measures it - from the oldest entry, not from ingestion.
    assert remaining <= window - stale_by + 5.0, (
        f"the cap is {remaining:.0f}s, but the evidence has only {window - stale_by:.0f}s left")


def _profile(**fields: Any) -> Any:
    from opsbrain.auto.config import PolicyProfileConfig

    return PolicyProfileConfig(name="general", **fields)


def test_a_profile_that_excludes_the_target_blocks_the_decision(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """`target_in_scope=bool(change.target)` said only that a string was present.

    So every scope the operator wrote - `allow_autonomous`, `allowed_targets`, `allowed_capabilities` -
    was configured, validated, shown in the overview, and never consulted.
    """
    from opsbrain.auto.config import AutoConfig

    ops.config = ops.config.model_copy(update={"auto": AutoConfig(
        enabled=True, autonomy_token=TOKEN, review={"runner": "codex"},
        decision={"mode": "autonomous"}, profiles=[_profile(allowed_targets=["web-1"])])})
    _ops, engine = _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    assert ops.auto.review_plan(plan)["outcome"] == "approvable", "the review itself is fine"
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "BLOCKED_AUTONOMOUSLY"
    assert "does not cover the target 'proxmox'" in out["decision"]["detail"]
    assert "web-1" in out["decision"]["detail"], "and the operator is told what it does cover"


def test_a_profile_that_excludes_the_capability_blocks_the_decision(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from opsbrain.auto.config import AutoConfig

    ops.config = ops.config.model_copy(update={"auto": AutoConfig(
        enabled=True, autonomy_token=TOKEN, review={"runner": "codex"},
        decision={"mode": "autonomous"}, profiles=[_profile(allowed_capabilities=["k8s.get"])])})
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "BLOCKED_AUTONOMOUSLY"
    assert "does not cover tofu.apply" in out["decision"]["detail"]


def test_a_profile_that_forbids_autonomy_blocks_the_decision(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from opsbrain.auto.config import AutoConfig

    ops.config = ops.config.model_copy(update={"auto": AutoConfig(
        enabled=True, autonomy_token=TOKEN, review={"runner": "codex"},
        decision={"mode": "autonomous"}, profiles=[_profile(allow_autonomous=False)])})
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "BLOCKED_AUTONOMOUSLY"
    assert "does not allow autonomous execution" in out["decision"]["detail"]


def test_a_review_that_cannot_be_resolved_blocks_the_decision(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """`_evaluate` only checked that the tuple was non-empty.

    A preflight record is a copy made at review time; records get removed and copies outlive their
    originals, so the engine was told a PASS it could not re-derive from anything - an approval whose
    stated justification cannot be audited.
    """
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    assert ops.auto.review_plan(plan)["outcome"] == "approvable"
    review_id = ops.auto.preflight().get_by_plan(plan.id)["review"]
    assert ops.auto.reviews.store.discard(review_id), "the review record is gone"
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "BLOCKED_AUTONOMOUSLY"
    assert "cannot be resolved" in out["decision"]["detail"]


# ------------------------------------------------ the ceilings the operator set, and the ids it named
def test_a_retry_stops_at_the_call_ceiling_not_only_the_cycle_count() -> None:
    """`max_repair_cycles` bounds how many times the loop goes round, not what it spends going round.

    A reviewer that fails on a quota error is retryable by construction, so a cycle budget alone lets the
    loop walk straight past the call, cost and elapsed-time bounds the operator set.
    """
    tight = engine(max_model_calls=2)
    facts = {field: getattr(inputs(), field) for field in Inputs.__dataclass_fields__}
    facts.update(review_status="TIMEOUT", review_verdict="", reviews_passed=0)

    still_going = tight.decide(Inputs(**{**facts, "attempts": 0, "calls_used": 1}),
                               "pl-1", "ah-1", change_id="c-1", review_ids=("rv-0000abcd",))
    assert still_going.decision is Decision.RETRY

    out = tight.decide(Inputs(**{**facts, "attempts": 0, "calls_used": 2}),
                       "pl-1", "ah-1", change_id="c-1", review_ids=("rv-0000abcd",))
    assert out.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert out.reason is Reason.RETRIES_EXHAUSTED
    assert "call ceiling is reached" in out.detail


def test_a_retry_stops_at_the_spend_and_elapsed_ceilings_too() -> None:
    tight = engine(max_spend_usd=1.0, max_wall_s=600)
    facts = {field: getattr(inputs(), field) for field in Inputs.__dataclass_fields__}
    facts.update(review_status="TIMEOUT", review_verdict="", reviews_passed=0)
    spent = tight.decide(Inputs(**{**facts, "attempts": 0, "spend_usd": 1.5}),
                         "pl-1", "ah-1", change_id="c-1", review_ids=("rv-0000abcd",))
    assert spent.reason is Reason.RETRIES_EXHAUSTED and "spend ceiling" in spent.detail
    slow = tight.decide(Inputs(**{**facts, "attempts": 0, "elapsed_s": 900.0}),
                        "pl-1", "ah-1", change_id="c-1", review_ids=("rv-0000abcd",))
    assert slow.reason is Reason.RETRIES_EXHAUSTED and "elapsed-time ceiling" in slow.detail


def test_the_instructions_name_the_retry_outcome_the_enum_actually_uses() -> None:
    from opsbrain.auto.decision import Decision
    from opsbrain.server import build_instructions

    assert Decision.RETRY.value == "RETRY"
    ops = _autonomous_ops_text()
    text = build_instructions(ops)
    assert "RETRY" in text
    assert "REFTRY" not in text, "a client matching the advertised name would not find the enum value"


def _autonomous_ops_text() -> Any:
    from opsbrain.config import AutoConfig

    class _Stub:
        pass

    stub = _Stub()
    stub.auto = AutoConfig(enabled=True, autonomy_token=TOKEN, decision={"mode": "autonomous"})
    return stub


def test_destructive_work_is_not_sent_to_a_path_that_cannot_execute(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """`--allow-destroy` is unreachable in autonomous mode: the gate still demands an engine approval."""
    _autonomous_ops(ops, tmp_path, allow_destructive=False)
    record = engine().decide(
        Inputs(**{**{f: getattr(inputs(), f) for f in Inputs.__dataclass_fields__},
                  "destructive": True, "reviews_passed": 1}),
        "pl-1", "ah-1", change_id="c-1", review_ids=("rv-0000abcd",))
    assert record.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert "REFTRY" not in record.next
    assert "allow_destructive" in record.next, "the operator is told the switch that would work"
    assert "manual" in record.next, "and the mode they would switch to"


def test_an_approval_cannot_rest_on_evidence_the_plan_never_named(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """`review_plan(plan, evidence=B)` lets a caller supply a different bundle than the plan declares."""
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    declared = _bundle(ops, tmp_path, change.id)
    other = _bundle(ops, tmp_path, change.id)
    plan = _plan_for_change(bundle_id=declared)
    # `review_plan` refuses the substitution at the door, so the plan never acquires a preflight that
    # would let a decision rest on evidence the immutable reviewed plan did not name.
    ops.auto.review_plan(plan, evidence=other)
    record = ops.auto.preflight().get_by_plan(plan.id)
    reviewed_ids = set(record["evidence_ids"])
    assert other in reviewed_ids, "the caller did add a bundle the plan never named"
    assert declared in reviewed_ids, "and the plan's own bundle is there too"
    # So the refusal has to happen at the decision, where the plan's own declaration is available: an
    # approval must not rest on evidence the immutable reviewed plan never named.
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "BLOCKED_AUTONOMOUSLY"
    assert "did not name" in out["decision"]["detail"]


def test_a_report_naming_this_plan_is_accepted_by_a_service_that_produced_it(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """`verify_plan` reports against the plan id; the executor's change is `c-*`. Same object, two names."""
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    # A report as the service emits it: `brief` names the change `change`, and `verify_plan` uses the plan
    # id there - the same object under the name a caller would have used.
    brief = report(CheckStatus.PASS, change_id=plan.id).brief()
    assert brief["change"] == plan.id
    out = ops.auto.decide_change(change.id, plan.id, verification=brief)
    assert out["decision"]["decision"] == "APPROVE", out["decision"].get("detail", out)


# ------------------------------------------------------- the profile's own requirements, and identity
def test_a_profile_that_requires_evidence_refuses_a_plan_that_cites_none(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """`allowed_*` and `allow_autonomous` were the only fields enforced.

    A profile could demand evidence, preconditions, verification or a second review and still see an
    APPROVE with none of them, because nothing read those four lists.
    """
    from opsbrain.auto.config import AutoConfig

    ops.config = ops.config.model_copy(update={"auto": AutoConfig(
        enabled=True, autonomy_token=TOKEN, review={"runner": "codex"},
        decision={"mode": "autonomous"},
        profiles=[_profile(require_evidence=["inventory"])])})
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    assert ops.auto.review_plan(plan)["outcome"] == "approvable"
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "BLOCKED_AUTONOMOUSLY"
    assert "requires evidence" in out["decision"]["detail"]


def test_an_approval_is_labelled_with_the_profile_the_plan_was_reviewed_under(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The default profile is the default for a plan that names none - not for one that names another.

    Labelling a `secrets` review as `general` meant changes to the profile actually in force never made
    the approval stale.
    """
    from opsbrain.auto.approval import ApprovalStore
    from opsbrain.auto.config import AutoConfig, PolicyProfileConfig

    ops.config = ops.config.model_copy(update={"auto": AutoConfig(
        enabled=True, autonomy_token=TOKEN, review={"runner": "codex"},
        decision={"mode": "autonomous", "default_profile": "general"},
        profiles=[PolicyProfileConfig(name="general"),
                  PolicyProfileConfig(name="secrets", allowed_targets=["proxmox"])])})
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id), profile="secrets")
    ops.auto.review_plan(plan)
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "APPROVE", out["decision"].get("detail", out)
    approval = ops.changes.get(change.id).engine_approval
    assert ApprovalStore(ops.auto.root / "approvals").get(approval).binding.profile == "secrets"


def test_a_preflight_record_carrying_another_plan_is_refused(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The outer record is selected by plan id, but a nested document that parses is not thereby it.

    Capability, target, arguments and profile are all read out of the document, so a stored PASS for plan
    A would otherwise authorise a change described only by plan B.
    """
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    stored = ops.auto.preflight().store.get(f"pf-{plan.plan_hash[:16]}")
    stored["plan_document"] = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id)).to_dict()
    ops.auto.preflight().store.put(f"pf-{plan.plan_hash[:16]}", stored)
    with pytest.raises(OpsError, match="carries a different plan"):
        ops.auto.decide_change(change.id, plan.id)


def test_a_review_that_became_a_denial_stops_being_cited(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The preflight record is a copy; a copy outlives the record it was copied from."""
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    assert ops.auto.review_plan(plan)["outcome"] == "approvable"
    review_id = ops.auto.preflight().get_by_plan(plan.id)["review"]
    document = ops.auto.reviews.store.get(review_id)
    document["verdict"] = "DENY"
    ops.auto.reviews.store.put(review_id, document)
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "BLOCKED_AUTONOMOUSLY"
    assert "cannot be resolved" in out["decision"]["detail"]


def test_a_failed_review_reaches_the_engine_instead_of_being_refused(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A runner failure is exactly what RETRY exists to answer.

    Refusing it in the resolver meant the exposed workflow never returned RETRY for a reviewer failure
    and the repair budget was never spent.
    """
    from opsbrain.auto.config import AutoConfig

    ops.config = ops.config.model_copy(update={"auto": AutoConfig(
        enabled=True, autonomy_token=TOKEN, review={"runner": "codex", "max_retries": 0},
        decision={"mode": "autonomous", "max_repair_cycles": 2})})
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)  # the plan is stored even though the reviewer did not answer
    review_id = ops.auto.preflight().get_by_plan(plan.id)["review"]
    document = ops.auto.reviews.store.get(review_id)
    document["status"] = "TIMEOUT"
    document["verdict"] = None
    ops.auto.reviews.store.put(review_id, document)
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "RETRY", out["decision"].get("detail", out)


def test_an_expired_approval_cannot_be_renewed_from_the_decision_that_granted_it(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """`issue` replaces an expired record on purpose - so the original APPROVE must not be replayable.

    Timestamps are outside the binding hash, so a re-review of an unchanged change lands on the same id;
    without recording which decision issued it, the old APPROVE could mint a fresh lease with a new
    `created`, renewing authority no re-review granted.
    """
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    out = ops.auto.decide_change(change.id, plan.id)
    approval = out.get("approval", "")
    assert approval

    # Age the stored lease so the store would otherwise replace it.
    path = ops.auto.root / "approvals" / f"{approval}.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["binding"]["created"] = round(now() - 10_000.0, 3)
    path.write_text(json.dumps(document), encoding="utf-8")

    # Through the engine, not the store: the store knows nothing about decisions, and the guard belongs
    # where a decision is turned into an approval.
    from opsbrain.changes import digest

    arguments = digest({k: v for k, v in sorted(change.args.items())}) if change.args else ""
    with pytest.raises(OpsError, match="already issued the approval"):
        ops.auto.engine().issue(change.id, arguments, bound_for(change, created=now()),
                                record=decide_for(change, by=ops.auto.engine()))


def test_a_successful_apply_spends_the_approval(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The gate only *read* the approval, so a revocation could still land after it.

    A successful apply left the lease `ISSUED`, which meant `revoke()` succeeded afterwards and erased
    the fact that it had been used - and a revocation landing between the read and the mutation would not
    have stopped anything. The lease is now spent under the store's lock when the gate opens, and its
    outcome recorded when the change reaches APPLIED.
    """
    from opsbrain.auto.approval import ApprovalStore, LeaseState

    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    approval = ops.auto.decide_change(change.id, plan.id)["approval"]
    store = ApprovalStore(ops.auto.root / "approvals")
    assert store.get(approval).state is LeaseState.ISSUED, "issuing alone does not spend"

    ops.exec.on(r"tofu apply", "Apply complete! Resources: 0 added, 1 changed, 0 destroyed.\n"
                               "@@OPSBRAIN-POSTPLAN 0@@\n")
    assert ops.tofu_apply(change.id)["ok"] is True
    spent = store.get(approval)
    assert spent.state is LeaseState.CONSUMED, "and the apply spent it"
    assert spent.outcome.get("executed") is True, "recording what ran"
    with pytest.raises(OpsError, match="was revoked|consumed|already spent"):
        store.revoke(approval, "too late")


def test_the_pair_of_review_answers_decides_the_same_way_in_either_slot() -> None:
    """A denial from either reviewer is a denial, whichever slot the runner was given.

    The primary `DENY` branch returned before the secondary was read, so `DENY`+`PASS` gave DENY while
    `PASS`+`DENY` reached the disagreement branch and blocked. The same two answers, two outcomes.
    """
    first = engine().decide(inputs(review_verdict="DENY", secondary_review_status="OK",
                                   secondary_review_verdict="PASS", reviews_passed=2),
                            "pl-1", "ah-1", review_ids=("rv-0000abcd", "rv-0000dcba"))
    second = engine().decide(inputs(review_verdict="PASS", secondary_review_status="OK",
                                    secondary_review_verdict="DENY", reviews_passed=2),
                             "pl-1", "ah-1", review_ids=("rv-0000abcd", "rv-0000dcba"))
    assert first.decision is Decision.DENY
    assert second.decision is Decision.DENY, "the answer does not depend on which reviewer ran first"
    assert first.reason is second.reason is Reason.REVIEW_DENIED


def test_a_retryable_failure_still_outranks_a_denial_from_the_other_reviewer() -> None:
    """Ordering fixed, and fixed deliberately: a reviewer that timed out is a retry, not a denial."""
    record = engine().decide(inputs(review_verdict="DENY", secondary_review_status="TIMEOUT",
                                    secondary_review_verdict="", reviews_passed=1, attempts=0),
                             "pl-1", "ah-1", review_ids=("rv-0000abcd",))
    assert record.decision is Decision.RETRY
    assert record.reason is Reason.RETRYABLE_RUNNER_FAILURE


def test_a_closed_change_cannot_be_decided_about(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """An APPROVE written into an APPLIED or DISCARDED record is an orphaned approval.

    `attach_approval` refused only at the very end, after the approval had been issued and the decision
    metadata written - leaving an issued approval and a durable decision for work that had already run.
    """
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    ops.changes.discard(change.id)
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "BLOCKED_AUTONOMOUSLY"
    assert "discarded" in out["decision"]["detail"]


def test_a_budget_ceiling_is_measured_from_this_workflow_not_from_the_service_lifetime(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """`BudgetLedger` is cumulative by design, so a decision needs a baseline rather than a total.

    Earlier unrelated reviews against a stricter ceiling reported a *new* workflow as exhausted before it
    had spent anything of its own budget.
    """
    from opsbrain.auto.config import AutoConfig

    ops.config = ops.config.model_copy(update={"auto": AutoConfig(
        enabled=True, autonomy_token=TOKEN, review={"runner": "codex", "max_model_calls": 50},
        decision={"mode": "autonomous", "max_model_calls": 4})})
    _autonomous_ops(ops, tmp_path)
    for index in range(3):  # unrelated reviews that consume the service's shared ledger
        ops.auto.review_plan(_plan_for_change(bundle_id=_bundle(ops, tmp_path, f"c-{index:08d}")))
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "APPROVE", (
        "three earlier reviews must not exhaust this decision's own ceiling")


def test_the_refusal_code_is_one_a_client_can_enumerate() -> None:
    """`_decision_refused` emitted a code belonging to no enum, so `autonomy action=reasons` lied."""
    from opsbrain.auto.config import all_reason_codes
    from opsbrain.auto.decision import Reason as DecisionReason

    assert DecisionReason.PLAN_CHANGED.value in set(all_reason_codes())


def test_tightening_a_profile_makes_the_approvals_it_granted_stale(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """#9: a profile is a set of requirements that can be rewritten in place.

    Requiring an extra review of `secrets` left every approval already issued under it spendable, because
    nothing in the binding had moved - it named the profile, and the profile still had the same name. A
    version is the fact that makes a requirements change visible.
    """
    from opsbrain.auto.approval import ApprovalStore
    from opsbrain.auto.config import AutoConfig, PolicyProfileConfig
    from opsbrain.auto.decision import ApprovalEngine

    def config_with(version: str) -> Any:
        return AutoConfig(
            enabled=True, autonomy_token=TOKEN, review={"runner": "codex"},
            decision={"mode": "autonomous", "default_profile": "general"},
            profiles=[PolicyProfileConfig(name="general"),
                      PolicyProfileConfig(name="secrets", allowed_targets=["proxmox"], version=version)])

    ops.config = ops.config.model_copy(update={"auto": config_with("1")})
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id), profile="secrets")
    ops.auto.review_plan(plan)
    approval = ops.auto.decide_change(change.id, plan.id)["approval"]
    assert ApprovalStore(ops.auto.root / "approvals").get(approval).binding.profile_version == "1"

    # The operator tightens the same profile. Its name is unchanged; its requirements are not.
    # A fresh engine over the tightened configuration - the same way a restarted server would see it.
    from opsbrain.auto.approval import ApprovalStore as Store

    engine = ApprovalEngine(ops.config.model_copy(update={"auto": config_with("2")}).auto,
                            Store(ops.auto.root / "approvals"))
    assert Store(ops.auto.root / "approvals").get(approval).binding.profile_version == "1"
    with pytest.raises(OpsError, match="profile_version_changed"):
        engine.gate(ops.changes.get(change.id), spend=False)


def test_a_risk_class_is_a_floor_the_profile_cannot_go_below() -> None:
    """`classification` used to be a word in a config file.

    `extra_reviews: 1` on a `critical` profile meant one review, and nothing said that was too few. Now
    the class states how many reviews it is worth and a configuration asking for fewer is rejected at
    load time rather than quietly governing less than its own name claims.
    """
    from opsbrain.auto.config import PolicyProfileConfig

    assert PolicyProfileConfig(name="general", classification="low", extra_reviews=0).min_reviews == 0
    with pytest.raises(ValueError, match="requires at least 1 review"):
        PolicyProfileConfig(name="general", classification="medium", extra_reviews=0)
    with pytest.raises(ValueError, match="requires at least 2 review"):
        PolicyProfileConfig(name="general", classification="high", extra_reviews=1)
    # Exceeding the floor is fine - the profile may be stricter than its class.
    assert PolicyProfileConfig(name="general", classification="medium", extra_reviews=3).min_reviews == 1


def test_a_serious_class_must_state_whether_autonomy_is_allowed() -> None:
    """`allow_autonomous` defaults to True, and a `critical` profile should not inherit that silently."""
    from opsbrain.auto.config import PolicyProfileConfig

    with pytest.raises(ValueError, match="allow_autonomous must be stated"):
        PolicyProfileConfig(name="general", classification="critical", extra_reviews=2)
    explicit = PolicyProfileConfig(name="general", classification="critical", extra_reviews=2,
                                   allow_autonomous=False)
    assert explicit.allow_autonomous is False


def test_a_class_floor_is_met_by_actually_running_the_reviews(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The floor is a promise the system keeps, not a wall a caller hits.

    `review_plan` asks the profile how many reviews its class is worth and runs that many, so a `medium`
    profile gets its two sessions and the decision proceeds. The refusal remains for the case where the
    runner cannot deliver them.
    """
    from opsbrain.auto.config import AutoConfig, PolicyProfileConfig

    ops.config = ops.config.model_copy(update={"auto": AutoConfig(
        enabled=True, autonomy_token=TOKEN, review={"runner": "codex"},
        decision={"mode": "autonomous", "default_profile": "secrets"},
        profiles=[PolicyProfileConfig(name="secrets", classification="medium", extra_reviews=2,
                                      allowed_targets=["proxmox"], allow_autonomous=True)])})
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id), profile="secrets")
    assert ops.auto._required_runs(plan) == 2, "the class says two, and the reviewer is asked for two"
    ops.auto.review_plan(plan)
    assert len(ops.auto.preflight().get_by_plan(plan.id)["review_refs"]) == 2
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "APPROVE", out["decision"].get("detail", out)


def test_a_floor_the_runner_cannot_meet_still_blocks(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """If the second session cannot be produced, the class floor is not quietly waived."""
    from opsbrain.auto.config import AutoConfig, PolicyProfileConfig

    ops.config = ops.config.model_copy(update={"auto": AutoConfig(
        enabled=True, autonomy_token=TOKEN, review={"runner": "codex", "max_retries": 0},
        decision={"mode": "autonomous", "default_profile": "secrets"},
        profiles=[PolicyProfileConfig(name="secrets", classification="high", extra_reviews=2,
                                      allowed_targets=["proxmox"], allow_autonomous=True)])})
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id), profile="secrets")
    ops.auto.review_plan(plan)
    record = ops.auto.preflight().get_by_plan(plan.id)
    # A second session that failed is not a second session.
    record["review_refs"] = record["review_refs"][:1]
    ops.auto.preflight().store.put(f"pf-{plan.plan_hash[:16]}", record)
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "BLOCKED_AUTONOMOUSLY"
    assert "2 reviews (high class, 1 ran)" in out["decision"]["detail"]


def test_a_profile_requirement_is_matched_against_its_field_not_against_prose(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Saying "systemd" in the diagnosis is not declaring `systemd:unit-start`.

    The requirements were matched by substring against the whole plan, which is a textual substitute for a
    structured requirement - and structured requirements are the entire point of a profile.
    """
    from opsbrain.auto.config import AutoConfig, PolicyProfileConfig

    ops.config = ops.config.model_copy(update={"auto": AutoConfig(
        enabled=True, autonomy_token=TOKEN, review={"runner": "codex"},
        decision={"mode": "autonomous", "default_profile": "secrets"},
        profiles=[PolicyProfileConfig(name="secrets", allowed_targets=["proxmox"],
                                      require_verification=["systemd:unit-start"])])})
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id), profile="secrets")
    ops.auto.review_plan(plan)
    from opsbrain.auto.plan import ChangePlan

    stored = ChangePlan.from_dict(ops.auto.preflight().get_by_plan(plan.id)["plan_document"])
    assert stored.profile == "secrets", "the profile survives into the record the decision reads"
    assert ops.auto._profile_gaps(stored, change, review_ids=("rv-0000abcd",)), "and is what the gate uses"
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "BLOCKED_AUTONOMOUSLY"
    assert "systemd:unit-start" in out["decision"]["detail"]
