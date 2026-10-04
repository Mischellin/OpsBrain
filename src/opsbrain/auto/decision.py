"""The approval engine: a decision, made the same way every time, or not at all.

Nothing in this module calls a model. That is the whole design. A reviewer may *advise*; the engine
decides, and it decides from structured facts - a preflight outcome, an evidence verdict, a policy
version, a verification report, the operator's autonomy setting. A language model that says "looks good"
is an opinion, and an opinion that can authorise an apply is indistinguishable from a compromised
reviewer.

Four outcomes, and they are not a spectrum:

* `APPROVE` - everything the policy requires was present, current and explicit.
* `RETRY` - the failure is one more attempt could plausibly fix, and the budget allows it.
* `DENY` - the policy forbids it. No amount of retrying changes a `deny` row.
* `BLOCKED_AUTONOMOUSLY` - the engine could not conclude. Deliberately terminal: the point of an
  autonomous path is that it must never come back asking a human for `yes` one more time.

The engine is fail-closed at every step. A missing review, an unverified evidence bundle, a target the
policy does not cover, a runner that errored, a disagreement between two reviews - each is a refusal with
its own reason code, and the codes are enumerated in `auto.config` so a caller can match on them.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ..changes import digest
from ..util import OpsError, new_id, now
from .approval import ApprovalBinding, ApprovalStore, LeaseState, StaleReason, stale_reasons
from .config import AutoConfig
from .evidence import Reason as EvidenceReason
from .preflight import Outcome
from .verify import CheckStatus, VerificationReport

CONTRACT_VERSION = "1.0"


class Decision(StrEnum):
    APPROVE = "APPROVE"
    RETRY = "RETRY"
    DENY = "DENY"
    BLOCKED_AUTONOMOUSLY = "BLOCKED_AUTONOMOUSLY"


class Reason(StrEnum):
    """Why the engine decided what it decided. Every branch below has one, and none share a code."""

    # APPROVE
    POLICY_ALLOWS = "policy_allows"
    HUMAN_APPROVED = "human_approved"
    # RETRY
    RETRYABLE_RUNNER_FAILURE = "retryable_runner_failure"
    RETRY_BUDGET_LEFT = "retry_budget_left"
    STALE_APPROVAL = "stale_approval"
    # DENY
    POLICY_FORBIDS = "policy_forbids"
    REVIEW_DENIED = "review_denied"
    VERIFICATION_FAILED = "verification_failed"
    DESTRUCTIVE_REQUIRES_HUMAN = "destructive_requires_human"
    # BLOCKED_AUTONOMOUSLY
    REVIEW_MISSING = "review_missing"
    REVIEW_FAILED = "review_failed"
    EVIDENCE_MISSING = "evidence_missing"
    EVIDENCE_NOT_FRESH = "evidence_not_fresh"
    VERDICT_DISAGREEMENT = "verdict_disagreement"
    TARGET_NOT_IN_SCOPE = "target_not_in_scope"
    VERIFICATION_UNKNOWN = "verification_unknown"
    VERIFICATION_NOT_RUN = "verification_not_run"
    RETRIES_EXHAUSTED = "retries_exhausted"
    AUTONOMY_OFF = "autonomy_off"
    AUTONOMY_REVOKED = "autonomy_revoked"
    EMERGENCY_STOP = "emergency_stop"
    MODE_UNKNOWN = "mode_unknown"


@dataclass(frozen=True)
class Inputs:
    """Everything the engine is allowed to see. There is no channel for anything else."""

    mode: str
    preflight_outcome: Outcome | None = None
    preflight_reason: str = ""
    #: Tri-state on purpose. `None` means "preflight did not say", which is not `True`, and a plan whose
    #: approvability nobody established must not be approved on the strength of an outcome label alone.
    preflight_approvable: bool | None = None
    evidence_reason: str = EvidenceReason.EVIDENCE_FRESH.value
    evidence_ids: tuple[str, ...] = ()
    review_verdict: str = ""
    review_status: str = ""
    secondary_review_verdict: str = ""
    secondary_review_status: str = ""
    #: How many reviews actually ran and returned OK, counted by the caller that ran them. The engine
    #: compares this with `required_reviews` rather than inferring the number from which fields happen to
    #: be populated: an unmapped second review and a second review that passed look identical otherwise.
    reviews_passed: int = 0
    #: Both are tri-state for the same reason. Defaulting them to `True` meant a caller who forgot to run
    #: or map the policy lookup got an affirmative policy decision it never made.
    policy_allows: bool | None = None
    target_in_scope: bool | None = None
    destructive: bool = False
    human_approved: bool = False
    verification: VerificationReport | None = None
    attempts: int = 0
    policy_version: str = ""
    autonomy_revoked: bool = False


@dataclass(frozen=True)
class DecisionRecord:
    """The durable answer. Contains the reasons, the versions and the references it was based on.

    It is written by the engine and by nothing else: a worker or a reviewer that could write one could
    authorise itself.
    """

    decision: Decision
    reason: Reason
    detail: str
    mode: str
    policy_version: str
    plan_id: str
    arguments_hash: str
    #: The change this decision is about. Carried in the record so issuance can prove the approval it
    #: writes is the one this decision authorised, instead of trusting the binding it was handed.
    change_id: str = ""
    created: float = field(default_factory=now)
    id: str = ""
    evidence_ids: tuple[str, ...] = ()
    review_ids: tuple[str, ...] = ()
    verification_status: str = ""
    attempts: int = 0
    next: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "contract_version": CONTRACT_VERSION, "decision": self.decision.value,
                "reason": self.reason.value, "detail": self.detail, "mode": self.mode,
                "policy_version": self.policy_version, "plan": self.plan_id,
                "change": self.change_id, "arguments_hash": self.arguments_hash,
                "created": round(self.created, 3),
                "evidence_refs": list(self.evidence_ids), "review_refs": list(self.review_ids),
                "verification": self.verification_status, "attempts": self.attempts, "next": self.next}

    @property
    def approvable(self) -> bool:
        return self.decision is Decision.APPROVE

    def brief(self) -> dict[str, Any]:
        out = {key: value for key, value in self.to_dict().items() if value not in ("", (), [], 0)}
        out["approvable"] = self.approvable
        return out


#: Failures worth another attempt. Everything else is terminal, because retrying a `deny` or an unbounded
#: ambiguity is how an autonomous loop turns into a loop.
_RETRYABLE_REVIEW_STATUS = frozenset({"TIMEOUT", "RUNNER_ERROR", "QUOTA_EXHAUSTED", "BUDGET_EXCEEDED"})


class ApprovalEngine:
    """Deterministic. No model, no network, no clock of its own beyond recording the decision."""

    def __init__(self, config: AutoConfig, approvals: ApprovalStore | None = None):
        self.config = config
        self.approvals = approvals
        self.changes: Any = None

    def install(self, changes: Any) -> None:
        """Put this engine in front of the change store, so the executor cannot skip it.

        Without this the human path is enough: an operator runs `opsbrain approve`, the store says
        APPROVED, and the autonomous machinery that was built to decide is simply not consulted. The gate
        makes the engine's decision a precondition of executing, not advice next to it.
        """
        changes.gate = self.gate
        # Kept so `issue` can record what the decision was made against. An engine that was never
        # installed in front of a store has nothing to write to, and must say so rather than issue an
        # approval nothing will later check.
        self.changes = changes

    def gate(self, change: Any) -> bool:
        """Refuse a change the engine has not authorised, when the engine is the one deciding.

        Returns True when the engine's own approval covers this change, which is what lets an autonomous
        execution skip the human step. False means "the engine is not deciding", not "approved".
        """
        if not self.autonomous():
            return False  # manual mode: the human path is the path, and it stands alone
        if not change.engine_approval:
            raise OpsError(
                f"change {change.id} carries no engine approval, and auto.decision.mode is `autonomous`: "
                "run the approval engine instead of approving by hand")
        if self.approvals is None:
            raise OpsError("auto.decision.mode is `autonomous` but no approval store is configured")
        approval = self.approvals.get(change.engine_approval)
        if approval.binding.change_id != change.id:
            raise OpsError(f"approval {approval.id} was issued for {approval.binding.change_id}, "
                           f"not for {change.id}")
        # Liveness, not just provenance. `get()` returns a revoked, consumed or expired approval perfectly
        # happily, and this gate was checking only the binding - so a change could execute under an
        # approval that had already been withdrawn or spent on something else.
        if approval.state is not LeaseState.ISSUED:
            raise OpsError(f"approval {approval.id} is {approval.state.value}, not usable for execution")
        if approval.binding.expired:
            raise OpsError(f"approval {approval.id} expired more than {approval.binding.expires_s:.0f}s ago")
        # The engine's *current* configured version, not the one the binding carries. Supplying the
        # binding's own value makes the comparison equal by construction, so an approval issued under v1
        # stayed executable forever after the policy moved to v2.
        reasons = stale_reasons(approval.binding, self._current_for(change, self.config.decision.policy_version))
        if reasons:
            raise OpsError(f"approval {approval.id} is STALE ({', '.join(reasons)})")
        return True

    @staticmethod
    def _current_for(change: Any, policy_version: str) -> dict[str, Any]:
        """The change's own facts, as the approval must be checked against them.

        Derived from the record, never from the binding: comparing `binding.evidence_ids` with
        `binding.evidence_ids` proves nothing, and an absent field used to be read as "unchanged" - so a
        binding could omit arguments and evidence and still open the gate. `arguments_hash` uses the same
        derivation as `binding_for`, and evidence comes from what issuance recorded on the change, so a
        change edited after the decision is stale on both counts.
        """
        recorded = list(change.details.get("evidence_ids") or ())
        # Derived from the change's own `args` whenever it has any. Preferring a recorded value would make
        # an approval survive an edit to the change: the record would keep asserting the arguments the
        # decision was about while the change described something else. The recorded value is the fallback
        # for a change with no arguments of its own.
        derived = digest({key: value for key, value in sorted(change.args.items())}) if change.args else ""
        return {
            "plan_hash": change.hash,
            "arguments_hash": derived or str(change.details.get("arguments_hash") or ""),
            "subject": f"{change.capability}:{change.target}",
            "targets": [change.target],
            "evidence_ids": recorded,
            "policy_version": policy_version,
        }

    def autonomous(self) -> bool:
        # `enabled` is part of the answer. The gate is installed unconditionally by `Core`, so an
        # `AutoConfig(enabled=False, decision={"mode": "autonomous"})` - valid, and the default shape of a
        # config that simply has not been switched on - would otherwise block ordinary changes for
        # lacking an engine approval from a subsystem the operator turned off.
        return bool(self.config.enabled and self.config.decision.autonomous)

    # ---------------------------------------------------------------------------------- the decision
    def decide(self, inputs: Inputs, plan_id: str, arguments_hash: str, *, change_id: str = "",
               review_ids: Sequence[str] = ()) -> DecisionRecord:
        outcome, reason, detail, nxt = self._evaluate(inputs, plan_id, tuple(review_ids))
        return DecisionRecord(
            id=new_id("dr"), decision=outcome, reason=reason, detail=detail, mode=inputs.mode,
            policy_version=inputs.policy_version, plan_id=plan_id, arguments_hash=arguments_hash,
            change_id=change_id,
            evidence_ids=inputs.evidence_ids, review_ids=tuple(review_ids),
            verification_status=inputs.verification.status.value if inputs.verification else "",
            attempts=inputs.attempts, next=nxt)

    def _evaluate(self, inputs: Inputs, plan_id: str, review_ids: Sequence[str]) -> tuple[Decision, Reason, str, str]:
        # ---- terminal, checked first so nothing downstream can undo them
        if inputs.mode not in ("manual", "autonomous"):
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.MODE_UNKNOWN,
                    f"unknown mode {inputs.mode!r}: the engine will not guess how it is allowed to act", "")

        # ---- policy: a `deny` is a `deny`, in every mode, at every attempt, and before anything that
        # sounds temporary - so a forbidden change is never reported as "a human could approve this".
        if inputs.policy_allows is False:
            return (Decision.DENY, Reason.POLICY_FORBIDS,
                    "policy denies this capability for this target", "no further action")
        if inputs.target_in_scope is False:
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.TARGET_NOT_IN_SCOPE,
                    "the target is not covered by the configured policy, and an uncovered target is not an "
                    "allowed target", "extend the policy explicitly, or leave it to a human")

        # The mode a caller claims must be the mode the operator configured. Otherwise an autonomous
        # engine can be handed `mode="manual"` plus `human_approved=True`, take the manual branch, and
        # issue an engine approval - which is exactly the gate this module exists to keep shut.
        if inputs.mode != self.config.decision.mode:
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.MODE_UNKNOWN,
                    f"the caller asked for {inputs.mode!r} but auto.decision.mode is "
                    f"{self.config.decision.mode!r}: the engine decides in its configured mode only", "")

        if inputs.mode == "autonomous" and self.config.decision.emergency_stop:
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.EMERGENCY_STOP,
                    "auto.decision.emergency_stop is set: every autonomous decision is blocked", "")
        if inputs.mode == "autonomous" and inputs.autonomy_revoked:
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.AUTONOMY_REVOKED,
                    "autonomy for this change was revoked", "")
        if inputs.mode == "autonomous" and not self.autonomous():
            # A missing token is not an invitation: an autonomous decision needs the operator to have
            # asked for one explicitly.
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.AUTONOMY_OFF,
                    "auto.decision.mode is not `autonomous`; the engine will not decide on its own", "")
        if inputs.mode == "manual" and not inputs.human_approved:
            # Without this the manual path was a *weaker* autonomous mode rather than the human's one:
            # everything green and no human anywhere, and the engine approved. `manual` exists so that a
            # person approves; if nobody approved, the answer is that nobody approved.
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.AUTONOMY_OFF,
                    "auto.decision.mode is `manual` and no human approved this change", "")

        # ---- policy facts must have been established, not merely omitted
        if inputs.policy_allows is not True:
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.POLICY_FORBIDS,
                    "no policy decision was supplied for this capability, and an unlooked-up policy is not "
                    "a permissive one", "resolve the policy and decide again")
        if inputs.target_in_scope is not True:
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.TARGET_NOT_IN_SCOPE,
                    "no scope decision was supplied for this target, and an unclassified target is not an "
                    "allowed target", "classify the target and decide again")

        # ---- evidence
        if not inputs.evidence_ids:
            # Regardless of the reason string. A caller that passes the default `evidence_fresh` with an
            # empty list would otherwise reach APPROVE with nothing an auditor could resolve afterwards.
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.EVIDENCE_MISSING,
                    "the decision references no evidence bundle, so nothing about it can be re-checked",
                    "collect evidence")
        if inputs.evidence_reason == EvidenceReason.EVIDENCE_MISSING.value:
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.EVIDENCE_MISSING,
                    f"the evidence bundle is missing: {inputs.evidence_reason}", "collect evidence")
        if inputs.evidence_reason not in (EvidenceReason.EVIDENCE_FRESH.value,):
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.EVIDENCE_NOT_FRESH,
                    f"the evidence is not usable: {inputs.evidence_reason}", "collect fresh evidence")

        # ---- the review, and the shape of its answer
        if not review_ids:
            # A verdict nobody can resolve is not a verdict. Without the reference the record names a
            # judgement with no artefact behind it, and the executor has nothing to re-check.
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.REVIEW_MISSING,
                    "no review reference was recorded, so the PASS cannot be resolved to a stored review",
                    "run a review and keep its reference")
        if not inputs.review_status:
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.REVIEW_MISSING,
                    "no review was run, so nothing was judged", "run a review")
        if inputs.review_status in _RETRYABLE_REVIEW_STATUS:
            if inputs.attempts < self.config.decision.max_repair_cycles:
                return (Decision.RETRY, Reason.RETRYABLE_RUNNER_FAILURE,
                        f"the reviewer reported {inputs.review_status}, which one more attempt may fix",
                        "retry the review")
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.RETRIES_EXHAUSTED,
                    f"the reviewer failed {inputs.review_status} on every attempt", "a human looks at this")
        if inputs.review_status != "OK":
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.REVIEW_FAILED,
                    f"the reviewer could not answer: {inputs.review_status}", "a human looks at this")
        if inputs.review_verdict == "DENY":
            return (Decision.DENY, Reason.REVIEW_DENIED, "the reviewer denied the plan", "revise the plan")
        if inputs.secondary_review_status:
            # Any populated non-OK secondary status has to be handled like the primary one. Handling only
            # a successful disagreement meant a required extra review that timed out vanished, and a
            # passing primary review carried the decision on its own.
            if inputs.secondary_review_status in _RETRYABLE_REVIEW_STATUS:
                if inputs.attempts < self.config.decision.max_repair_cycles:
                    return (Decision.RETRY, Reason.RETRYABLE_RUNNER_FAILURE,
                            f"the second reviewer reported {inputs.secondary_review_status}, which one "
                            "more attempt may fix", "retry the review")
                return (Decision.BLOCKED_AUTONOMOUSLY, Reason.RETRIES_EXHAUSTED,
                        f"the second reviewer failed {inputs.secondary_review_status} on every attempt",
                        "a human looks at this")
            if inputs.secondary_review_status != "OK":
                return (Decision.BLOCKED_AUTONOMOUSLY, Reason.REVIEW_FAILED,
                        f"the second reviewer could not answer: {inputs.secondary_review_status}",
                        "a human looks at this")
            if inputs.secondary_review_verdict != inputs.review_verdict:
                # Two independent reviews that disagree are not a tie to break by preference.
                return (Decision.BLOCKED_AUTONOMOUSLY, Reason.VERDICT_DISAGREEMENT,
                        f"two reviews disagree: {inputs.review_verdict} against "
                        f"{inputs.secondary_review_verdict}", "a human decides")
        if inputs.review_verdict != "PASS":
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.REVIEW_MISSING,
                    f"the reviewer answered {inputs.review_verdict or 'nothing'}", "revise the plan")
        # Every other branch above ends in a refusal, so reaching here means the primary review passed and
        # the secondary one is either absent or in agreement. Count what actually ran and compare with what
        # the profile demands. A profile that requires two reviews and got one blocks, rather than
        # treating the empty second field as a review that happened to pass.
        required = self.config.decision.required_reviews
        passed = max(1, inputs.reviews_passed) if not inputs.secondary_review_status else inputs.reviews_passed
        if passed < required:
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.REVIEW_MISSING,
                    f"{passed} review(s) completed, {required} required: the reviews that were asked for "
                    f"did not happen, and a missing review is not a passing one",
                    f"run {required} reviews and decide again")

        # ---- the plan itself
        if inputs.preflight_outcome is None:
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.REVIEW_MISSING,
                    "the plan was never reviewed", "run preflight")
        if inputs.preflight_outcome in (Outcome.NEEDS_CHANGES, Outcome.DENIED):
            return (Decision.DENY, Reason.REVIEW_DENIED,
                    f"preflight concluded {inputs.preflight_outcome.value} ({inputs.preflight_reason})",
                    "revise the plan")
        if inputs.preflight_outcome is Outcome.NEEDS_EVIDENCE:
            if inputs.attempts < self.config.decision.max_repair_cycles:
                return (Decision.RETRY, Reason.RETRY_BUDGET_LEFT,
                        f"preflight needs evidence: {inputs.preflight_reason}",
                        "collect the evidence the reviewer asked for")
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.RETRIES_EXHAUSTED,
                    f"the evidence never arrived: {inputs.preflight_reason}", "a human looks at this")
        if inputs.preflight_outcome is not Outcome.APPROVABLE or inputs.preflight_approvable is not True:
            # `is not True`, not `is False`: an outcome label of APPROVABLE with an unestablished
            # `approvable` field is a plan nobody confirmed, and `PreflightResult.approvable` is the field
            # that opens the gate. Absent, malformed or unavailable all mean the same thing here.
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.REVIEW_MISSING,
                    f"preflight concluded {inputs.preflight_outcome.value} but approvability is "
                    f"{inputs.preflight_approvable!r} ({inputs.preflight_reason})", "revise the plan")

        # ---- what actually happened, not that the command returned
        report = inputs.verification
        if report is not None:
            # The report has to be about *this* plan. Reading only its aggregate status meant a PASS from
            # an unrelated earlier change could be supplied while deciding this one.
            if report.change_id and plan_id and report.change_id != plan_id:
                return (Decision.BLOCKED_AUTONOMOUSLY, Reason.VERIFICATION_UNKNOWN,
                        f"the verification report is for {report.change_id}, not for {plan_id}",
                        "verify this plan again")
            if report.status is CheckStatus.FAIL:
                return (Decision.DENY, Reason.VERIFICATION_FAILED,
                        f"verification of the applied change failed: {report.brief().get('reason', '')}",
                        "roll back or revise")
            if report.status is CheckStatus.UNKNOWN:
                return (Decision.BLOCKED_AUTONOMOUSLY, Reason.VERIFICATION_UNKNOWN,
                        "verification could not conclude, and an unknown state is not a good one",
                        "collect the missing observation")
            if report.status is CheckStatus.NOT_RUN:
                return (Decision.BLOCKED_AUTONOMOUSLY, Reason.VERIFICATION_NOT_RUN,
                        "the checks that would establish the outcome did not run", "fix the checks")

        # ---- destructive work still belongs to a person
        if inputs.destructive and not inputs.human_approved and not self.autonomous():
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.DESTRUCTIVE_REQUIRES_HUMAN,
                    "the change destroys or replaces resources", "a human approves with --allow-destroy")
        if inputs.destructive and self.autonomous() and not self.config.decision.allow_destructive:
            return (Decision.BLOCKED_AUTONOMOUSLY, Reason.DESTRUCTIVE_REQUIRES_HUMAN,
                    "the change is destructive and auto.decision.allow_destructive is false",
                    "a human approves with --allow-destroy")
        if inputs.human_approved:
            return (Decision.APPROVE, Reason.HUMAN_APPROVED, "a human approved this change", "")

        return (Decision.APPROVE, Reason.POLICY_ALLOWS,
                "the policy allows it, the review passed, the evidence is fresh and the checks agree", "")

    # ------------------------------------------------------------------------------------- issuance
    def issue(self, plan_id: str, arguments_hash: str, binding: ApprovalBinding, *,
              record: DecisionRecord) -> str:
        """Publish the approval the executor will spend, and record what it was decided against.

        Only an APPROVE reaches this. Issuance is also where the change learns which evidence and which
        policy version the decision rested on: `gate` re-derives the change's own facts later and refuses
        anything that moved. Recording them here is what makes that later check compare two real values
        instead of the binding with itself.
        """
        if not record.approvable:
            raise OpsError(f"refusing to issue an approval for {record.decision.value}: {record.detail}")
        if self.approvals is None:
            raise OpsError("no approval store is configured, so there is nothing to spend")
        if self.changes is None:
            raise OpsError("the engine is not installed in front of a change store, so an issued approval "
                           "would record nothing for the gate to check later; call install() first")
        # The binding has to be the one this record decided about. Checking only `record.approvable` and
        # ignoring `plan_id`/`arguments_hash` let an APPROVE produced for one plan authorise an arbitrary
        # binding for another change - the record said yes to something, and the approval said yes to
        # whatever the caller handed over.
        #
        # Every one of these is required, not skipped when absent. `change_id` defaults to empty, so
        # `if record.change_id and ...` compared nothing at all for a record that did not name its change -
        # and that is exactly the record an APPROVE for plan A becomes when it is replayed against plan B.
        if not record.change_id:
            raise OpsError("refusing to issue: the decision does not name the change it was made about, "
                           "so nothing ties this approval to anything")
        if binding.change_id != record.change_id:
            raise OpsError(f"refusing to issue: the binding authorises {binding.change_id!r} but the "
                           f"decision was made about {record.change_id!r}")
        if not record.plan_id:
            raise OpsError("refusing to issue: the decision does not name the plan it was made about, "
                           "so nothing ties this approval to anything")
        if plan_id != record.plan_id:
            raise OpsError(f"refusing to issue: issuance names plan {plan_id!r} but the decision was "
                           f"made about {record.plan_id!r}")
        if arguments_hash != record.arguments_hash:
            raise OpsError(f"refusing to issue: the binding carries arguments {binding.arguments_hash!r} "
                           f"but the decision was about {record.arguments_hash!r}")
        if binding.policy_version != record.policy_version:
            raise OpsError(f"refusing to issue: the binding names policy {binding.policy_version!r} but the "
                           f"decision was made under {record.policy_version!r}")
        if tuple(sorted(binding.evidence_ids)) != tuple(sorted(record.evidence_ids)):
            raise OpsError(f"refusing to issue: the binding names {len(binding.evidence_ids)} evidence "
                           f"references but the decision was made on {len(record.evidence_ids)}")
        if not binding.targets:
            raise OpsError("refusing to issue: the binding names no target, so it authorises nothing")
        approval_id = self.approvals.issue(binding).id
        self.changes.record_decision_inputs(
            binding.change_id, evidence_ids=list(binding.evidence_ids),
            policy_version=binding.policy_version, plan_id=plan_id, decision=record.decision.value,
            arguments_hash=binding.arguments_hash, decision_record=record.to_dict())
        return approval_id

    # ----------------------------------------------------------------------------------------- audit
    @staticmethod
    def stale_binding_reason(reasons: Sequence[str]) -> str:
        return ",".join(sorted(set(reasons))) or StaleReason.UNBOUND.value
