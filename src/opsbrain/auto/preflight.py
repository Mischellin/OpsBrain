"""Preflight: the review of a plan, before anything changes.

The flow is deliberately dull: assemble the request from a plan and its evidence, hand it to the
ReviewService, and turn the answer into a decision-shaped record. Nothing in here executes anything. A
preflight that could change the world would defeat the point of reviewing it first.

Two failure modes get specific handling, because both are ways a bad plan slips through:

* **Insufficient evidence** is not a soft "maybe". It returns the concrete read-only requests the reviewer
  asked for, and the caller collects them and starts again. It is never rounded up to a pass.
* **A diagnostic that changes state is not read-only.** A check like "does restarting the unit make the
  symptom go away" is an experiment, not a probe, and `read_only_probes` marks anything that might start,
  stop, restart or write as not read-only so the caller cannot run it as a lookup.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ..util import now
from .config import AutoConfig
from .evidence import EvidenceBundle, render_for_reviewer
from .plan import ChangePlan, PlanError
from .review import ReviewLimits, ReviewRequest, ReviewResult, RunnerStatus, Severity, Subject, Verdict
from .store import RecordStore
from .verify import Target

#: Verbs that mean "this request is an experiment", not a probe. Matched on word boundaries, because a
#: plain substring match files `cat /etc/logrotate.conf` as an action on account of the `rotate` inside
#: "logrotate" - and a bucket that cries wolf gets ignored.
_STATE_CHANGING = re.compile(
    r"\b(restart|start|stop|reboot|apply|delete|write|create|patch|scale|sync|flush|rotate|unset|reconfigure"
    r"|drop|enable|disable|reload|kill|reinstall|truncate|reset|revert)\b|\brm\b")


class Outcome(StrEnum):
    """What preflight concluded. Only `APPROVABLE` opens the door; the rest are honest stops."""

    APPROVABLE = "approvable"  # a reviewer said PASS and nothing structural is missing
    NEEDS_CHANGES = "needs_changes"
    NEEDS_EVIDENCE = "needs_evidence"
    DENIED = "denied"
    REVIEW_FAILED = "review_failed"  # timeout, quota, crash, malformed answer
    INCOMPLETE = "incomplete"  # the plan itself is structurally short, whatever the reviewer said


OUTCOME_BY_VERDICT = {
    Verdict.PASS: Outcome.APPROVABLE,
    Verdict.NEEDS_CHANGES: Outcome.NEEDS_CHANGES,
    Verdict.NEEDS_EVIDENCE: Outcome.NEEDS_EVIDENCE,
    Verdict.DENY: Outcome.DENIED,
}

REASON_BY_OUTCOME = {
    Outcome.APPROVABLE: "review_passed",
    Outcome.NEEDS_CHANGES: "review_blocked",
    Outcome.NEEDS_EVIDENCE: "evidence_missing",
    Outcome.DENIED: "policy_forbids",
    Outcome.REVIEW_FAILED: "review_failed",
    Outcome.INCOMPLETE: "evidence_incomplete",
}


@dataclass(frozen=True)
class PreflightResult:
    """The record a decision engine reads. `approvable` is the only field that may authorise anything."""

    plan_id: str
    outcome: Outcome
    reason: str
    review_id: str
    review_status: RunnerStatus
    verdict: Verdict | None
    findings: tuple[dict[str, Any], ...]
    unverified_claims: tuple[str, ...]
    requested_probes: tuple[str, ...]
    state_changing_probes: tuple[str, ...]
    structural_gaps: tuple[str, ...]
    arguments_hash: str
    plan_hash: str
    created: float = 0.0

    @property
    def approvable(self) -> bool:
        return self.outcome is Outcome.APPROVABLE and not self.structural_gaps

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan": self.plan_id,
            "outcome": self.outcome.value,
            "approvable": self.approvable,
            "reason": self.reason,
            "review": self.review_id,
            "review_status": self.review_status.value,
            "verdict": self.verdict.value if self.verdict else None,
            "findings": list(self.findings),
            "unverified_claims": list(self.unverified_claims),
            "requested_probes": list(self.requested_probes),
            "state_changing_probes": list(self.state_changing_probes),
            "structural_gaps": list(self.structural_gaps),
            "arguments_hash": self.arguments_hash,
            "plan_hash": self.plan_hash,
            "created": round(self.created, 3),
        }

    def brief(self) -> dict[str, Any]:
        out: dict[str, Any] = {"plan": self.plan_id, "outcome": self.outcome.value, "approvable": self.approvable,
                               "reason": self.reason, "review": self.review_id}
        if self.verdict is not None:
            out["verdict"] = self.verdict.value
        if self.structural_gaps:
            out["structural_gaps"] = list(self.structural_gaps)
        if self.findings:
            out["findings"] = list(self.findings[:8])
        if self.requested_probes:
            out["requested_probes"] = list(self.requested_probes[:8])
        if self.state_changing_probes:
            out["state_changing_probes"] = list(self.state_changing_probes[:8])
        if self.unverified_claims:
            out["unverified_claims"] = list(self.unverified_claims[:8])
        return out


def split_probes(checks: Sequence[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Separate "go and look" from "go and change something", so a caller can only act on the first.

    A reviewer asking for a diagnostic is not asking for permission to run an experiment. An experiment
    has to be declared in the change plan like any other state change, so the request is surfaced
    separately and never quietly executed as a lookup.
    """
    read_only: list[str] = []
    acting: list[str] = []
    for check in checks:
        (acting if _STATE_CHANGING.search(check.lower()) else read_only).append(check)
    return tuple(read_only), tuple(acting)


class Preflight:
    """Runs one plan review and records the outcome. Holds no executor and mutates nothing."""

    def __init__(self, auto: AutoConfig, reviews: Any, root: Any):
        self.auto = auto
        self.reviews = reviews
        self.store = RecordStore(root / "preflight", ("pf",))

    def limits(self) -> ReviewLimits:
        """The configured ceilings, in the contract's units. A plan longer than the context budget is
        clipped by the service before the id is derived, so the reviewer is asked about what it sees."""
        review = self.auto.review
        return ReviewLimits(timeout_s=review.timeout_s, context_chars=review.context_chars,
                            output_chars=review.output_chars)

    def build_request(self, plan: ChangePlan, bundle: EvidenceBundle | None = None, *,
                      subject_ref: str | None = None) -> ReviewRequest:
        context = [plan.render_for_reviewer()]
        if bundle is not None:
            context.append("")
            context.append(render_for_reviewer(bundle))
        refs = tuple(sorted(set(plan.evidence_refs) | ({bundle.id} if bundle else set())))
        return ReviewRequest(subject=Subject.INFRA_PLAN, subject_ref=subject_ref or plan.id,
                             objective=f"preflight: {plan.objective}", context="\n".join(context),
                             evidence_refs=refs, model=self.auto.review.model,
                             limits=self.limits())

    def run(self, plan: ChangePlan, bundle: EvidenceBundle | None = None, *,
            subject_ref: str | None = None) -> PreflightResult:
        try:
            request = self.build_request(plan, bundle, subject_ref=subject_ref)
        except PlanError:
            raise
        result: ReviewResult = self.reviews.review(request)
        read_only, acting = split_probes(result.next_checks)
        gaps = plan.incomplete()
        outcome = self._outcome(result, gaps)
        preflight = PreflightResult(
            plan_id=plan.id, outcome=outcome, reason=REASON_BY_OUTCOME[outcome], review_id=result.review_id,
            review_status=result.status, verdict=result.verdict,
            findings=tuple(finding.to_dict() for finding in result.findings),
            unverified_claims=tuple(result.unverified_claims), requested_probes=read_only,
            state_changing_probes=acting, structural_gaps=gaps,
            arguments_hash=plan.arguments_hash, plan_hash=plan.plan_hash, created=now())
        self.store.put(f"pf-{plan.plan_hash[:16]}", preflight.to_dict())
        return preflight

    def _outcome(self, result: ReviewResult, gaps: Sequence[str]) -> Outcome:
        """A structurally short plan is not approvable whatever the reviewer answered.

        The reviewer's PASS is about the plan it read. If the plan is missing the evidence it claims, the
        pass is about a fiction, so the structural gap wins - the reviewer is not the only gate.
        """
        if result.status is not RunnerStatus.OK or result.verdict is None:
            return Outcome.REVIEW_FAILED
        if gaps:
            return Outcome.INCOMPLETE
        if result.is_pass:
            return Outcome.APPROVABLE
        if result.verdict is Verdict.PASS:
            # A PASS that carries a BLOCKER is a self-contradicting answer. `is_pass` already refused it;
            # mapping the verdict alone would let the contradiction through and open the door anyway.
            return Outcome.NEEDS_CHANGES
        return OUTCOME_BY_VERDICT.get(result.verdict, Outcome.NEEDS_CHANGES)

    def get(self, plan_hash: str) -> dict[str, Any]:
        return self.store.get(f"pf-{plan_hash[:16]}")

    def list(self, limit: int = 20) -> list[dict[str, Any]]:
        return [{key: row[key] for key in ("plan", "outcome", "approvable", "reason", "verdict", "created")
                 if key in row} for row in self.store.list(limit)]


def declared_state_changing(plan: ChangePlan) -> tuple[str, ...]:
    """The names a plan authorises to act, so the verifier can compare them with what it will run.

    Verification is allowed to start something only if the plan said so *in advance*. This is the one place
    that extracts that declaration, so a plan cannot quietly grow a permitted action after review.
    """
    return tuple(sorted({f"{change.capability}:{change.target}" for change in plan.changes if change.state_changing}))


def verification_targets(plan: ChangePlan) -> tuple[Target, ...]:
    """The targets a verification could be asked about, derived from the plan's declared scope.

    Deliberately empty unless the plan names concrete verification targets: a plan that says "fix the
    logs" has not said what should be checked afterwards, and inventing the target here would let
    verification pass against something nobody planned for.
    """
    return ()


def blocking_findings(result: ReviewResult) -> tuple[dict[str, Any], ...]:
    return tuple(finding.to_dict() for finding in result.findings
                 if finding.severity in (Severity.BLOCKER, Severity.MAJOR))
