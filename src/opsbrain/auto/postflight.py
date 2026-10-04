"""OPS-AUTO-08: what the change actually achieved, judged against the goal the plan set.

Preflight asks "is this plan worth running". Verification asks "did the facts move the way the plan said
they would". Neither asks the only question an operator has afterwards: *did it work?* A change can pass
review, apply cleanly, and satisfy every declared check while leaving the underlying problem exactly as it
was. Postflight is that question, and it is the one place a model is allowed to answer.

Two properties keep it an observation rather than a second authority:

* **It cannot authorise.** The outcome vocabulary is `CONFIRMED` / `NOT_MET` / `UNCLEAR` - there is no
  "approved", and `Confirm` is not among them, because authorisation is the deterministic engine's job and
  a second one would be a way around it.
* **It cannot be told to confirm.** `CONFIRMED` requires a verification report that actually ran. Without
  one, or with one whose status is not a pass, the most it can say is `UNCLEAR` - a model asked to judge
  an outcome nobody measured will agree with whatever it is shown.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ..util import OpsError, new_id, now
from .review import ReviewRequest, RunnerStatus, Subject, Verdict

#: A separate rubric from the preflight one, so a postflight is not answered from the plan's cache.
POSTFLIGHT_RUBRIC = "opsbrain-rubric-postflight-1"


class Outcome(StrEnum):
    """What the postflight found. There is deliberately no member meaning "authorise"."""

    CONFIRMED = "confirmed"
    NOT_MET = "not_met"
    UNCLEAR = "unclear"


#: Model verdicts mapped onto outcomes. Anything unmapped is `UNCLEAR`, never a confirmation: an answer
#: this code does not recognise is not evidence that the goal was met.
_VERDICT_MAP = {
    "PASS": Outcome.CONFIRMED,
    "NEEDS_CHANGES": Outcome.NOT_MET,
    "NEEDS_EVIDENCE": Outcome.UNCLEAR,
    "DENY": Outcome.NOT_MET,
}


@dataclass(frozen=True)
class Postflight:
    """One postflight judgement, and everything needed to argue with it later."""

    change_id: str
    plan_id: str
    outcome: Outcome
    reason: str
    review_id: str = ""
    model: str = ""
    findings: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    created: float = 0.0
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            object.__setattr__(self, "id", new_id("pf"))
        if not self.created:
            object.__setattr__(self, "created", now())

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "change_id": self.change_id, "plan_id": self.plan_id,
                "outcome": self.outcome.value, "reason": self.reason, "review_id": self.review_id,
                "model": self.model, "findings": list(self.findings),
                "evidence_refs": list(self.evidence_refs), "created": round(self.created, 3)}

    @property
    def confirmed(self) -> bool:
        return self.outcome is Outcome.CONFIRMED

    def next_action(self) -> str:
        """What an operator should do, in one sentence."""
        if self.outcome is Outcome.CONFIRMED:
            return "the change did what the plan said; close it"
        if self.outcome is Outcome.NOT_MET:
            return "the change did not achieve its goal: roll back, or plan the difference"
        return "nobody measured what happened: run the checks, then decide"


def postflight(reviews: Any, *, change_id: str, plan_id: str, objective: str,
               post_checks: tuple[str, ...], rollback: str,
               verification: dict[str, Any] | None = None) -> Postflight:
    """Ask the reviewer whether the goal was met, and answer with what it can support.

    `reviews` is anything with a `review(request) -> ReviewResult` - `ReviewService` in production. Typed
    loosely on purpose: `ReviewService` lives in `service.py`, which imports this package, and naming it
    here would close the cycle.
    """
    # `verification` is the deterministic report from OPS-AUTO-07: the ground truth the model reasons over,
    # and its absence caps the answer at `UNCLEAR`.
    measured = _what_was_measured(verification)
    if not measured:
        # Fail-closed, before the model is asked anything. A judgement made with no measurements is a
        # guess, and a guess that says "confirmed" is the worst possible guess.
        return Postflight(change_id=change_id, plan_id=plan_id, outcome=Outcome.UNCLEAR,
                          reason="nothing measured the outcome, so there is nothing to judge; "
                                 "the checks the plan declared did not run",
                          findings=("the change was applied without a verification report",))
    if measured["status"] != "PASS":
        return Postflight(change_id=change_id, plan_id=plan_id, outcome=Outcome.NOT_MET,
                          reason=f"the checks ran and reported {measured['status']}: "
                                 f"{measured.get('reason') or 'see the report'}",
                          findings=measured["outstanding"], evidence_refs=measured["evidence_refs"])

    request = ReviewRequest(
        subject=Subject.INFRA_RESULT, subject_ref=change_id,
        objective=f"did this change achieve its goal? goal: {objective}",
        rubric_version=POSTFLIGHT_RUBRIC,
        context=_context(objective, post_checks, rollback, measured),
        evidence_refs=tuple(measured["evidence_refs"]))
    try:
        answer = reviews.review(request)
    except OpsError as exc:
        return Postflight(change_id=change_id, plan_id=plan_id, outcome=Outcome.UNCLEAR,
                          reason=f"the reviewer could not answer: {exc}")
    if answer.status is not RunnerStatus.OK or answer.verdict is None:
        # A reviewer that failed did not clear the change. That is what `UNCLEAR` is for.
        return Postflight(change_id=change_id, plan_id=plan_id, outcome=Outcome.UNCLEAR,
                          reason=f"the reviewer reported {answer.status.value}: {answer.note or 'no answer'}",
                          evidence_refs=tuple(measured["evidence_refs"]))
    return Postflight(
        change_id=change_id, plan_id=plan_id, outcome=_VERDICT_MAP.get(answer.verdict.value, Outcome.UNCLEAR),
        reason=(f"the reviewer answered {answer.verdict.value} against a verification report that passed"),
        review_id=answer.review_id, model=answer.model,
        findings=tuple(finding.summary for finding in answer.findings),
        evidence_refs=tuple(measured["evidence_refs"]))


def unobserved(change_id: str, plan_id: str, reason: str) -> Postflight:
    """A postflight that never reached the reviewer, because there was nothing of it to reach.

    Used when the change itself is not something that ran. An `UNCLEAR` built here carries no `review_id`,
    so it is visibly different from one where a reviewer answered and the answer was unusable - which is
    the difference between "nobody looked" and "somebody looked and could not tell".
    """
    return Postflight(change_id=change_id, plan_id=plan_id, outcome=Outcome.UNCLEAR, reason=reason)


def _what_was_measured(verification: dict[str, Any] | None) -> dict[str, Any] | None:
    """The facts the judgement rests on, or None when nothing was measured.

    `brief()` exposes the change as `change`, `to_dict()` as `change_id`; both are accepted because both
    shapes come out of this package.
    """
    if not verification:
        return None
    status = str(verification.get("status") or "")
    if not status or status.upper() in {"NOT_RUN", "UNKNOWN"}:
        return None
    return {
        "status": status.upper(),
        "reason": str(verification.get("reason") or ""),
        "outstanding": [str(item.get("check", "")) for item in verification.get("outstanding", ())],
        "evidence_refs": [str(ref) for ref in verification.get("evidence_refs", ())],
    }


def _context(objective: str, post_checks: tuple[str, ...], rollback: str,
             measured: dict[str, Any]) -> str:
    """What the reviewer is shown: the goal, the checks, and what the facts actually said.

    The outstanding list goes in even when everything passed, because "nothing outstanding" is itself
    a claim the reviewer should be able to check rather than infer.
    """
    declared = [f"  - {check}" for check in post_checks] or ["  (none declared)"]
    lines = [f"goal: {objective}", "", "checks the plan declared:", *declared,
             "", f"rollback available: {rollback or 'none - this change cannot be undone'}",
             "", f"verification status: {measured['status']}",
             f"outstanding: {', '.join(measured['outstanding']) or 'none'}",
             f"evidence: {', '.join(measured['evidence_refs']) or 'none'}",
             "",
             "Answer with the verdict only. State whether the goal was met. Do not propose or approve "
             "any further change: authorisation is not yours to give."]
    return "\n".join(lines)


__all__ = ["Outcome", "Postflight", "postflight", "unobserved", "POSTFLIGHT_RUBRIC", "Verdict"]
