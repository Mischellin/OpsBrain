"""OPS-AUTO-09: a bounded recovery loop, and a refusal to guess at progress.

Two failures the pipeline has to survive: a plan that needs evidence it does not carry, and a plan that
is simply wrong. Both are answerable - go and get the evidence, or write a different plan - and both are
ways an autonomous system can walk forever. The loop is bounded, durable, and stops with a written
answer rather than another question for a person who is not there.

The property that matters most is the one that is easiest to lose: **a recovery attempt is a new change,
and it inherits nothing.** The change that failed keeps its approval spent, its scope, its profile; the
repair goes back through preflight, review and the deterministic engine like any other change. A loop
that reused the previous approval would be a way around the gate that exists precisely so that not
everything is a way around the gate.

Progress is measured from facts, because a worker that has just been told to try again will report that
it worked:

* the set of *error fingerprints* must strictly shrink - a fingerprint is what failed, not what it was
  called;
* or a property that was never verified before must now be verified.

`attempt.claimed` is recorded, because it is worth seeing in the report, and it is never on its own
sufficient: an attempt that says it succeeded while the same fingerprints remain is not progress, and
treating its own account as evidence is how a loop spends its whole budget re-running the same failure
under a new plan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ..util import OpsError, digest, new_id, now


class Stop(StrEnum):
    """Why the loop stopped. `PROGRESS` is the only one that is not a terminal answer."""

    NONE = "none"
    NO_PROGRESS = "no_progress"
    RETRIES_EXHAUSTED = "retries_exhausted"
    BUDGET_EXHAUSTED = "budget_exhausted"
    DISAGREEMENT = "disagreement"
    OUTCOME_UNKNOWN = "outcome_unknown"
    NO_PERMITTED_ACTION = "no_permitted_action"


class Step(StrEnum):
    """What the loop is allowed to try. The profile names these; the loop never invents one."""

    COLLECT_EVIDENCE = "collect_evidence"
    REWRITE_PLAN = "rewrite_plan"
    ROLLBACK = "rollback"


#: Steps that mutate infrastructure, and therefore produce a new plan and a new approval. `ROLLBACK` is
#: here for the same reason and not as an exception: an undo is a change like any other, and the plan that
#: declared it was reviewed on its own terms.
_MUTATING = frozenset({Step.REWRITE_PLAN, Step.ROLLBACK})


@dataclass(frozen=True)
class Observation:
    """What was actually true at one point in the loop.

    `fingerprints` are the failures themselves - a check name paired with the condition it failed on, not
    a sentence. `verified` is the set of properties somebody has actually established, which is what
    distinguishes "we looked and it holds" from "we assume it holds".
    """

    fingerprints: frozenset[str] = frozenset()
    verified: frozenset[str] = frozenset()
    captured: float = 0.0

    def __post_init__(self) -> None:
        if not self.captured:
            object.__setattr__(self, "captured", now())

    def to_dict(self) -> dict[str, Any]:
        return {"fingerprints": sorted(self.fingerprints), "verified": sorted(self.verified),
                "captured": round(self.captured, 3)}

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> Observation:
        return cls(frozenset(document.get("fingerprints", ())), frozenset(document.get("verified", ())),
                   float(document.get("captured", 0.0) or 0.0))


@dataclass(frozen=True)
class Progress:
    """Whether the last attempt moved anything, and the evidence for that claim."""

    made: bool
    resolved: tuple[str, ...] = ()
    remaining: tuple[str, ...] = ()
    newly_verified: tuple[str, ...] = ()
    why: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"made": self.made, "resolved": list(self.resolved), "remaining": list(self.remaining),
                "newly_verified": list(self.newly_verified), "why": self.why}


def measure(before: Observation, after: Observation, *, claimed: bool = False) -> Progress:
    """Whether `after` is better than `before`, and say which measurement decided it.

    Two things count, and only two: a failure that is no longer there, and a property that was never
    established and now is. Everything else - including the worker's own account - is recorded and
    ignored, because "the drop-in is fixed now" is exactly the sentence a loop would say forever while
    the unit stays masked.
    """
    resolved = tuple(sorted(before.fingerprints - after.fingerprints))
    remaining = tuple(sorted(after.fingerprints))
    newly = tuple(sorted(after.verified - before.verified))
    if resolved:
        return Progress(made=True, resolved=resolved, remaining=remaining, newly_verified=newly,
                        why=f"{len(resolved)} failure(s) no longer reproduce"
                             + ("; ignored its own claim of success" if claimed else ""))
    if newly:
        return Progress(made=True, resolved=(), remaining=remaining, newly_verified=newly,
                        why=f"{len(newly)} propert{'y' if len(newly) == 1 else 'ies'} now established")
    if claimed:
        return Progress(made=False, remaining=remaining,
                        why="the attempt reported success and the same failures are still there; a claim "
                            "is not a measurement")
    return Progress(made=False, remaining=remaining, why="nothing changed that was being measured")


@dataclass
class Attempt:
    """One go round the loop, and what it cost.

    `step` is what was tried and `plan_id` is the plan that came out of it - a *new* one, because the old
    one was the thing that failed. `change_id` is likewise new, and carries no approval until the engine
    issues one against it.
    """

    number: int
    step: str
    before: Observation
    after: Observation
    progress: Progress
    claimed: bool = False
    plan_id: str = ""
    change_id: str = ""
    calls_used: int = 0
    spend_usd: float = 0.0
    created: float = 0.0

    def __post_init__(self) -> None:
        if not self.created:
            self.created = now()

    def to_dict(self) -> dict[str, Any]:
        return {"number": self.number, "step": self.step, "before": self.before.to_dict(),
                "after": self.after.to_dict(), "progress": self.progress.to_dict(),
                "claimed": self.claimed, "plan_id": self.plan_id, "change_id": self.change_id,
                "calls_used": self.calls_used, "spend_usd": self.spend_usd,
                "created": round(self.created, 3)}


@dataclass(frozen=True)
class Ceiling:
    """The four limits a loop runs into, in one place so none of them can be checked by accident.

    All four, not the repair count: a loop bounded only by its own attempts spends the operator's money
    and wall-clock time on the same failure without ever tripping anything.
    """

    max_repair_cycles: int = 3
    max_model_calls: int = 40
    max_spend_usd: float = 0.0
    max_wall_s: float = 1800.0

    def reached(self, loop: Recovery) -> tuple[bool, str]:
        if len(loop.attempts) >= self.max_repair_cycles:
            return True, (f"the repair ceiling is reached ({len(loop.attempts)} of "
                          f"{self.max_repair_cycles} cycles)")
        if loop.calls_used >= self.max_model_calls:
            return True, f"the call ceiling is reached ({loop.calls_used} of {self.max_model_calls} calls)"
        if self.max_spend_usd > 0 and loop.spend_usd >= self.max_spend_usd:
            return True, (f"the spend ceiling is reached (${loop.spend_usd:.4f} of "
                          f"${self.max_spend_usd:.2f})")
        if loop.elapsed_s >= self.max_wall_s:
            return True, (f"the time ceiling is reached ({loop.elapsed_s:.0f}s of "
                          f"{self.max_wall_s:.0f}s)")
        return False, ""


@dataclass
class Recovery:
    """The loop's durable state: where it is, what it has tried, and what it has spent.

    `attempts` is the record the ceilings are measured from, so a restart neither replays a side effect
    nor hands back a fresh budget. The digest binds the change it is recovering and the permitted steps,
    because a loop whose allowed actions can be widened mid-flight is not a bounded loop.
    """

    change_id: str
    permitted: tuple[str, ...]
    attempts: list[Attempt] = field(default_factory=list)
    stop: str = Stop.NONE.value
    stop_reason: str = ""
    baseline_calls: int = 0
    baseline_spend: float = 0.0
    started: float = 0.0
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = new_id("rc")
        if not self.started:
            self.started = now()

    @property
    def digest(self) -> str:
        return digest({"change_id": self.change_id, "permitted": sorted(self.permitted)})

    @property
    def calls_used(self) -> int:
        return sum(attempt.calls_used for attempt in self.attempts)

    @property
    def spend_usd(self) -> float:
        return sum(attempt.spend_usd for attempt in self.attempts)

    @property
    def elapsed_s(self) -> float:
        return now() - self.started

    @property
    def finished(self) -> bool:
        # By value, not identity: `stop` is persisted as a string and read back as one, and a `StrEnum`
        # member is not the same object as its own value - so `is Stop.NONE` was true for every loop
        # loaded from disk, and every restored loop reported itself finished before it began.
        return self.stop != Stop.NONE.value

    def next_step(self) -> str | None:
        """The next permitted action, or None when there is nothing left this loop is allowed to try.

        Consumed once tried, whatever the outcome. A step that made no progress cannot be repeated with
        the same inputs - a different plan for the same unmeasured failure is the same failure - and a
        step that did make progress already produced a change, which running it again would duplicate.
        So the set of permitted steps is spent one at a time, and the loop's answer to running out is to
        stop rather than to ask a person who is not there.
        """
        if self.finished:
            return None
        attempted = {attempt.step for attempt in self.attempts}
        for step in self.permitted:
            if step not in attempted:
                return step
        return None

    def record(self, step: str, before: Observation, after: Observation, *, claimed: bool = False,
               plan_id: str = "", change_id: str = "", calls_used: int = 0, spend_usd: float = 0.0,
               stop: str = Stop.NONE, reason: str = "") -> Attempt:
        """Fold one attempt into the state, and stop if it is the end of the line."""
        progress = measure(before, after, claimed=claimed)
        attempt = Attempt(number=len(self.attempts) + 1, step=step, before=before, after=after,
                          progress=progress, claimed=claimed, plan_id=plan_id, change_id=change_id,
                          calls_used=calls_used, spend_usd=spend_usd)
        self.attempts.append(attempt)
        if stop is not Stop.NONE:
            self.stop = stop.value if isinstance(stop, Stop) else str(stop)
            self.stop_reason = reason
        elif not progress.made:
            # A loop that keeps trying the same unmeasured failure is not bounded in any way that matters.
            self.stop = Stop.NO_PROGRESS.value
            self.stop_reason = progress.why
        elif self.next_step() is None:
            # Every permitted action has been tried. The answer is the state, not another question.
            self.stop = Stop.NO_PERMITTED_ACTION.value
            self.stop_reason = (f"every permitted action ({', '.join(sorted({a.step for a in self.attempts}))})"
                                f" has been tried and the last one worked; the state above is the answer")
        return attempt

    def stop_now(self, stop: str, reason: str) -> None:
        self.stop = stop.value if isinstance(stop, Stop) else str(stop)
        self.stop_reason = reason

    def blocked(self, ceiling: Ceiling) -> tuple[bool, str]:
        """Which ceiling, if any, this loop has already reached, in the operator's own words."""
        return ceiling.reached(self)

    def report(self) -> dict[str, Any]:
        """What an operator reads: the facts as they stand, what is still blocking, the history, the cost."""
        last = self.attempts[-1] if self.attempts else None
        return {"id": self.id, "change_id": self.change_id, "digest": self.digest,
                "permitted": list(self.permitted), "attempts": [a.to_dict() for a in self.attempts],
                "state": {"remaining": list(last.after.fingerprints) if last else [],
                          "verified": sorted(last.after.verified) if last else []},
                "spend": {"calls": self.calls_used, "usd": round(self.spend_usd, 4),
                          "elapsed_s": round(self.elapsed_s, 1)},
                "stop": self.stop, "reason": self.stop_reason,
                "next": self.next_step() or "nothing left to try; the state above is the answer"}

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "change_id": self.change_id, "digest": self.digest,
                "permitted": list(self.permitted), "attempts": [a.to_dict() for a in self.attempts],
                "stop": self.stop, "stop_reason": self.stop_reason, "baseline_calls": self.baseline_calls,
                "baseline_spend": self.baseline_spend, "started": round(self.started, 3)}

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> Recovery:
        if document.get("digest") and document["digest"] != digest(
                {"change_id": document["change_id"], "permitted": sorted(document.get("permitted", ()))}):
            raise OpsError(f"recovery {document.get('id')} is corrupt: its permitted actions do not match "
                           "its own digest")
        loop = cls(change_id=document["change_id"], permitted=tuple(document.get("permitted", ())),
                   stop=document.get("stop", Stop.NONE.value),
                   stop_reason=document.get("stop_reason", ""),
                   baseline_calls=int(document.get("baseline_calls", 0) or 0),
                   baseline_spend=float(document.get("baseline_spend", 0.0) or 0.0),
                   started=float(document.get("started", 0.0) or 0.0), id=document.get("id", ""))
        for row in document.get("attempts", ()):
            loop.attempts.append(Attempt(
                number=int(row["number"]), step=row["step"], before=Observation.from_dict(row["before"]),
                after=Observation.from_dict(row["after"]),
                progress=Progress(bool(row["progress"]["made"]), tuple(row["progress"]["resolved"]),
                                  tuple(row["progress"]["remaining"]), tuple(row["progress"]["newly_verified"]),
                                  row["progress"]["why"]),
                claimed=bool(row.get("claimed")), plan_id=row.get("plan_id", ""),
                change_id=row.get("change_id", ""), calls_used=int(row.get("calls_used", 0) or 0),
                spend_usd=float(row.get("spend_usd", 0.0) or 0.0), created=float(row.get("created", 0.0) or 0.0)))
        return loop


def reconciliation_required(previous: dict[str, Any], observed: dict[str, Any] | None) -> str:
    """Whether the outcome of the previous attempt has to be established before anything is retried.

    An operation whose result nobody observed is not a failed operation - it is an unknown one, and
    repeating it blindly is how a retry duplicates a side effect that had in fact landed. So the answer
    is never "run it again": it is "go and look", and the loop only proceeds once the looking has produced
    a state to reason about.
    """
    if observed is not None and str(observed.get("state") or "") == "resolved":
        return ""
    if previous.get("result") in ("failed", "rc", "error") and observed is None:
        return (f"the previous attempt reported {previous.get('result')!r} and nothing has observed the "
                "target since, so its outcome is unknown rather than failed; establish what is actually "
                "there before running anything again")
    if previous.get("result") in ("ok", "applied") and observed is None:
        return ("the previous attempt reported success and nothing has observed the target since, so a "
                "retry could duplicate work that had already landed; observe before running anything again")
    return ""


def permits_new_change(step: str) -> bool:
    """Whether this step touches infrastructure, and therefore needs its own plan and its own change.

    `COLLECT_EVIDENCE` is the exception and deliberately so: it reads, and it is the one step a profile
    can permit that produces no change at all. The two that do touch infrastructure - rewriting the plan
    and rolling back - both produce a *new* change, and both go back through preflight, review and the
    engine like any other change. A repair that reused the previous change's approval would inherit the
    previous change's authorisation, which is exactly what the gate was installed to prevent.
    """
    return step in _MUTATING


__all__ = ["Attempt", "Ceiling", "Observation", "Progress", "Recovery", "Step", "Stop", "measure",
           "permits_new_change", "reconciliation_required"]
