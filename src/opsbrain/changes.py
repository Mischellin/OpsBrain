"""ChangeStore: the two-step gate in front of every mutation.

`plan` / `check` creates a Change bound to a hash of exactly what would be applied. `apply` consumes
it: it must exist, be unexpired, carry the same hash and - unless policy says `allow` - have been
approved by a human with `opsbrain approve <id>` on a terminal. A change is single use.
"""

from __future__ import annotations

import contextlib
import json
import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .util import OpsError, file_lock, new_id, now, write_private
from .util import digest as _digest

_ID = re.compile(r"^c-[0-9a-f]{8}$")
#: The id becomes a lock filename, so it is validated as one before it is used as one.
_CHANGE_ID = re.compile(r"^c-[0-9a-f]{8,64}$")
PENDING, APPROVED, APPLIED, DISCARDED = "pending", "approved", "applied", "discarded"


#: Re-exported: callers throughout the codebase take it from here, and it now lives in `util` so the
#: `auto` package does not have to import the change store for a hash.
digest = _digest


@dataclass
class Change:
    id: str
    capability: str
    target: str
    summary: str
    hash: str
    created: float
    expires: float
    state: str = PENDING
    dangerous: bool = False
    allow_dangerous: bool = False
    args: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    decided_at: float | None = None
    #: The engine-issued approval this change executes under. Set by the engine, never by an operator, and
    #: required in autonomous mode: without it the gate has no record of a decision having been made.
    engine_approval: str = ""

    @property
    def expired(self) -> bool:
        return now() > self.expires

    def brief(self) -> dict[str, Any]:
        state = "expired" if self.expired and self.state in (PENDING, APPROVED) else self.state
        return {"id": self.id, "capability": self.capability, "target": self.target, "state": state,
                "dangerous": self.dangerous, "summary": self.summary,
                "expires_min": max(0, int((self.expires - now()) / 60))}


class ChangeStore:
    #: Installed by the approval engine. `changes.py` deliberately does not import `auto`, so the
    #: dependency runs one way: the engine installs a check, the store calls it, and the store keeps
    #: working unchanged when nothing is installed.
    #: Returns True when the engine itself authorised this change, which satisfies the human-approval
    #: requirement for it. A gate that raises instead refuses; a gate that returns False only leaves the
    #: question of approval where it was.
    gate: Callable[[Change], bool] | None = None
    on_executed: Callable[[Change, str, dict[str, Any]], None] | None = None
    #: The approval the engine spent, handed to the operator path so the *job* records the outcome.
    #: `consume` runs before `start_job`, so claiming "executed" there would assert a mutation that may
    #: never have been dispatched - and a lease recorded as executed is no longer reclaimable.
    spent_approval: str = ""

    def __init__(self, root: Path, ttl_s: int):
        self.root, self.ttl_s = root, ttl_s

    def _path(self, change_id: str) -> Path:
        if not _ID.fullmatch(change_id):
            raise OpsError(f"invalid change id: {change_id!r}")
        return self.root / f"{change_id}.json"

    def _save(self, change: Change) -> None:
        write_private(self._path(change.id), json.dumps(asdict(change), ensure_ascii=False))

    def create(self, capability: str, target: str, summary: str, content_hash: str, *, dangerous: bool = False,
               args: dict[str, Any] | None = None, details: dict[str, Any] | None = None) -> Change:
        change = Change(new_id("c"), capability, target, summary, content_hash, now(), now() + self.ttl_s,
                        dangerous=dangerous, args=args or {}, details=details or {})
        self._save(change)
        return change

    def get(self, change_id: str) -> Change:
        path = self._path(change_id)
        if not path.is_file():
            raise OpsError(f"change not found: {change_id}")
        return Change(**json.loads(path.read_text(encoding="utf-8")))

    def list(self, *, include_closed: bool = False) -> list[Change]:
        changes = []
        for path in self.root.glob("c-*.json"):
            try:
                change = Change(**json.loads(path.read_text(encoding="utf-8")))
            except (OSError, ValueError, TypeError):
                continue
            if include_closed or (change.state in (PENDING, APPROVED) and not change.expired):
                changes.append(change)
        return sorted(changes, key=lambda change: change.created, reverse=True)

    def approve(self, change_id: str, *, allow_dangerous: bool = False) -> Change:
        # approve/discard/consume are three transitions of one record and share one lock. Locking only
        # `consume` leaves the window this closes: a concurrent `approve` reads PENDING, `consume` writes
        # APPLIED, and `approve` writes APPROVED back over it - handing out a second run of a spent change.
        with self._transition(change_id):
            change = self.get(change_id)
            if change.state != PENDING:
                raise OpsError(f"change {change_id} is {change.state}, not pending")
            if change.expired:
                raise OpsError(f"change {change_id} has expired; plan again")
            if change.dangerous and not allow_dangerous:
                raise OpsError(f"change {change_id} destroys or replaces resources: "
                               f"approve with --allow-destroy")
            change.state, change.allow_dangerous, change.decided_at = APPROVED, allow_dangerous, now()
            self._save(change)
        return change

    def update_hash(self, change_id: str, new_hash: str) -> Change:
        """Rewrite the recorded fingerprint. Used only to model "the plan changed after it was approved"."""
        change = self.get(change_id)
        change.hash = new_hash
        self._save(change)
        return change

    def update_args(self, change_id: str, new_args: dict[str, Any]) -> Change:
        """Rewrite the recorded arguments. Used only to model "the arguments moved after the decision".

        Same purpose as `update_hash`, for the other half of the binding: an approval names both, and a
        change whose arguments move after a decision is as stale as one whose plan moves.
        """
        change = self.get(change_id)
        change.args = dict(new_args)
        self._save(change)
        return change

    def note_workflow_start(self, change_id: str, *, calls: int, spend: float, at: float) -> Change:
        """Record what the shared ledger had already spent when this decision first ran.

        `BudgetLedger` is cumulative by design - usage has to survive a restart - so a decision that needs
        its *own* spend has to subtract a baseline rather than read a lifetime total.
        """
        with self._transition(change_id):
            change = self.get(change_id)
            change.details = {**change.details, "baseline_calls": calls, "baseline_spend": spend,
                              "workflow_started": at}
            self._save(change)
        return change

    def record_execution(self, change_id: str, outcome: dict[str, Any]) -> None:
        """Record what the spent lease actually did, from the job that did it."""
        with self._transition(change_id):
            change = self.get(change_id)
            spent = self.spent_approval or change.engine_approval
            if spent and self.on_executed is not None:
                with contextlib.suppress(Exception):  # a lost outcome must not undo the mutation
                    self.on_executed(change, spent, outcome)

    def note_repair_cycle(self, change_id: str) -> Change:
        """Count one repair cycle durably.

        The engine bounds how many times it will answer RETRY for the same change. That bound is only
        real if the count survives the process: held in memory, it starts at zero on every call and a
        change whose reviewer keeps timing out is retried forever.
        """
        with self._transition(change_id):
            change = self.get(change_id)
            change.details = {**change.details,
                              "repair_cycles": int(change.details.get("repair_cycles", 0) or 0) + 1}
            self._save(change)
        return change

    def attach_approval(self, change_id: str, approval_id: str) -> Change:
        """Record the engine-issued approval this change will be executed under.

        Persisted rather than set in memory, because `consume` re-reads the change: an approval attached
        to an object that is never written down is an approval the gate will not see.

        Under the same transition lock as `approve`, `discard` and `consume`, with the whole read-modify-
        write inside it. Without it a redelivered issuance could read `pending`, wait for a `consume` to
        write `applied`, and then write its own stale copy back - putting `pending` and an approval on a
        change that had already run, which is a second run waiting to happen. Attaching to a change that
        is no longer open is refused rather than resurrecting it.
        """
        with self._transition(change_id):
            change = self.get(change_id)
            if change.state not in (PENDING, APPROVED):
                raise OpsError(f"change {change_id} is already {change.state}; an approval attached to it "
                               f"would authorise a second run")
            if change.expired:
                raise OpsError(f"change {change_id} has expired; plan again")
            change.engine_approval = approval_id
            self._save(change)
        return change

    # `Sequence`, not `list`: inside this class body the bare name `list` is `ChangeStore.list`, so a
    # `list[str]` annotation here is not a type at all and mypy is right to say so.
    def record_decision_inputs(self, change_id: str, *, evidence_ids: Sequence[str], policy_version: str,
                              plan_id: str, decision: str, arguments_hash: str = "", profile: str = "",
                              profile_version: str = "", profile_requirements: str = "",
                              decision_record: dict[str, Any] | None = None) -> Change:
        """Record what the decision engine decided against, so the gate can check it later.

        Without this the gate had two options, both bad: trust the binding's own evidence list (which
        proves nothing) or skip the comparison. The recorded values are what `stale_reasons` later
        compares the binding to, so a change edited after the decision reads as stale.

        `decision_record` is the whole record - reason, review references, verification status, attempts,
        id. Persisting it is what makes the approval traceable after a restart: without it, the only
        surviving artefact is a binding, and nobody can say afterwards *why* the execution was allowed.
        """
        with self._transition(change_id):
            change = self.get(change_id)
            change.details = {**change.details, "evidence_ids": list(evidence_ids),
                              "policy_version": policy_version, "plan_id": plan_id,
                              "decision": decision, "arguments_hash": arguments_hash,
                              **({"profile": profile} if profile else {}),
                              **({"profile_version": profile_version} if profile_version else {}),
                              **({"profile_requirements": profile_requirements}
                                 if profile_requirements else {}),
                              **({"decision_id": (decision_record or {}).get("id")}
                                 if decision_record and decision_record.get("id") else {}),
                              **({"decision_record": decision_record} if decision_record else {})}
            self._save(change)
        return change

    def discard(self, change_id: str) -> Change:
        # The whole read-check-write is inside the lock. Taking it only around the read - as an earlier fix
        # did - serialises nothing at all: the check and the write still straddle the unlock.
        with self._transition(change_id):
            change = self.get(change_id)
            if change.state not in (PENDING, APPROVED):
                raise OpsError(f"change {change_id} is already {change.state}")
            change.state, change.decided_at = DISCARDED, now()
            self._save(change)
        return change

    def consume(self, change_id: str, capability: str, target: str, *, needs_approval: bool,
                content_hash: str | None = None) -> Change:
        """Validates and burns the change, atomically. Raises unless everything matches.

        The read-check-write is one critical section. Two HTTP requests, or two OpsBrain processes, both
        used to read APPROVED before either wrote APPLIED, and both ran the mutation - which breaks the
        single-use guarantee in exactly the case it exists for: a retry, or a double submit.
        """
        with self._transition(change_id):
            change = self.get(change_id)
            engine_approved = False
            # A destructive change needs a decision whatever the policy said, so the gate is consulted for
            # it even when no approval is being demanded. Skipping the gate on `needs_approval=False` alone
            # left `auto.decision.allow_destructive` ineffective for a policy-allow target: the operator
            # entry point checked the engine approval, then consumed with `needs_approval=False`, and the
            # destructive guard below demanded a human flag the engine had already covered.
            if self.gate is not None and (needs_approval or change.dangerous):
                # Before anything else: in autonomous mode this change must be carrying a decision the
                # engine made. A human approval, or no approval at all, does not open this path.
                #
                # Not consulted for an ordinary policy-allow mutation. The policy already allowed it, so
                # there is nobody to approve anything, and demanding an engine decision there meant the
                # change was created and then immediately refused for lacking a record that could not yet
                # exist - the gate consulted about a decision that was never on the table.
                engine_approved = self.gate(change)
            if change.capability != capability or change.target != target:
                raise OpsError(f"change {change_id} is for {change.capability}:{change.target}")
            if change.expired:
                raise OpsError(f"change {change_id} has expired; plan again")
            if change.state == APPLIED:
                raise OpsError(f"change {change_id} was already applied (single use)")
            if change.state == DISCARDED:
                raise OpsError(f"change {change_id} was discarded")
            if content_hash is not None and content_hash != change.hash:
                raise OpsError(
                    f"change {change_id}: the code or arguments changed since it was planned; plan again")
            if change.dangerous and not change.allow_dangerous and not engine_approved:
                # The engine only approves a destructive change when the operator set
                # `auto.decision.allow_destructive`, so its approval covers this check too. Without that,
                # the opt-in existed in the decision and was discarded at the point of use, leaving the
                # autonomous destructive path impossible.
                raise OpsError(f"change {change_id} is destructive: a human must run "
                               f"`opsbrain approve {change_id} --allow-destroy`")
            # An engine approval *is* the approval in autonomous mode. Demanding a second, human one on top
            # would make the autonomous path unreachable, which is not the same as making it safe.
            if needs_approval and change.state != APPROVED and not engine_approved:
                raise OpsError(f"change {change_id} is not approved: a human must run `opsbrain approve "
                               f"{change_id}`")
            change.state, change.decided_at = APPLIED, now()
            self._save(change)
            # Handed over, not recorded: the mutation has not been dispatched yet.
            self.spent_approval = change.engine_approval if engine_approved else ""
            return change

    @contextlib.contextmanager
    def _transition(self, change_id: str) -> Iterator[None]:
        """Exclusive over the whole store directory, so two processes cannot consume one change.

        A kernel-held lock, not a lock file reclaimed by age. Reclaiming by mtime let a *slow* process -
        a stalled write, a suspended one - lose its lock to a second writer, and when it finally ran its
        cleanup it unlinked the replacement, admitting a third. Two read-modify-write passes then
        interleaved on one record, which is the thing the lock exists to prevent. `flock` cannot fail that
        way: the kernel drops it when the holder dies, so a crash needs no reclaim at all.
        """
        if not _CHANGE_ID.fullmatch(change_id):
            # The id reaches a filename, so it is checked before it is used as one.
            raise OpsError(f"invalid change id: {change_id!r}")
        with file_lock(self.root / f"{change_id}.transition.lock"):
            yield
