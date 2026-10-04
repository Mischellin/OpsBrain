"""ChangeStore: the two-step gate in front of every mutation.

`plan` / `check` creates a Change bound to a hash of exactly what would be applied. `apply` consumes
it: it must exist, be unexpired, carry the same hash and - unless policy says `allow` - have been
approved by a human with `opsbrain approve <id>` on a terminal. A change is single use.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .util import OpsError, compact, file_lock, new_id, now, write_private

_ID = re.compile(r"^c-[0-9a-f]{8}$")
#: The id becomes a lock filename, so it is validated as one before it is used as one.
_CHANGE_ID = re.compile(r"^c-[0-9a-f]{8,64}$")
PENDING, APPROVED, APPLIED, DISCARDED = "pending", "approved", "applied", "discarded"


def digest(value: Any) -> str:
    return hashlib.sha256(compact(value).encode()).hexdigest()


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
                              plan_id: str, decision: str, arguments_hash: str = "") -> Change:
        """Record what the decision engine decided against, so the gate can check it later.

        Without this the gate had two options, both bad: trust the binding's own evidence list (which
        proves nothing) or skip the comparison. The recorded values are what `stale_reasons` later
        compares the binding to, so a change edited after the decision reads as stale.
        """
        with self._transition(change_id):
            change = self.get(change_id)
            change.details = {**change.details, "evidence_ids": list(evidence_ids),
                              "policy_version": policy_version, "plan_id": plan_id,
                              "decision": decision, "arguments_hash": arguments_hash}
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
            if self.gate is not None and needs_approval:
                # Before anything else: in autonomous mode this change must be carrying a decision the
                # engine made. A human approval, or no approval at all, does not open this path.
                #
                # Only when an approval is actually being demanded. A policy-allow mutation has nobody to
                # approve anything - the policy already allowed it - so requiring an engine decision there
                # meant the change was created and then immediately refused for lacking a record that
                # could not yet exist. The gate would have been consulted for a decision that was never
                # on the table.
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
