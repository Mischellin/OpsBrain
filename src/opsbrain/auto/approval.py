"""What an approval is bound to, when it goes stale, and how it is spent exactly once.

The rule this module exists to enforce: an approval is a decision about *one specific set of inputs*.
Change any of them and the decision no longer describes what would happen, so it must be made again
rather than quietly reused. In practice that covers five things, because those are the five ways a
"same" change can differ from the one a human looked at:

* the **plan** — its hash, so a swapped `.tfplan` cannot be applied under an approval for another one;
* the **arguments** — the limit, the tags, the stack;
* the **targets** — which host or cluster is touched;
* the **evidence** — which bundle the decision was made on, and whether it is still fresh;
* the **policy** — its version, so tightening a policy invalidates approvals made under the old one.

Spending is separate from granting and is exactly-once. A lease is taken atomically before the work
starts and released afterwards, so a retry, a second HTTP request or a second process cannot run the
same approved change twice. Spending is *not* idempotent by accident: a caller that retries has to say
so with the same idempotency key, and gets the earlier outcome back rather than a second execution.
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from ..changes import digest
from ..util import OpsError, new_id, now, write_private

CONTRACT_VERSION = "1.0"

#: A lease longer than this is treated as abandoned: a holder that died mid-apply must not wedge the
#: change forever, and one that is merely slow still finishes inside the normal timeout.
LEASE_TTL_S = 900.0


class StaleReason(StrEnum):
    """Why an approval no longer describes what would happen. Every one of these requires a new review."""

    PLAN_CHANGED = "plan_changed"
    ARGUMENTS_CHANGED = "arguments_changed"
    TARGETS_CHANGED = "targets_changed"
    EVIDENCE_CHANGED = "evidence_changed"
    POLICY_CHANGED = "policy_changed"
    SUBJECT_CHANGED = "subject_changed"
    UNBOUND = "unbound"


class LeaseState(StrEnum):
    ISSUED = "issued"
    CONSUMED = "consumed"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True)
class ApprovalBinding:
    """The five inputs plus the subject, in one content-addressed record.

    Frozen and hashed: an approval that cannot be edited is an approval that cannot be widened after a
    human read it. `binding_hash` covers everything, so a single comparison decides whether the thing
    about to happen is the thing that was approved.
    """

    change_id: str
    subject: str
    plan_hash: str
    arguments_hash: str
    targets: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    policy_version: str
    profile: str = "general"
    expires_s: float = 3600.0
    created: float = field(default_factory=now)

    def __post_init__(self) -> None:
        if not self.change_id.strip():
            raise OpsError("an approval must name the change it approves")
        if not self.plan_hash.strip():
            raise OpsError("an approval must carry the hash of the plan it approves")

    def as_digest_source(self) -> dict[str, Any]:
        return {"contract_version": CONTRACT_VERSION, "change_id": self.change_id, "subject": self.subject,
                "plan_hash": self.plan_hash, "arguments_hash": self.arguments_hash,
                "targets": list(self.targets), "evidence_ids": list(self.evidence_ids),
                "policy_version": self.policy_version, "profile": self.profile}

    @property
    def binding_hash(self) -> str:
        return digest(self.as_digest_source())

    @property
    def id(self) -> str:
        return f"ap-{self.binding_hash[:16]}"

    @property
    def expired(self) -> bool:
        return now() - self.created > self.expires_s

    def to_dict(self) -> dict[str, Any]:
        return {**self.as_digest_source(), "id": self.id, "binding_hash": self.binding_hash,
                "expires_s": self.expires_s, "created": round(self.created, 3)}

    @staticmethod
    def from_dict(data: Any) -> ApprovalBinding:
        if not isinstance(data, dict):
            raise OpsError("an approval binding must be an object")
        if data.get("contract_version", CONTRACT_VERSION) != CONTRACT_VERSION:
            raise OpsError(f"binding contract version mismatch: {data.get('contract_version')!r}")
        return ApprovalBinding(
            change_id=str(data.get("change_id", "")), subject=str(data.get("subject", "")),
            plan_hash=str(data.get("plan_hash", "")), arguments_hash=str(data.get("arguments_hash", "")),
            targets=tuple(data.get("targets", [])), evidence_ids=tuple(data.get("evidence_ids", [])),
            policy_version=str(data.get("policy_version", "")), profile=str(data.get("profile", "general")),
            expires_s=float(data.get("expires_s", 3600.0)), created=float(data.get("created", now())))


def stale_reasons(binding: ApprovalBinding, current: dict[str, Any]) -> tuple[str, ...]:
    """Every reason the approval no longer matches, not just the first.

    Reporting one at a time turns a fix-incrementally loop into N rounds, and a caller who fixes the plan
    hash learns nothing about the policy version that also moved.
    """
    reasons: list[str] = []
    if not current.get("plan_hash"):
        reasons.append(StaleReason.UNBOUND.value)
    for name, stale in (("plan_hash", StaleReason.PLAN_CHANGED), ("arguments_hash", StaleReason.ARGUMENTS_CHANGED),
                        ("subject", StaleReason.SUBJECT_CHANGED), ("policy_version", StaleReason.POLICY_CHANGED)):
        expected = getattr(binding, name)
        # An absent field is a mismatch, not a free pass. Comparing only when the caller supplied a truthy
        # value meant `consume(id, {"plan_hash": expected})` verified one field out of five.
        if current.get(name) != expected:
            reasons.append(stale.value)
    if tuple(current.get("targets") or ()) != binding.targets:
        reasons.append(StaleReason.TARGETS_CHANGED.value)
    if tuple(current.get("evidence_ids") or ()) != binding.evidence_ids:
        reasons.append(StaleReason.EVIDENCE_CHANGED.value)
    return tuple(reasons)


@dataclass(frozen=True)
class Approval:
    binding: ApprovalBinding
    state: LeaseState = LeaseState.ISSUED
    consumed_at: float = 0.0
    lease_owner: str = ""
    outcome: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return self.binding.id

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "state": self.state.value, "binding": self.binding.to_dict(),
                "consumed_at": round(self.consumed_at, 3), "lease_owner": self.lease_owner,
                "outcome": self.outcome}

    @staticmethod
    def from_dict(data: Any) -> Approval:
        if not isinstance(data, dict):
            raise OpsError("an approval must be an object")
        return Approval(binding=ApprovalBinding.from_dict(data.get("binding")),
                        state=LeaseState(data.get("state", "issued")),
                        consumed_at=float(data.get("consumed_at", 0.0)),
                        lease_owner=str(data.get("lease_owner", "")),
                        outcome=dict(data.get("outcome", {})))


class AlreadySpent(OpsError):
    """The idempotent retry was recognised, and there is nothing left to do."""


class ApprovalStore:
    """Durable approvals and single-use leases, both under an exclusive lock.

    The lock is the whole point. `get` -> validate -> write is a race: two HTTP requests, or two OpsBrain
    processes, both read APPROVED and both execute. The read-check-transition is one critical section
    here, and the lease file makes it visible to a process that did not create it.
    """

    def __init__(self, root: Path, *, ttl_s: float = LEASE_TTL_S):
        self.root = root
        self.ttl_s = ttl_s
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    # -- issuing ----------------------------------------------------------------------------------
    def issue(self, binding: ApprovalBinding) -> Approval:
        if binding.expired:
            raise OpsError(f"the plan behind this approval is older than {binding.expires_s:.0f}s; plan again")
        approval = Approval(binding=binding)
        with _locked(self.root / ".approvals.lock"):
            path = self._path(approval.id)
            if path.is_file():
                existing = Approval.from_dict(json.loads(path.read_text(encoding="utf-8")))
                if existing.binding.binding_hash != binding.binding_hash:
                    raise OpsError(f"approval id {approval.id} is held by a different binding")
                if existing.state is LeaseState.ISSUED and not existing.binding.expired:
                    return existing
                # The stored record is spent, revoked or simply too old to use. `created` and `expires_s`
                # are deliberately outside the binding hash - the same decision must keep the same id -
                # so a re-review of an unchanged change lands here and would otherwise hand back the dead
                # record forever, leaving no way to act on a change that is still open. Replacing it keeps
                # the identity and gives the fresh review a live lease; a spent one is refused instead,
                # because overwriting it would erase what ran.
                if existing.state is LeaseState.CONSUMED:
                    raise OpsError(f"approval {approval.id} was already spent; a spent approval is not "
                                   f"replaced, and the change it authorised has already run")
                approval = Approval(binding=binding)
            write_private(path, json.dumps(approval.to_dict(), ensure_ascii=False))
        return approval

    def get(self, approval_id: str) -> Approval:
        path = self._path(approval_id)
        if not path.is_file():
            raise OpsError(f"no approval {approval_id}")
        approval = Approval.from_dict(json.loads(path.read_text(encoding="utf-8")))
        # The id is derived from the binding's own hash, so a record whose recomputed identity disagrees
        # with the name it was read under is not the record that was issued. Trusting the parsed binding
        # instead means anything able to write this file can manufacture an approval for a change of its
        # choosing, with no engine decision behind it - the same defect the change store had.
        if approval.binding.id != approval_id:
            raise OpsError(f"approval {approval_id} does not match its contents "
                           f"(the file holds {approval.binding.id})")
        return approval

    def list(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = []
        for path in sorted(self.root.glob("ap-*.json")):
            try:
                approval = Approval.from_dict(json.loads(path.read_text(encoding="utf-8")))
                if approval.binding.id != path.stem:
                    continue  # a file whose name is not its own identity is not one of ours
                rows.append(approval.to_dict())
            except (OSError, ValueError, OpsError):
                continue
        rows.sort(key=lambda row: float(row["binding"].get("created", 0)), reverse=True)
        return rows[:limit]

    # -- spending ---------------------------------------------------------------------------------
    def consume(self, approval_id: str, current: dict[str, Any], *, owner: str = "",
                idempotency_key: str = "") -> Approval:
        """Spend an approval, exactly once, refusing it if any bound input has moved.

        A retry with the same `idempotency_key` returns the recorded outcome instead of executing again;
        a retry with a *different* key is refused, because that is a second change wearing the same id.
        """
        with _locked(self.root / ".approvals.lock"):
            path = self._path(approval_id)
            if not path.is_file():
                raise OpsError(f"no approval {approval_id}")
            approval = Approval.from_dict(json.loads(path.read_text(encoding="utf-8")))
            if approval.state is LeaseState.REVOKED:
                raise OpsError(f"approval {approval_id} was revoked")
            if approval.state is LeaseState.CONSUMED:
                if idempotency_key and approval.outcome.get("idempotency_key") == idempotency_key:
                    # Marked as a replay so `execute_once` knows not to enter the work a second time.
                    return Approval(binding=approval.binding, state=approval.state,
                                     consumed_at=approval.consumed_at, lease_owner=approval.lease_owner,
                                     outcome={**approval.outcome, "replayed": True})
                raise OpsError(f"approval {approval_id} was already spent "
                               f"(by {approval.lease_owner or 'someone else'})")
            if approval.binding.expired:
                raise OpsError(f"approval {approval_id} expired; review and approve again")
            reasons = stale_reasons(approval.binding, current)
            if reasons:
                raise OpsError(f"approval {approval_id} is STALE ({', '.join(reasons)}): "
                               "the plan, arguments, targets, evidence or policy moved since it was granted")
            spent = Approval(binding=approval.binding, state=LeaseState.CONSUMED, consumed_at=now(),
                             lease_owner=owner or new_id("lease"),
                             outcome={"idempotency_key": idempotency_key} if idempotency_key else {})
            write_private(path, json.dumps(spent.to_dict(), ensure_ascii=False))
            return spent

    def revoke(self, approval_id: str, why: str = "") -> Approval:
        """Withdraw an approval that has not been spent.

        Refuses once the lease is consumed. Overwriting a CONSUMED record with a REVOKED one used to
        destroy `consumed_at` and the recorded outcome - the durable proof of what actually ran - and it
        broke same-key idempotent replay, which then answered "revoked" instead of the earlier outcome.
        A terminal record is not negotiable; there is nothing left to withdraw.
        """
        with _locked(self.root / ".approvals.lock"):
            path = self._path(approval_id)
            if not path.is_file():
                raise OpsError(f"no approval {approval_id}")
            approval = Approval.from_dict(json.loads(path.read_text(encoding="utf-8")))
            if approval.state is LeaseState.CONSUMED:
                raise OpsError(f"approval {approval_id} was already spent by "
                               f"{approval.lease_owner or 'someone else'}; a spent approval cannot be "
                               f"revoked, and the record of what ran is not ours to erase")
            if approval.state is LeaseState.REVOKED:
                return approval
            revoked = Approval(binding=approval.binding, state=LeaseState.REVOKED, lease_owner=why or "revoked")
            write_private(path, json.dumps(revoked.to_dict(), ensure_ascii=False))
            return revoked

    def record_outcome(self, approval_id: str, outcome: dict[str, Any]) -> None:
        with _locked(self.root / ".approvals.lock"):
            path = self._path(approval_id)
            approval = Approval.from_dict(json.loads(path.read_text(encoding="utf-8")))
            write_private(path, json.dumps(
                Approval(binding=approval.binding, state=approval.state, consumed_at=approval.consumed_at,
                         lease_owner=approval.lease_owner,
                         outcome={**approval.outcome, **outcome}).to_dict(), ensure_ascii=False))

    def _path(self, approval_id: str) -> Path:
        body = approval_id[3:] if approval_id.startswith("ap-") else ""
        if not body or not all(character in "0123456789abcdef" for character in body):
            raise OpsError(f"invalid approval id {approval_id!r}")
        return self.root / f"{approval_id}.json"


@contextlib.contextmanager
def execute_once(approval_id: str, store: ApprovalStore, current: dict[str, Any], *,
                 owner: str = "", idempotency_key: str = "") -> Iterator[Approval]:
    """Spend the approval, run the work once, and record what happened.

    A retry with the same idempotency key is *answered*, not re-entered: yielding here would run the
    caller's mutation body a second time, which is precisely what the idempotency key exists to prevent,
    and it would also re-execute after a crash that spent the approval without recording an outcome. The
    recorded outcome is returned through `AlreadySpent` instead, so a caller can report it without the
    body ever running twice.
    """
    approval = store.consume(approval_id, current, owner=owner, idempotency_key=idempotency_key)
    if approval.state is LeaseState.CONSUMED and approval.outcome.get("replayed"):
        raise AlreadySpent(f"approval {approval_id} was already spent by {approval.lease_owner or 'an earlier run'}"
                           f"; the recorded outcome is {approval.outcome}")
    yield approval
    store.record_outcome(approval_id, {"state": "executed", "at": round(now(), 3)})


@contextlib.contextmanager
def _locked(path: Path) -> Iterator[None]:
    """One writer at a time across processes. A lock left by a crash is taken over, not obeyed forever."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    while True:
        try:
            handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            with contextlib.suppress(OSError):
                if time.time() - path.stat().st_mtime > 120:
                    path.unlink()
            time.sleep(0.005)
            continue
        break
    try:
        yield
    finally:
        os.close(handle)
        with contextlib.suppress(OSError):
            path.unlink()


def binding_for(change: Any, *, evidence_ids: Sequence[str] = (), policy_version: str = "",
                profile: str = "general", expires_s: float = 3600.0,
                evidence_expires_in_s: float | None = None) -> ApprovalBinding:
    """Build the binding for an existing `Change`, so a caller cannot quietly leave a field empty.

    Every one of the five inputs is taken from the change record itself rather than from the caller: a
    binding assembled from arguments the caller supplies is a binding the caller chose.

    `evidence_expires_in_s` caps the approval at the moment its own evidence goes stale. The defaults put
    the two an order of magnitude apart - evidence fresh for 900s, an approval good for 3600s - so without
    the cap an approval issued just inside the freshness boundary stays executable for three quarters of
    an hour after the observations behind it stopped describing the world.
    """
    arguments = digest({key: value for key, value in sorted(change.args.items())}) if change.args else ""
    # The binding inherits the change's own age instead of restarting at "now". An approval that outlives
    # the plan it approves is a fresh hour of authority for a plan a human looked at days ago.
    if change.expired:
        raise OpsError(f"change {change.id} expired at {change.expires:.0f}; plan it again")
    remaining = max(0.0, float(change.expires) - now())
    lifetime = min(expires_s, remaining)
    if evidence_expires_in_s is not None:
        # Only ever shortened. A caller passing a larger number must not be able to widen an approval past
        # the life of the evidence it rests on.
        lifetime = min(lifetime, max(0.0, float(evidence_expires_in_s)))
    return ApprovalBinding(
        change_id=change.id, subject=f"{change.capability}:{change.target}", plan_hash=change.hash,
        arguments_hash=arguments, targets=tuple(sorted({change.target})), evidence_ids=tuple(evidence_ids),
        policy_version=policy_version or "unset", profile=profile, expires_s=lifetime,
        created=now())


def verify(approval: Approval, current: dict[str, Any]) -> tuple[str, ...]:
    """The public read-only check: is this approval still a decision about what would happen?"""
    if approval.state is not LeaseState.ISSUED:
        return (f"approval_{approval.state.value}",)
    if approval.binding.expired:
        return ("approval_expired",)
    return stale_reasons(approval.binding, current)
