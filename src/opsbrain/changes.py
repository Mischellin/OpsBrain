"""ChangeStore: the two-step gate in front of every mutation.

`plan` / `check` creates a Change bound to a hash of exactly what would be applied. `apply` consumes
it: it must exist, be unexpired, carry the same hash and - unless policy says `allow` - have been
approved by a human with `opsbrain approve <id>` on a terminal. A change is single use.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .util import OpsError, compact, new_id, now, write_private

_ID = re.compile(r"^c-[0-9a-f]{8}$")
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

    @property
    def expired(self) -> bool:
        return now() > self.expires

    def brief(self) -> dict[str, Any]:
        state = "expired" if self.expired and self.state in (PENDING, APPROVED) else self.state
        return {"id": self.id, "capability": self.capability, "target": self.target, "state": state,
                "dangerous": self.dangerous, "summary": self.summary,
                "expires_min": max(0, int((self.expires - now()) / 60))}


class ChangeStore:
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
        change = self.get(change_id)
        if change.state != PENDING:
            raise OpsError(f"change {change_id} is {change.state}, not pending")
        if change.expired:
            raise OpsError(f"change {change_id} has expired; plan again")
        if change.dangerous and not allow_dangerous:
            raise OpsError(f"change {change_id} destroys or replaces resources: approve with --allow-destroy")
        change.state, change.allow_dangerous, change.decided_at = APPROVED, allow_dangerous, now()
        self._save(change)
        return change

    def discard(self, change_id: str) -> Change:
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
            if change.dangerous and not change.allow_dangerous:
                raise OpsError(f"change {change_id} is destructive: a human must run "
                               f"`opsbrain approve {change_id} --allow-destroy`")
            if needs_approval and change.state != APPROVED:
                raise OpsError(f"change {change_id} is not approved: a human must run `opsbrain approve "
                               f"{change_id}`")
            change.state, change.decided_at = APPLIED, now()
            self._save(change)
            return change

    @contextlib.contextmanager
    def _transition(self, change_id: str) -> Iterator[None]:
        """Exclusive over the whole store directory, so two processes cannot consume one change.

        A lock left behind by a crash is reclaimed after a minute rather than wedging every later
        approval behind a process that no longer exists.
        """
        lock = self.root / f"{change_id}.consume.lock"
        self.root.mkdir(parents=True, exist_ok=True)
        while True:
            try:
                handle = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                with contextlib.suppress(OSError):
                    if time.time() - lock.stat().st_mtime > 60:
                        lock.unlink()
                time.sleep(0.005)
                continue
            break
        try:
            yield
        finally:
            os.close(handle)
            with contextlib.suppress(OSError):
                lock.unlink()
