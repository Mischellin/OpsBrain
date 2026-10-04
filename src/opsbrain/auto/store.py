"""File-backed durable records for the autonomous pipeline.

Everything survives a restart: a review result, an evidence bundle, an approval, a rollout. Records are
written 0600 and atomically, because the CLI in another process reads them and a half-written JSON is
worse than a missing one. Ids are validated against a fixed shape before they ever reach the filesystem,
so a crafted id cannot walk out of the directory.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any

from ..util import OpsError, write_private

_ID = re.compile(r"^[a-z]{1,3}-[0-9a-f]{8,32}$")

#: Reserved names: a record can never be written under a prefix that a directory needs.
_PREFIXES = ("rv", "ev", "ap", "pl", "ro", "rc", "st")


def valid_id(record_id: str, prefixes: tuple[str, ...] = _PREFIXES) -> bool:
    return bool(_ID.fullmatch(record_id)) and record_id.split("-", 1)[0] in prefixes


class RecordStore:
    """One JSON file per record, plus an index by creation time."""

    def __init__(self, root: Path, prefixes: tuple[str, ...] = _PREFIXES):
        self.root = root
        self.prefixes = prefixes
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _path(self, record_id: str) -> Path:
        if not valid_id(record_id, self.prefixes):
            raise OpsError(f"invalid record id: {record_id!r}")
        # `.resolve()` plus the prefix check above: a symlink inside the directory cannot redirect a write
        # outside it, because the name is fully validated and the directory is ours.
        return self.root / f"{record_id}.json"

    def put(self, record_id: str, document: dict[str, Any]) -> None:
        write_private(self._path(record_id), json.dumps(document, ensure_ascii=False, default=str))

    def get(self, record_id: str) -> dict[str, Any]:
        path = self._path(record_id)
        if not path.is_file():
            raise OpsError(f"record not found: {record_id}")
        try:
            document: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise OpsError(f"record {record_id} is corrupt: {exc}") from exc
        return document

    def has(self, record_id: str) -> bool:
        return valid_id(record_id, self.prefixes) and self._path(record_id).is_file()

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for path in self.root.glob("*.json"):
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(document, dict):
                rows.append(document)
        rows.sort(key=lambda row: float(row.get("created", 0) or 0), reverse=True)
        return rows[:limit]

    def update(self, record_id: str, **fields: Any) -> dict[str, Any]:
        document = self.get(record_id)
        document.update(fields)
        document["updated"] = round(time.time(), 3)
        self.put(record_id, document)
        return document

    def gc(self, retention_s: float) -> int:
        removed = 0
        if not self.root.is_dir():
            return 0
        for path in self.root.glob("*.json"):
            try:
                if time.time() - path.stat().st_mtime > retention_s:
                    path.unlink(missing_ok=True)
                    removed += 1
            except OSError:
                continue
        return removed


def atomic_claim(path: Path, owner: str, ttl_s: float) -> str | None:
    """Take an exclusive, expiring lease on a path, or return None if someone holds it.

    `O_CREAT|O_EXCL` is the only cross-process primitive that needs no daemon, and it is what keeps two
    concurrent applies of the same change from both starting. A crashed holder cannot wedge the lease
    forever: an expired file is taken over, and the takeover is visible in the file.
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = json.dumps({"owner": owner, "acquired": round(time.time(), 3), "ttl_s": ttl_s})
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if not _expired(path, ttl_s):
            return None
        # Reclaiming by unlink is a race: the holder whose lease just expired may have been replaced
        # between our read and our unlink, and we would then delete the *new* owner's claim. So the file is
        # renamed to a name of our own first - rename is atomic and cannot clobber a different name - and
        # only what we successfully moved is treated as the expired lease.
        stale = path.with_name(f"{path.name}.stale-{os.getpid()}")
        try:
            os.rename(path, stale)
        except OSError:
            return None
        holder = read_claim(stale)
        if holder is not None and not _expired_dict(holder, ttl_s):
            # Somebody re-created it between the rename and here. Put it back if it is gone.
            with contextlib.suppress(OSError):
                os.rename(stale, path)
            return None
        stale.unlink(missing_ok=True)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return None
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(payload)
    return owner


def _expired(path: Path, ttl_s: float) -> bool:
    document = read_claim(path)
    return True if document is None else _expired_dict(document, ttl_s)


def _expired_dict(document: dict[str, Any], ttl_s: float) -> bool:
    try:
        return time.time() - float(document.get("acquired", 0)) > float(document.get("ttl_s", ttl_s))
    except (TypeError, ValueError):
        return True  # unreadable lease: treat as expired rather than wedged forever


def release_claim(path: Path, owner: str) -> bool:
    """Release the lease, but only if this owner still holds it.

    Read-then-unlink is a race: the lease can expire and be reclaimed by a contender between the two
    steps, and the original owner would then delete the *contender's* live lease while the contender goes
    on believing it owns exclusivity. Renaming the claim to a name of our own first means the thing we
    delete is provably the one we read, because `rename` cannot clobber a different name.
    """
    try:
        document = read_claim(path)
    except OSError:
        return False
    if document is None or document.get("owner") != owner:
        return False
    mine = path.with_name(f"{path.name}.release-{owner}-{os.getpid()}")
    try:
        os.rename(path, mine)
    except OSError:
        return False
    try:
        still = read_claim(mine)
        if still is not None and still.get("owner") != owner:
            with contextlib.suppress(OSError):
                os.rename(mine, path)
            return False
        mine.unlink(missing_ok=True)
    except OSError:
        return False
    return True


def read_claim(path: Path) -> dict[str, Any] | None:
    try:
        document: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return document
