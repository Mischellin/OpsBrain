"""Small shared helpers: ids, compact JSON, atomic writes, log compression."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import threading
import time
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class OpsError(Exception):
    """An expected failure reported to the caller as `{"error": ...}` (bad argument, denied, not found)."""


def new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(4)}"


def now() -> float:
    return time.time()


def compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def write_private(path: Path, text: str) -> None:
    """Atomic 0600 write (a change or job record is read by the CLI in another process)."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(temporary, path)


def clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


_TIMESTAMP = re.compile(r"^\S*\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*\s*|^[A-Z][a-z]{2}\s+\d+\s[\d:]{8}\s*")
_VARIABLE = re.compile(r"0x[0-9a-fA-F]+|\b[0-9a-f]{8,}\b|\d+")


def compress_log(lines: list[str], *, top: int = 8, tail: int = 8, width: int = 220) -> dict[str, Any]:
    """Many log lines -> the most frequent message shapes (numbers / ids collapsed) plus the last few lines.

    A thousand repetitions of one error cost one line instead of a thousand.
    """
    lines = [line.rstrip() for line in lines if line.strip()]
    shapes: Counter[str] = Counter()
    example: dict[str, str] = {}
    for line in lines:
        body = _TIMESTAMP.sub("", line)
        shape = _VARIABLE.sub("#", body)[:160]
        shapes[shape] += 1
        example[shape] = body
    patterns = [{"n": count, "msg": clip(example[shape], width)} for shape, count in shapes.most_common(top)
                if count > 1]
    return {"lines": len(lines), "patterns": patterns, "tail": [clip(line, width) for line in lines[-tail:]]}


def hoist_common(rows: list[dict[str, str]]) -> tuple[dict[str, str], list[dict[str, str]]]:
    """Labels identical across every row are returned once instead of once per row."""
    if len(rows) < 2:
        return {}, rows
    common = {key: value for key, value in rows[0].items() if all(row.get(key) == value for row in rows[1:])}
    return common, [{key: value for key, value in row.items() if key not in common} for row in rows]


#: One `threading.Lock` per path, for the half of the exclusion `flock` does not give. `flock` is held per
#: open file description on Linux but per *process* on the BSDs this also runs on, so two threads of one
#: process both "acquire" it. The stores are driven from a thread pool, so without this the kernel lock
#: would be no protection at all inside a single server.
_THREAD_LOCKS: dict[str, threading.Lock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()


def _thread_lock(path: Path) -> threading.Lock:
    with _THREAD_LOCKS_GUARD:
        return _THREAD_LOCKS.setdefault(str(path), threading.Lock())


@contextmanager
def file_lock(path: Path) -> Iterator[None]:
    """Exclusive across processes, released by the kernel when the holder dies.

    The earlier lock here was a file created with `O_EXCL` and reclaimed once its mtime looked old. That
    is a heuristic, and it fails in the worst direction: a process that is merely *slow* — a stalled write,
    a suspended one — loses its lock to a second writer, and when it finally runs its cleanup it unlinks
    the replacement, admitting a third. Two writers then interleave their read-modify-write of the same
    record, which is exactly what the lock exists to prevent.

    `flock` has no such case to get wrong. The kernel drops it when the process exits or is killed, so a
    crash needs no reclaim at all, and a live holder is never displaced. The lock file is kept rather than
    deleted, because unlinking it is the only way to end up with a second inode holding the same name.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with _thread_lock(path):
        handle = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(handle, fcntl.LOCK_UN)
            os.close(handle)


def digest(value: Any) -> str:
    """A stable hash of any JSON-shaped value.

    Lives here rather than in the change store because both `changes` and the `auto` package need it, and
    having `auto` import `changes` for a hash would invert the layering.
    """
    return hashlib.sha256(compact(value).encode()).hexdigest()
