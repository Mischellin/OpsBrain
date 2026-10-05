"""Small shared helpers: ids, compact JSON, atomic writes, log compression."""

from __future__ import annotations

import json
import os
import re
import secrets
import time
from collections import Counter
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
