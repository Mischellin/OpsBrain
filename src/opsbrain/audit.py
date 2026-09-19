"""Append-only JSONL audit log: who called what, whether it worked and how many bytes were saved."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .redact import redact_text
from .util import now


class AuditLog:
    def __init__(self, path: Path):
        self.path = path

    def record(self, **fields: Any) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        line = redact_text(json.dumps({"ts": round(now(), 3), **fields}, ensure_ascii=False, default=str))
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        out: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

    def stats(self) -> dict[str, Any]:
        entries = [entry for entry in self.entries() if "tool" in entry]
        raw = sum(int(entry.get("raw_bytes", 0)) for entry in entries)
        returned = sum(int(entry.get("out_bytes", 0)) for entry in entries)
        per_tool: dict[str, dict[str, int]] = {}
        for entry in entries:
            row = per_tool.setdefault(entry["tool"], {"calls": 0, "raw_bytes": 0, "out_bytes": 0})
            row["calls"] += 1
            row["raw_bytes"] += int(entry.get("raw_bytes", 0))
            row["out_bytes"] += int(entry.get("out_bytes", 0))
        return {"calls": len(entries), "raw_bytes": raw, "returned_bytes": returned,
                "tokens_saved_estimate": max(0, raw - returned) // 4, "per_tool": per_tool}
