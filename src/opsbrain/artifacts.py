"""ArtifactStore: raw command output lives on disk, redacted; Claude gets an id and reads slices on demand."""

from __future__ import annotations

import contextvars
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .redact import redact
from .util import OpsError, clip, new_id, now, write_private

_ID = re.compile(r"^a-[0-9a-f]{8}$")
# bytes of raw output produced while serving the current tool call (for the savings statistics)
raw_bytes: contextvars.ContextVar[int] = contextvars.ContextVar("opsbrain_raw_bytes", default=0)


@dataclass(frozen=True)
class ArtifactMeta:
    id: str
    kind: str
    title: str
    created: float
    bytes: int
    lines: int
    redactions: int


class ArtifactStore:
    def __init__(self, root: Path, *, retention_days: int = 14):
        self.root = root
        self.retention_s = retention_days * 86_400

    def save(self, kind: str, title: str, text: str, *, redacted: bool = False) -> ArtifactMeta:
        """Store `text`. Pass `redacted=True` when the caller has already redacted it.

        Running the text redactor over an already-redacted document is not a no-op: it does not recognise
        the quoted JSON marker `"password":"[REDACTED:value]"` as done, and rewrites it to a bare
        unquoted token - so a stored result that was valid JSON stops parsing. The flag says what is true
        rather than making the caller defend against a second pass.
        """
        clean, redactions = (text, 0) if redacted else redact(text)
        meta = ArtifactMeta(new_id("a"), kind, clip(title, 120), now(), len(clean.encode()), clean.count("\n") + 1,
                            redactions)
        write_private(self.root / f"{meta.id}.txt", clean)
        write_private(self.root / f"{meta.id}.json", json.dumps(asdict(meta)))
        raw_bytes.set(raw_bytes.get() + meta.bytes)
        return meta

    def _text(self, artifact_id: str) -> list[str]:
        if not _ID.fullmatch(artifact_id):
            raise OpsError(f"invalid artifact id: {artifact_id!r}")
        path = self.root / f"{artifact_id}.txt"
        if not path.is_file():
            raise OpsError(f"artifact not found: {artifact_id}")
        return path.read_text(encoding="utf-8").splitlines()

    def read(self, artifact_id: str, start: int = 1, lines: int = 60) -> dict[str, Any]:
        content = self._text(artifact_id)
        start = max(1, start) if start >= 0 else max(1, len(content) + start + 1)
        lines = max(1, min(lines, 400))
        return {"id": artifact_id, "total_lines": len(content), "start": start,
                "text": "\n".join(clip(line, 400) for line in content[start - 1:start - 1 + lines])}

    def grep(self, artifact_id: str, pattern: str, context: int = 0, limit: int = 30) -> dict[str, Any]:
        try:
            regex = re.compile(pattern[:200], re.IGNORECASE)
        except re.error as exc:
            raise OpsError(f"invalid pattern: {exc}") from exc
        content = self._text(artifact_id)
        context = max(0, min(context, 5))
        hits = [index for index, line in enumerate(content) if regex.search(line)]
        out: list[str] = []
        shown: set[int] = set()
        for index in hits[:max(1, min(limit, 200))]:
            for position in range(max(0, index - context), min(len(content), index + context + 1)):
                if position not in shown:
                    shown.add(position)
                    out.append(f"{position + 1}: {clip(content[position], 300)}")
        return {"id": artifact_id, "matches": len(hits), "text": "\n".join(out)}

    def list(self, limit: int = 20) -> list[dict[str, Any]]:
        metas: list[dict[str, Any]] = []
        for path in self.root.glob("a-*.json"):
            try:
                metas.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
        metas.sort(key=lambda meta: meta.get("created", 0), reverse=True)
        return [{"id": meta["id"], "kind": meta["kind"], "title": meta["title"], "lines": meta["lines"],
                 "age_min": int((now() - meta["created"]) / 60)} for meta in metas[:limit]]

    def gc(self) -> int:
        removed = 0
        if not self.root.is_dir():
            return 0
        for path in self.root.glob("a-*"):
            if now() - path.stat().st_mtime > self.retention_s:
                path.unlink(missing_ok=True)
                removed += 1
        return removed
