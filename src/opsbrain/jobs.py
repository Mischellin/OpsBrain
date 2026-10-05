"""JobStore: records of detached operations. The state lives in files (record, log, rc), never in memory,
so a job started before a server restart can still be polled and finalised afterwards."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .util import OpsError, new_id, now, write_private

_ID = re.compile(r"^j-[0-9a-f]{8}$")
RUNNING, DONE = "running", "done"


@dataclass
class Job:
    id: str
    kind: str
    title: str
    where: str  # "local", a host name, or "group"
    log: str
    rc_file: str
    started: float
    state: str = RUNNING
    rc: int | None = None
    result: dict[str, Any] | None = None
    meta: dict[str, Any] = field(default_factory=dict)
    children: list[str] = field(default_factory=list)

    def brief(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "title": self.title, "state": self.state, "rc": self.rc,
                "age_min": int((now() - self.started) / 60)}


class JobStore:
    def __init__(self, root: Path):
        self.root = root

    def _path(self, job_id: str) -> Path:
        if not _ID.fullmatch(job_id):
            raise OpsError(f"invalid job id: {job_id!r}")
        return self.root / f"{job_id}.json"

    def new(self, kind: str, title: str, where: str, remote_dir: str, meta: dict[str, Any] | None = None,
            children: list[str] | None = None) -> Job:
        job_id = new_id("j")
        base = str(self.root / job_id) if where in ("local", "group") else f"{remote_dir.rstrip('/')}/{job_id}"
        job = Job(job_id, kind, title, where, f"{base}.log", f"{base}.rc", now(), meta=meta or {},
                  children=children or [])
        self.save(job)
        return job

    def save(self, job: Job) -> None:
        write_private(self._path(job.id), json.dumps(asdict(job), ensure_ascii=False, default=str))

    def get(self, job_id: str) -> Job:
        path = self._path(job_id)
        if not path.is_file():
            raise OpsError(f"job not found: {job_id}")
        return Job(**json.loads(path.read_text(encoding="utf-8")))

    def list(self, limit: int = 20) -> list[Job]:
        jobs = []
        for path in self.root.glob("j-*.json"):
            try:
                jobs.append(Job(**json.loads(path.read_text(encoding="utf-8"))))
            except (OSError, ValueError, TypeError):
                continue
        return sorted(jobs, key=lambda job: job.started, reverse=True)[:limit]
