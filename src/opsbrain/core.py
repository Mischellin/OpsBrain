"""Core: shared state of the service, policy gate, detached-job polling and the audited call wrapper."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .artifacts import ArtifactStore, raw_bytes
from .audit import AuditLog
from .auto.service import AutoService
from .changes import Change, ChangeStore
from .config import Access, Config
from .executor import Executor
from .httpclient import HttpClient
from .jobs import DONE, Job, JobStore
from .policy import decide
from .util import OpsError, clip, compact

Finalizer = Callable[[Job, int, str], dict[str, Any]]

LIMIT = re.compile(r"^[A-Za-z0-9_.,:!&*\[\]-]{1,200}$")
TAGS = re.compile(r"^[A-Za-z0-9_.,-]{1,200}$")


class Core:
    def __init__(self, config: Config, *, executor: Executor | None = None, http: HttpClient | None = None,
                 sleep: Callable[[float], None] = time.sleep, reviewer: Any = None):
        self.config = config
        self.exec = executor or Executor(config)
        self.http = http or HttpClient(verify_tls=config.observe.verify_tls)
        self.sleep = sleep
        data = config.data_path
        self.artifacts = ArtifactStore(data / "artifacts", retention_days=config.limits.artifact_retention_days)
        self.changes = ChangeStore(data / "changes", config.limits.change_ttl_s)
        self.jobs = JobStore(data / "jobs")
        self.audit = AuditLog(data / "audit.jsonl")
        self.auto = AutoService(config, reviewer=reviewer)
        self.finalizers: dict[str, Finalizer] = {}

    # -- helpers -----------------------------------------------------------------------------------
    @property
    def repo(self) -> Path:
        return self.config.repo_path

    @property
    def max_items(self) -> int:
        return self.config.limits.max_items

    def capped(self, items: list[Any], limit: int | None = None) -> dict[str, Any]:
        limit = limit or self.max_items
        out: dict[str, Any] = {"items": items[:limit]}
        if len(items) > limit:
            out["more"] = len(items) - limit
        return out

    def require(self, capability: str, target: str = "") -> Access:
        access = decide(self.config.policy, capability, target)
        if access is Access.DENY:
            raise OpsError(f"denied by policy: {capability}{':' + target if target else ''}")
        return access

    def gate(self, capability: str, target: str, change_id: str | None, *, summary: str, content_hash: str,
             args: dict[str, Any] | None = None) -> Change | dict[str, Any]:
        """For mutations with no separate plan step. Returns the consumed Change (go ahead) or the
        response telling Claude that a human has to approve first."""
        access = self.require(capability, target)
        if change_id is None:
            change = self.changes.create(capability, target, summary, content_hash, args=args)
            if access is Access.ALLOW:
                return self.changes.consume(change.id, capability, target, needs_approval=False,
                                            content_hash=content_hash)
            return self.approval_needed(change)
        return self.changes.consume(change_id, capability, target, needs_approval=access is Access.CONFIRM,
                                    content_hash=content_hash)

    @staticmethod
    def approval_needed(change: Change) -> dict[str, Any]:
        flag = " --allow-destroy" if change.dangerous else ""
        return {"change": change.brief(),
                "next": f"ask the user to run `opsbrain approve {change.id}{flag}` in a terminal, then repeat this "
                        f"call with change_id={change.id}"}

    # -- detached jobs -----------------------------------------------------------------------------
    def start_job(self, kind: str, title: str, where: str, script: str, *, meta: dict[str, Any] | None = None,
                  cwd: Path | None = None, env: dict[str, str] | None = None) -> Job:
        job = self.jobs.new(kind, title, where, self.config.remote_job_dir, meta)
        if where == "local":
            self.exec.start_local(script, Path(job.log), Path(job.rc_file), cwd=cwd, env=env)
        else:
            self.exec.start_ssh(where, script, job.log, job.rc_file)
        return job

    def _probe(self, job: Job) -> tuple[int | None, str]:
        if job.where == "local":
            rc_path, log_path = Path(job.rc_file), Path(job.log)
            text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.is_file() else ""
            if not rc_path.is_file():
                return None, text[-1500:]
            state = rc_path.read_text().strip()
            return (int(state) if state.lstrip("-").isdigit() else 1), text
        rc, tail = self.exec.poll_ssh(job.where, job.log, job.rc_file, full=False)
        if rc is None:
            return None, tail
        rc, text = self.exec.poll_ssh(job.where, job.log, job.rc_file, full=True)
        return rc, text

    def poll(self, job: Job) -> dict[str, Any]:
        """Current view of a job; finalises it (parse, artifact, change) the first time it is seen finished."""
        if job.state == DONE:
            return {"job": job.id, "state": DONE, "rc": job.rc, **(job.result or {})}
        if job.children:
            return self._poll_group(job)
        rc, text = self._probe(job)
        if rc is None:
            tail = [clip(line, 200) for line in text.splitlines()[-4:]]
            return {"job": job.id, "state": "running", "age_s": int(time.time() - job.started), "tail": tail,
                    "next": f"job action=status id={job.id}"}
        finalizer = self.finalizers.get(job.kind)
        result = finalizer(job, rc, text) if finalizer else {"artifact": self.artifacts.save(job.kind, job.title,
                                                                                            text).id}
        job.state, job.rc, job.result = DONE, rc, result
        self.jobs.save(job)
        if job.where == "local":
            Path(job.log).unlink(missing_ok=True)
            Path(job.rc_file).unlink(missing_ok=True)
        else:
            self.exec.cleanup_ssh(job.where, job.log, job.rc_file)
        return {"job": job.id, "state": DONE, "rc": rc, **result}

    def _poll_group(self, job: Job) -> dict[str, Any]:
        views = {child: self.poll(self.jobs.get(child)) for child in job.children}
        if any(view["state"] != DONE for view in views.values()):
            running = [child for child, view in views.items() if view["state"] != DONE]
            return {"job": job.id, "state": "running", "waiting_for": running,
                    "next": f"job action=status id={job.id}"}
        finalizer = self.finalizers[job.kind]
        result = finalizer(job, 0, compact(views))
        job.state, job.rc, job.result = DONE, int(result.pop("rc", 0)), result
        self.jobs.save(job)
        return {"job": job.id, "state": DONE, "rc": job.rc, **result}

    def wait(self, job: Job, wait_s: int | None) -> dict[str, Any]:
        budget = self.config.limits.default_wait_s if wait_s is None else max(0, min(int(wait_s), 600))
        deadline = time.monotonic() + budget
        while True:
            view = self.poll(self.jobs.get(job.id))
            if view["state"] == DONE or time.monotonic() >= deadline:
                return view
            self.sleep(2)

    # -- audited entry point -----------------------------------------------------------------------
    def call(self, tool: str, arguments: dict[str, Any], handler: Callable[[], Any]) -> str:
        started = time.monotonic()
        raw_bytes.set(0)
        ok = True
        try:
            result: Any = handler()
        except OpsError as exc:
            ok, result = False, {"error": str(exc)}
        except Exception as exc:  # noqa: BLE001 - a tool must answer, never crash the server
            ok, result = False, {"error": f"internal: {type(exc).__name__}: {str(exc)[:300]}"}
        text = compact(result)
        limit = self.config.limits.max_chars
        if len(text) > limit:
            meta = self.artifacts.save("result", f"{tool} full result", text)
            text = compact({"truncated": True, "artifact": meta.id, "head": text[:limit]})
        self.audit.record(tool=tool, args={key: value for key, value in arguments.items() if value is not None},
                          ok=ok, raw_bytes=max(raw_bytes.get(), len(text)), out_bytes=len(text),
                          ms=int((time.monotonic() - started) * 1000))
        return text
