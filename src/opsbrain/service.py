"""OpsBrain service: everything the MCP tools and the CLI call."""

from __future__ import annotations

from typing import Any

from .config import Config
from .core import Core
from .executor import Executor
from .httpclient import HttpClient
from .jobs import RUNNING
from .operators import Operators
from .readers import Readers


class OpsBrain(Readers, Operators):
    def __init__(self, config: Config, *, executor: Executor | None = None, http: HttpClient | None = None,
                 **kwargs: Any):
        Core.__init__(self, config, executor=executor, http=http, **kwargs)
        self.register_finalizers()

    def overview(self) -> dict[str, Any]:
        """What exists and what is in flight, in one small answer."""
        config = self.config
        tags: dict[str, int] = {}
        for host in config.hosts.values():
            for tag in host.tags or ["untagged"]:
                tags[tag] = tags.get(tag, 0) + 1
        out: dict[str, Any] = {
            "name": config.name,
            "hosts": {"total": len(config.hosts), "by_tag": tags},
            "tofu_stacks": {name: stack.runner for name, stack in config.tofu.items()},
            "ansible_playbooks": self.ansible_playbooks()["playbooks"] if config.ansible else [],
            "k8s": bool(config.k8s), "network": config.network.router if config.network else None,
            "observe": [key for key, value in (("prometheus", config.observe.prometheus_url),
                                               ("loki", config.observe.loki_url),
                                               ("http", config.observe.http_checks)) if value],
            "pending_changes": [change.brief() for change in self.changes.list()][:10],
            "running_jobs": [job.brief() for job in self.jobs.list(50) if job.state == RUNNING][:10],
        }
        if config.docs.memory_file or config.docs.status_file:
            out["state"] = "docs action=status"
        return out
