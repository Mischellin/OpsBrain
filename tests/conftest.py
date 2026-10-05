from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from opsbrain.config import Config
from opsbrain.executor import Executor, Result
from opsbrain.service import OpsBrain


class FakeExecutor(Executor):
    """Records every command; answers from `(regex, Result | callable)` rules. Detached jobs finish at once."""

    def __init__(self, config: Config):
        super().__init__(config)
        self.calls: list[tuple[str, str]] = []
        self.rules: list[tuple[str, Any]] = []
        self.remote: dict[str, tuple[int, str]] = {}  # rc-file -> (rc, log)

    def on(self, pattern: str, answer: Result | Callable[[str], Result] | str, rc: int = 0) -> None:
        self.rules.insert(0, (pattern, Result(rc, answer) if isinstance(answer, str) else answer))

    def _answer(self, where: str, script: str) -> Result:
        self.calls.append((where, script))
        for pattern, answer in self.rules:
            if re.search(pattern, script):
                return answer(script) if callable(answer) else answer
        return Result(0, "")

    def run_local(self, argv, *, cwd=None, env=None, timeout=60, stdin=None):  # type: ignore[no-untyped-def]
        return self._answer("local", " ".join(argv))

    def run_ssh(self, host_name, script, *, timeout=60):  # type: ignore[no-untyped-def]
        self.host(host_name)
        return self._answer(host_name, script)

    def start_local(self, script, log, rc, *, cwd=None, env=None):  # type: ignore[no-untyped-def]
        result = self._answer("local-job", script)
        Path(log).parent.mkdir(parents=True, exist_ok=True)
        Path(log).write_text(result.out)
        Path(rc).write_text(str(result.rc))

    def start_ssh(self, host_name, script, log, rc):  # type: ignore[no-untyped-def]
        result = self._answer(f"{host_name}-job", script)
        self.remote[rc] = (result.rc, result.out)

    def poll_ssh(self, host_name, log, rc, *, full):  # type: ignore[no-untyped-def]
        code, text = self.remote[rc]
        return code, text

    def cleanup_ssh(self, host_name, log, rc):  # type: ignore[no-untyped-def]
        self.remote.pop(rc, None)


class FakeHttp:
    def __init__(self) -> None:
        self.responses: dict[str, Any] = {}
        self.codes: dict[str, int] = {}

    def get_json(self, url: str, params: dict[str, Any] | None = None, timeout: float = 20) -> Any:
        for fragment, response in self.responses.items():
            if fragment in url:
                return response
        raise AssertionError(f"unexpected url {url}")

    def check(self, url: str, timeout: float = 10) -> tuple[int, int]:
        return self.codes.get(url, 200), 12


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "ansible" / "playbooks").mkdir(parents=True)
    (root / "ansible" / "playbooks" / "common.yml").write_text("- hosts: all\n")
    (root / "ansible" / "playbooks" / "firewall.yml").write_text("- hosts: all\n")
    (root / "docs" / "ai").mkdir(parents=True)
    (root / "docs" / "STATUS.md").write_text("# Status\n## Guests\nmanaged by tofu\n## Hosts\nansible\n")
    (root / "docs" / "ai" / "memory.md").write_text("# Log\n## 2026-01-01\nold\n## 2026-02-02\nwireguard rotated, "
                                                    "password: hunter2secret\n")
    (root / "docs" / "vault.md").write_text("never readable\n")
    (root / "network").mkdir()
    (root / "network" / "router.rsc").write_text("# 2026-01-01 10:00:00 by RouterOS 7.15\n/ip address\n"
                                                 "add address=10.0.0.1/24 interface=bridge\n")
    (root / "tf").mkdir()
    (root / "tf" / "main.tf").write_text('resource "x" "y" {}\n')
    return root


@pytest.fixture
def config(tmp_path: Path, repo: Path) -> Config:
    return Config.model_validate({
        "repo": str(repo), "data_dir": str(tmp_path / "data"),
        "hosts": {"pve": {"address": "10.0.0.11", "tags": ["proxmox"]},
                  "ops": {"address": "10.0.0.42", "jump": "pve", "services": ["caddy"]},
                  "router": {"address": "10.0.0.1", "user": "admin", "kind": "routeros"}},
        "tofu": {"proxmox": {"runner": "ops", "dir": "/root/tofu", "env_file": "/root/.tofu.env",
                             "source_dir": "tf"}},
        "ansible": {"dir": "ansible", "require_limit_for_apply": True},
        "k8s": {"context": "test"},
        "network": {"router": "router", "tracked_export": "network/router.rsc"},
        "observe": {"prometheus_url": "http://prom:9090", "loki_url": "http://loki:3100",
                    "http_checks": {"site": "https://example.com", "healthz": "https://example.com/healthz"}},
        "docs": {"globs": ["docs/**/*.md"], "status_file": "docs/STATUS.md", "memory_file": "docs/ai/memory.md"},
        "drift": {"playbooks": ["common"]},
        "policy": {"k8s.refresh": "allow", "hosts.restart:pve": "deny"},
    })


@pytest.fixture
def fake(config: Config) -> FakeExecutor:
    return FakeExecutor(config)


@pytest.fixture
def http() -> FakeHttp:
    return FakeHttp()


@pytest.fixture
def ops(config: Config, fake: FakeExecutor, http: FakeHttp) -> OpsBrain:
    return OpsBrain(config, executor=fake, http=http, sleep=lambda _: None)  # type: ignore[arg-type]


#: Which suite a test belongs to, by the file it lives in. Applied at collection rather than written on
#: every test, because a property a test has is what it *proves* - a security regression is also an
#: end-to-end test, and a decorator on 600 functions would make the two fight over one function.
#:
#: `security` and `e2e` are marked in the files themselves, because those are assertions about the test
#: as much as about the code. Everything else is classified here: the pipeline modules, which wire
#: several together without mutating anything, are integration; the rest are unit.
_PIPELINE = {
    "test_auto_decision.py", "test_auto_approval.py", "test_auto_preflight.py", "test_auto_evidence.py",
    "test_auto_verify.py", "test_auto_postflight.py", "test_auto_rollout.py", "test_auto_recovery.py",
    "test_policy_changes.py",
}


def pytest_collection_modifyitems(items: list[Any]) -> None:
    for item in items:
        path = Path(str(item.fspath)).name
        if item.get_closest_marker("security") or item.get_closest_marker("e2e"):
            continue  # already claimed by the file that wrote it
        item.add_marker(pytest.mark.integration if path in _PIPELINE else pytest.mark.unit)
