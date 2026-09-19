"""Executor: the only place that starts processes.

Local commands are argv lists (no shell). Remote commands are one script string handed to the remote
shell by `ssh`; callers build it from fixed templates and `shlex.quote` every variable part. Long
operations run detached: `(script) > log 2>&1; echo $? > rc` under nohup / a new session, so an MCP
timeout, a dropped ssh connection or a server restart cannot interrupt a `tofu apply`.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .config import Config, HostConfig
from .util import OpsError

SSH_OPTIONS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new",
               "-o", "ServerAliveInterval=15"]
_PASS_ENV = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "SSH_AUTH_SOCK", "TMPDIR")


@dataclass(frozen=True)
class Result:
    rc: int
    out: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out


class Executor:
    def __init__(self, config: Config):
        self.config = config

    # -- environment -------------------------------------------------------------------------------
    def base_env(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        env = {key: os.environ[key] for key in _PASS_ENV if key in os.environ}
        env.update(extra or {})
        return env

    def ssh_argv(self, host_name: str, script: str) -> list[str]:
        host = self.host(host_name)
        argv = ["ssh", *SSH_OPTIONS, "-p", str(host.port)]
        if host.jump is not None:
            jump = self.host(host.jump)
            argv += ["-J", f"{jump.user}@{jump.address}:{jump.port}"]
        return [*argv, f"{host.user}@{host.address}", script]

    def host(self, name: str) -> HostConfig:
        try:
            return self.config.hosts[name]
        except KeyError:
            raise OpsError(f"unknown host: {name!r}") from None

    # -- short commands ----------------------------------------------------------------------------
    def run_local(self, argv: list[str], *, cwd: Path | None = None, env: Mapping[str, str] | None = None,
                  timeout: float = 60, stdin: str | None = None) -> Result:
        try:
            done = subprocess.run(argv, cwd=cwd, env=self.base_env(env), input=stdin, capture_output=True, text=True,
                                  timeout=timeout, errors="replace", check=False)
        except subprocess.TimeoutExpired as exc:
            partial = exc.stdout if isinstance(exc.stdout, str) else ""
            return Result(124, partial, timed_out=True)
        except OSError as exc:
            return Result(127, f"{argv[0]}: {exc}")
        return Result(done.returncode, done.stdout + (("\n" + done.stderr) if done.stderr.strip() else ""))

    def run_ssh(self, host_name: str, script: str, *, timeout: float = 60) -> Result:
        return self.run_local(self.ssh_argv(host_name, script), timeout=timeout)

    # -- detached jobs -----------------------------------------------------------------------------
    @staticmethod
    def _wrapped(script: str, log: str, rc: str) -> str:
        return f"umask 077; ({script}) > {shlex.quote(log)} 2>&1; echo $? > {shlex.quote(rc)}"

    def start_local(self, script: str, log: Path, rc: Path, *, cwd: Path | None = None,
                    env: Mapping[str, str] | None = None) -> None:
        log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        subprocess.Popen(["sh", "-c", self._wrapped(script, str(log), str(rc))], cwd=cwd, env=self.base_env(env),
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)

    def start_ssh(self, host_name: str, script: str, log: str, rc: str) -> None:
        directory = shlex.quote(os.path.dirname(log))
        launcher = (f"umask 077; mkdir -p {directory} && nohup sh -c {shlex.quote(self._wrapped(script, log, rc))} "
                    "> /dev/null 2>&1 < /dev/null &")
        result = self.run_ssh(host_name, launcher, timeout=30)
        if not result.ok:
            raise OpsError(f"cannot start job on {host_name}: {result.out.strip()[:300]}")

    def poll_ssh(self, host_name: str, log: str, rc: str, *, full: bool) -> tuple[int | None, str]:
        """(exit code or None while running, log tail or whole log)."""
        reader = f"cat {shlex.quote(log)}" if full else f"tail -c 1500 {shlex.quote(log)}"
        result = self.run_ssh(host_name, f"cat {shlex.quote(rc)} 2>/dev/null || echo running; echo @@LOG@@; "
                                         f"{reader} 2>/dev/null", timeout=60)
        if not result.ok:
            raise OpsError(f"cannot poll job on {host_name}: {result.out.strip()[:300]}")
        head, _, body = result.out.partition("@@LOG@@\n")
        state = head.strip()
        return (None if state == "running" or not state.lstrip("-").isdigit() else int(state)), body

    def cleanup_ssh(self, host_name: str, log: str, rc: str) -> None:
        self.run_ssh(host_name, f"rm -f {shlex.quote(log)} {shlex.quote(rc)}", timeout=30)
