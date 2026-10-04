"""Operate side: OpenTofu, Ansible and the composite drift check. Everything long runs as a detached job."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import shlex
import tarfile
from pathlib import Path
from typing import Any

from . import parsers
from .changes import digest
from .config import Access, AnsibleConfig, TofuStack
from .core import LIMIT, TAGS, Core
from .jobs import Job
from .util import OpsError, clip

JSON_MARK = "@@OPSBRAIN-JSON@@"
POSTPLAN = re.compile(r"^@@OPSBRAIN-POSTPLAN (\d+)@@$", re.MULTILINE)
_LOCK = re.compile(r"^[0-9a-fA-F-]{8,64}$")
_SYNC_SUFFIXES = (".tf", ".tftpl", ".tpl")
_SKIP_FINGERPRINT = re.compile(r"(^|/)(\.git|__pycache__|\.ansible|collections|\.cache)(/|$)|\.retry$|\.pyc$")


class Operators(Core):
    def register_finalizers(self) -> None:
        self.finalizers.update({"tofu.plan": self._done_tofu_plan, "tofu.apply": self._done_tofu_apply,
                                "ansible.check": self._done_ansible, "ansible.apply": self._done_ansible,
                                "ansible.multi": self._done_ansible_multi, "drift": self._done_drift})

    # ------------------------------------------------------------------------------------------ tofu
    def _stack(self, name: str | None) -> tuple[str, TofuStack]:
        if name is None and len(self.config.tofu) == 1:
            name = next(iter(self.config.tofu))
        if name is None or name not in self.config.tofu:
            raise OpsError(f"stack must be one of {sorted(self.config.tofu)}")
        return name, self.config.tofu[name]

    @staticmethod
    def _tofu_prefix(stack: TofuStack) -> str:
        env = f"set -a && . {shlex.quote(stack.env_file)} && set +a && " if stack.env_file else ""
        return f"cd {shlex.quote(stack.dir)} && {env}"

    def _sync(self, stack: TofuStack) -> dict[str, Any]:
        """Copies the *.tf sources to the runner (never deletes there; reports files that exist only remotely)."""
        assert stack.source_dir is not None
        source = (self.repo / stack.source_dir).resolve()
        if not source.is_relative_to(self.repo) or not source.is_dir():
            raise OpsError(f"tofu source_dir not found: {stack.source_dir}")
        files = sorted(path for path in source.iterdir()
                       if path.is_file() and (path.suffix in _SYNC_SUFFIXES or path.name == ".terraform.lock.hcl"))
        if not files:
            raise OpsError(f"no *.tf files in {stack.source_dir}")
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for path in files:
                archive.add(path, arcname=path.name)
        payload = base64.b64encode(buffer.getvalue()).decode()
        directory = shlex.quote(stack.dir)
        result = self.exec.run_local(
            self.exec.ssh_argv(stack.runner, f"ls {directory}/*.tf 2>/dev/null | xargs -n1 basename; "
                                             f"base64 -d | tar -C {directory} -xzf - && echo @@SYNCED@@"),
            stdin=payload, timeout=120)
        if "@@SYNCED@@" not in result.out:
            raise OpsError(f"sync to {stack.runner} failed: {clip(result.out.strip(), 300)}")
        local = {path.name for path in files}
        remote_only = sorted(name for name in result.out.splitlines() if name.endswith(".tf") and name not in local)
        out: dict[str, Any] = {"files": len(files)}
        if remote_only:
            out["remote_only"] = remote_only  # a file deleted in the repo is still live on the runner
        return out

    def tofu_plan(self, stack: str | None = None, wait_s: int | None = None,
                  sync: bool | None = None) -> dict[str, Any]:
        name, config = self._stack(stack)
        self.require("tofu.plan", name)
        do_sync = config.sync if sync is None else (sync and bool(config.source_dir))
        synced = self._sync(config) if do_sync else None
        job = self.jobs.new("tofu.plan", f"tofu plan {name}", config.runner, self.config.remote_job_dir,
                            {"stack": name, "synced": synced})
        plan_file = f".opsbrain/{job.id}.tfplan"
        binary = shlex.quote(config.binary)
        script = (f"{self._tofu_prefix(config)}mkdir -p .opsbrain && chmod 700 .opsbrain && "
                  "find .opsbrain -name '*.tfplan' -mmin +1440 -delete; "
                  f"{binary} plan -input=false -no-color -lock-timeout=60s -detailed-exitcode -out={plan_file}; rc=$?; "
                  f"if [ $rc -eq 2 ]; then echo {JSON_MARK}; {binary} show -json {plan_file}; "
                  f"else rm -f {plan_file}; fi; exit $rc")
        job.meta["plan_file"] = plan_file
        self.jobs.save(job)
        self.exec.start_ssh(config.runner, script, job.log, job.rc_file)
        return self.wait(job, wait_s)

    def _done_tofu_plan(self, job: Job, rc: int, text: str) -> dict[str, Any]:
        human, _, machine = text.partition(JSON_MARK)
        meta = self.artifacts.save("tofu-plan", job.title, human)  # the JSON part may hold sensitive values: not stored
        stack = job.meta["stack"]
        out: dict[str, Any] = {"stack": stack, "artifact": meta.id}
        if job.meta.get("synced"):
            out["synced"] = job.meta["synced"]
        if rc == 0:
            return {**out, "changes": False}
        if rc != 2:
            return {**out, "failed": True, **parsers.tofu_text(human)}
        document: dict[str, Any] = {}
        for line in machine.splitlines():
            if line.startswith("{"):
                try:
                    document = json.loads(line)
                    break
                except ValueError:
                    continue
        if not document:
            return {**out, "changes": True, **parsers.tofu_text(human),
                    "warning": "plan JSON unreadable: no change was created, plan again"}
        summary = parsers.tofu_plan_json(document, max_items=self.max_items)
        dangerous = bool(summary["destroy"] or summary["replace"])
        line = (f"tofu apply {stack}: +{summary['add']} ~{summary['change']} -{summary['destroy']} "
                f"replace {summary['replace']}")
        change = self.changes.create("tofu.apply", stack, line, digest(parsers.tofu_fingerprint(document)),
                                     dangerous=dangerous, args={"plan_file": job.meta["plan_file"]},
                                     details={"resources": summary["resources"]})
        return {**out, "changes": True, **summary, "dangerous": dangerous, "change": change.id,
                "next": f"tofu action=apply change_id={change.id} (after a human approves it)"}

    def _plan_fingerprint(self, config: Any, plan_file: str) -> str:
        """The digest of the saved plan, read from the runner immediately before the approval is spent.

        The plan lives where `tofu plan` wrote it, on the runner, so it is hashed there. A local read would
        either fail or - worse - silently hash nothing and let a replaced plan through under an approval a
        human gave for the original resource actions.
        """
        binary = shlex.quote(config.binary)
        result = self.exec.run_ssh(
            config.runner,
            f"{self._tofu_prefix(config)}{binary} show -json {shlex.quote(plan_file)}",
            timeout=60)
        if not result.ok:
            raise OpsError(f"the saved plan is unreadable: {clip(result.out.strip(), 120)}")
        # `tofu show` can print a warning before the document, so the first `{` line wins - the same
        # tolerance the plan path already applies, rather than a stricter rule that would fail on a warning.
        for line in result.out.splitlines():
            if line.startswith("{"):
                try:
                    return digest(parsers.tofu_fingerprint(json.loads(line)))
                except ValueError:
                    break
        raise OpsError(f"the saved plan is unreadable: {clip(result.out.strip(), 120)}")

    def tofu_apply(self, change_id: str, wait_s: int | None = None) -> dict[str, Any]:
        pending = self.changes.get(change_id)
        name, config = self._stack(pending.target)
        access = self.require("tofu.apply", name)
        if pending.state == "pending" and (access is Access.CONFIRM or pending.dangerous):
            return self.approval_needed(pending)
        # The saved plan is re-read and re-fingerprinted immediately before the approval is spent.
        # Without it the plan file can be replaced between plan and apply and still run under an
        # approval a human gave for the original resource actions.
        plan_file = str(pending.args["plan_file"])
        change = self.changes.consume(change_id, "tofu.apply", name,
                                      needs_approval=access is Access.CONFIRM,
                                      content_hash=self._plan_fingerprint(config, plan_file))
        if not re.fullmatch(r"\.opsbrain/j-[0-9a-f]{8}\.tfplan", plan_file):
            raise OpsError("corrupt change record")
        binary = shlex.quote(config.binary)
        # a saved plan file is applied: tofu itself refuses it when the state moved since the plan
        script = (f"{self._tofu_prefix(config)}{binary} apply -input=false -no-color -lock-timeout=60s {plan_file}; "
                  f"rc=$?; rm -f {plan_file}; if [ $rc -eq 0 ]; then "
                  f"{binary} plan -input=false -no-color -lock-timeout=60s -detailed-exitcode > /dev/null 2>&1; "
                  "echo \"@@OPSBRAIN-POSTPLAN $?@@\"; fi; exit $rc")
        job = self.start_job("tofu.apply", f"tofu apply {name}", config.runner, script,
                             meta={"stack": name, "change": change.id})
        return self.wait(job, wait_s)

    def _done_tofu_apply(self, job: Job, rc: int, text: str) -> dict[str, Any]:
        meta = self.artifacts.save("tofu-apply", job.title, text)
        out: dict[str, Any] = {"stack": job.meta["stack"], "change": job.meta["change"], "artifact": meta.id,
                               "ok": rc == 0, **parsers.tofu_text(text)}
        if match := POSTPLAN.search(text):
            out["post_plan_clean"] = match[1] == "0"
            if match[1] != "0":
                out["hint"] = "plan after apply still shows changes: usually needs a targeted ignore_changes"
        return out

    def tofu_state(self, stack: str | None = None, grep: str | None = None) -> dict[str, Any]:
        name, config = self._stack(stack)
        self.require("tofu.state", name)
        result = self.exec.run_ssh(config.runner, f"{self._tofu_prefix(config)}{shlex.quote(config.binary)} state list",
                                   timeout=120)
        if not result.ok:
            raise OpsError(f"tofu state list: {clip(result.out.strip(), 300)}")
        addresses = [line.strip() for line in result.out.splitlines() if line.strip() and not line.startswith(" ")]
        if grep:
            addresses = [address for address in addresses if grep.lower() in address.lower()]
        return {"stack": name, "resources": len(addresses), **self.capped(addresses, 60)}

    def tofu_unlock(self, lock_id: str, stack: str | None = None, change_id: str | None = None) -> dict[str, Any]:
        name, config = self._stack(stack)
        if not _LOCK.fullmatch(lock_id):
            raise OpsError(f"invalid lock id: {lock_id!r}")
        gate = self.gate("tofu.unlock", name, change_id, summary=f"tofu force-unlock {lock_id} ({name})",
                         content_hash=digest(["tofu.unlock", name, lock_id]))
        if isinstance(gate, dict):
            return gate
        result = self.exec.run_ssh(config.runner, f"{self._tofu_prefix(config)}{shlex.quote(config.binary)} "
                                                  f"force-unlock -force {shlex.quote(lock_id)}", timeout=90)
        return {"stack": name, "ok": result.ok, "output": clip(result.out.strip(), 300), "change": gate.id}

    # --------------------------------------------------------------------------------------- ansible
    def _ansible(self) -> tuple[AnsibleConfig, Path]:
        config = self.config.ansible
        if config is None:
            raise OpsError("ansible is not configured")
        directory = (self.repo / config.dir).resolve()
        if not directory.is_relative_to(self.repo) or not directory.is_dir():
            raise OpsError(f"ansible dir not found: {config.dir}")
        return config, directory

    def ansible_playbooks(self) -> dict[str, Any]:
        config, directory = self._ansible()
        found = sorted(path.stem for path in (directory / config.playbooks_dir).glob("*.yml"))
        allowed = [name for name in found if not config.playbooks or name in config.playbooks]
        return {"playbooks": allowed}

    def _playbook_command(self, playbook: str, limit: str | None, tags: str | None, *, check: bool) -> str:
        config, _ = self._ansible()
        if playbook not in self.ansible_playbooks()["playbooks"]:
            raise OpsError(f"unknown playbook {playbook!r}: see ansible action=playbooks")
        if limit is not None and not LIMIT.fullmatch(limit):
            raise OpsError(f"invalid limit: {limit!r}")
        if tags is not None and not TAGS.fullmatch(tags):
            raise OpsError(f"invalid tags: {tags!r}")
        parts = [shlex.quote(str(Path(config.playbook_bin).expanduser())),
                 shlex.quote(f"{config.playbooks_dir}/{playbook}.yml"), "--diff"]
        if check:
            parts.append("--check")
        if limit:
            parts += ["--limit", shlex.quote(limit)]
        if tags:
            parts += ["--tags", shlex.quote(tags)]
        return " ".join(parts)

    def _ansible_env(self) -> dict[str, str]:
        config, _ = self._ansible()
        env = {"ANSIBLE_NOCOLOR": "1", "ANSIBLE_FORCE_COLOR": "0", "PYTHONUNBUFFERED": "1", **config.env}
        if config.ssh_auth_sock_from_launchctl:
            result = self.exec.run_local(["launchctl", "getenv", "SSH_AUTH_SOCK"], timeout=10)
            if result.ok and result.out.strip():
                env["SSH_AUTH_SOCK"] = result.out.strip()
        return env

    def _fingerprint(self) -> str:
        """Hash of every file under the ansible directory: an approved check is void once the code changes."""
        _, directory = self._ansible()
        sha = hashlib.sha256()
        for path in sorted(directory.rglob("*")):
            relative = path.relative_to(directory).as_posix()
            if path.is_file() and not _SKIP_FINGERPRINT.search(relative):
                sha.update(relative.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
        return sha.hexdigest()

    def _ansible_hash(self, playbook: str, limit: str | None, tags: str | None) -> str:
        return digest(["ansible.apply", playbook, limit or "", tags or "", self._fingerprint()])

    def ansible_check(self, playbook: str, limit: str | None = None, tags: str | None = None,
                      wait_s: int | None = None) -> dict[str, Any]:
        self.require("ansible.check", playbook)
        _, directory = self._ansible()
        command = self._playbook_command(playbook, limit, tags, check=True)
        job = self.start_job("ansible.check", f"ansible --check {playbook} {limit or 'all'}", "local", command,
                             cwd=directory, env=self._ansible_env(),
                             meta={"playbook": playbook, "limit": limit, "tags": tags,
                                   "hash": self._ansible_hash(playbook, limit, tags)})
        return self.wait(job, wait_s)

    def ansible_apply(self, change_id: str, wait_s: int | None = None) -> dict[str, Any]:
        config, directory = self._ansible()
        pending = self.changes.get(change_id)
        playbook = pending.target
        limit, tags = pending.args.get("limit"), pending.args.get("tags")
        access = self.require("ansible.apply", playbook)
        if config.require_limit_for_apply and not limit:
            raise OpsError("apply needs a limit (ansible.require_limit_for_apply): run the check with `limit`")
        if pending.state == "pending" and access is Access.CONFIRM:
            return self.approval_needed(pending)
        change = self.changes.consume(change_id, "ansible.apply", playbook, needs_approval=access is Access.CONFIRM,
                                      content_hash=self._ansible_hash(playbook, limit, tags))
        command = self._playbook_command(playbook, limit, tags, check=False)
        job = self.start_job("ansible.apply", f"ansible apply {playbook} {limit}", "local", command, cwd=directory,
                             env=self._ansible_env(), meta={"playbook": playbook, "limit": limit, "change": change.id})
        return self.wait(job, wait_s)

    def _done_ansible(self, job: Job, rc: int, text: str) -> dict[str, Any]:
        meta = self.artifacts.save(job.kind, job.title, text)
        summary = parsers.ansible_run(text, max_items=self.max_items)
        out: dict[str, Any] = {"playbook": job.meta["playbook"], "limit": job.meta.get("limit"),
                               "artifact": meta.id, **summary}
        if job.kind == "ansible.apply":
            return {**out, "change": job.meta.get("change")}
        if summary["green"] and summary["changed"]:
            limit, tags = job.meta.get("limit"), job.meta.get("tags")
            line = f"ansible-playbook {job.meta['playbook']} --limit {limit or 'ALL'}: {summary['changed']} change(s)"
            change = self.changes.create("ansible.apply", job.meta["playbook"], line, job.meta["hash"],
                                         args={"limit": limit, "tags": tags},
                                         details={"changed_tasks": summary["changed_tasks"]})
            out["change"] = change.id
            out["next"] = f"ansible action=apply change_id={change.id} (after a human approves it)"
        return out

    # ----------------------------------------------------------------------------------------- drift
    def drift_check(self, wait_s: int | None = None) -> dict[str, Any]:
        """Code vs live infrastructure: tofu plan per stack, playbooks in --check, router export. Read-only."""
        self.require("drift.check")
        children: list[str] = []
        stacks = self.config.drift.tofu_stacks or list(self.config.tofu)
        for stack in stacks:
            children.append(self.tofu_plan(stack, wait_s=0, sync=False)["job"])
        if self.config.drift.playbooks and self.config.ansible is not None:
            _, directory = self._ansible()
            # one retry when a playbook reports ONLY unreachable hosts (ssh flake), as the runbook prescribes
            steps = []
            for playbook in self.config.drift.playbooks:
                command = self._playbook_command(playbook, None, None, check=True)
                steps.append(f"echo '@@PLAYBOOK {playbook}@@'; out=$({command} 2>&1); "
                             "if printf '%s' \"$out\" | grep -Eq 'unreachable=[1-9]' && "
                             "! printf '%s' \"$out\" | grep -Eq '(changed|failed)=[1-9]'; then sleep 5; "
                             f"out=$({command} 2>&1); fi; printf '%s\\n' \"$out\"")
            job = self.start_job("ansible.multi", "drift: ansible --check", "local", "; ".join(steps), cwd=directory,
                                 env=self._ansible_env(), meta={"playbooks": self.config.drift.playbooks})
            children.append(job.id)
        network: dict[str, Any] | None = None
        if self.config.drift.network and self.config.network is not None and self.config.network.tracked_export:
            try:
                network = self.network_drift()  # type: ignore[attr-defined]
            except OpsError as exc:
                network = {"error": str(exc)}
        group = self.jobs.new("drift", "drift check", "group", self.config.remote_job_dir, {"network": network},
                              children)
        return self.wait(group, wait_s)

    def _done_ansible_multi(self, job: Job, rc: int, text: str) -> dict[str, Any]:
        meta = self.artifacts.save("ansible.multi", job.title, text)
        playbooks: dict[str, Any] = {}
        for name, body in parsers.split_marked(text, "PLAYBOOK").items():
            summary = parsers.ansible_run(body, max_items=8)
            clean = summary["green"] and not summary["changed"]
            playbooks[name] = "ok" if clean else {key: summary[key] for key in (
                "changed", "failed", "unreachable", "recap", "changed_tasks", "failures", "error", "hint")
                if summary.get(key)}
        return {"artifact": meta.id, "playbooks": playbooks}

    def _done_drift(self, job: Job, rc: int, text: str) -> dict[str, Any]:
        views: dict[str, dict[str, Any]] = json.loads(text)
        out: dict[str, Any] = {}
        drift = False
        for view in views.values():
            if "stack" in view:
                keep = ("changes", "failed", "add", "change", "destroy", "replace", "resources", "errors",
                        "state_lock", "artifact")
                out.setdefault("tofu", {})[view["stack"]] = (
                    "ok" if view.get("changes") is False else {key: view[key] for key in keep if key in view})
                drift |= view.get("changes") is not False
            elif "playbooks" in view:
                out["ansible"] = view["playbooks"]
                out["ansible_artifact"] = view["artifact"]
                drift |= any(state != "ok" for state in view["playbooks"].values())
        network = job.meta.get("network")
        if network is not None:
            out["network"] = "ok" if network.get("drift") is False else network
            drift |= network.get("drift") is not False
        return {"drift": drift, **out, "rc": 1 if drift else 0}
