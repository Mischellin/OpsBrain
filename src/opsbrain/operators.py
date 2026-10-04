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
PLAN_SHA = re.compile(r"^@@OPSBRAIN-PLAN-SHA ([0-9a-f]{64})@@$", re.MULTILINE)
PLANMISMATCH = re.compile(r"^@@OPSBRAIN-PLAN-MISMATCH ([0-9a-f]*)@@$", re.MULTILINE)
#: A saved plan is applied by path, so the path is constrained to the one shape `tofu_plan` ever writes.
PLAN_PATH = re.compile(r"^\.opsbrain/j-[0-9a-f]{8}\.tfplan$")
#: The exit code `_plan_apply_script` reserves for "the plan is not the one that was approved".
PLAN_MISMATCH_RC = 78
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
        scratch = f".opsbrain/{job.id}.partial"
        binary = shlex.quote(config.binary)
        # `tofu plan` writes to a scratch name, and the plan the record is built from is a *copy* of it,
        # made read-only in the same breath. Hashing the file `tofu` wrote and then showing that same file
        # were two opens of one mutable path: replacing it between them gave the record the checksum of
        # plan A and the resource summary of plan B - and restoring A before the apply would then pass the
        # checksum guard with bytes the approver never saw. One held artifact is written, hashed, shown and
        # later applied, so every one of those four steps reads the same bytes.
        script = (f"{self._tofu_prefix(config)}mkdir -p .opsbrain && chmod 700 .opsbrain && "
                  # Both extensions: an interrupted plan leaves a `.partial` behind, and a saved plan may
                  # hold the stack's variable values, so neither may sit on the runner indefinitely.
                  "find .opsbrain \( -name '*.tfplan' -o -name '*.partial' \) -mmin +1440 -delete; "
                  f"{binary} plan -input=false -no-color -lock-timeout=60s -detailed-exitcode -out={scratch}; rc=$?; "
                  f"if [ $rc -eq 2 ]; then cp -- {scratch} {plan_file} && chmod 400 {plan_file}; rm -f {scratch}; "
                  f"echo \"@@OPSBRAIN-PLAN-SHA $(sha256sum {plan_file} | cut -d' ' -f1)@@\"; "
                  f"echo {JSON_MARK}; {binary} show -json {plan_file}; "
                  f"else rm -f {scratch} {plan_file}; fi; exit $rc")
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
        # The digest of the saved plan file itself, taken on the runner as it was written. The change
        # record is worthless without it: `tofu_apply` re-hashes the file and refuses to apply anything
        # whose bytes are not the ones this approval was granted for. A plan that cannot report it is not
        # offered as approvable, because "no digest" would otherwise mean "no check".
        sha = PLAN_SHA.search(human)
        if not sha:
            # The plan is unusable - no checksum means nothing to check it against later - and a saved plan
            # can carry the stack's variable values. Leaving it for the age-based sweep meant it stayed
            # until some later `tofu plan` happened to be more than a day old, or forever if none did.
            self._discard_saved_plan(stack, job.meta["plan_file"])
            return {**out, "changes": True, **summary, "dangerous": dangerous,
                    "warning": "plan digest unreadable: the saved plan was removed and no change was "
                               "created, plan again"}
        change = self.changes.create("tofu.apply", stack, line, digest(parsers.tofu_fingerprint(document)),
                                     dangerous=dangerous, args={"plan_file": job.meta["plan_file"]},
                                     details={"resources": summary["resources"], "plan_sha256": sha.group(1)})
        return {**out, "changes": True, **summary, "dangerous": dangerous, "change": change.id,
                "next": f"tofu action=apply change_id={change.id} (after a human approves it)"}

    def _discard_saved_plan(self, stack: str, plan_file: str) -> None:
        """Remove a saved plan that will never be applied, so it does not outlive its usefulness."""
        try:
            _, config = self._stack(stack)
        except OpsError:
            return  # the stack is gone; whatever it left is no longer ours to reach
        self.exec.run_ssh(config.runner, f"{self._tofu_prefix(config)}command rm -f {shlex.quote(plan_file)}",
                          timeout=30)

    def _plan_apply_script(self, config: Any, plan_file: str, expected_sha: str) -> str:
        """One runner-side script: take an immutable copy of the plan, hash *that*, and apply *that*.

        Three defects, in the order they were found. The digest used to be fetched in one command and the
        apply issued in another, so anything that replaced the plan between them had its plan applied
        under an approval given for the first one. Hashing and applying in one shell closed the shell
        boundary but not the pathname: `sha256sum` and `tofu apply` each open the same mutable path, so a
        replacement between the two still ran unchecked bytes. The script therefore copies the plan to a
        fresh name, drops write permission, and hashes and applies *the copy* - the path that gets applied
        is the path that was checked, and its name is generated inside this shell rather than chosen by
        whoever is trying to substitute it.

        The `cd` into the stack directory comes first and applies to the hash as well as the apply. A
        detached SSH job starts in the remote user's login directory, and the saved plan path is relative
        to the stack, so hashing before the `cd` reported every valid plan as missing.

        The hash covers the `.tfplan` file rather than `tofu show -json` output: it is the artifact that is
        actually applied, it needs no JSON parser on the runner, and it removes the "first line starting
        with `{`" tolerance a warning above the document used to require.

        What this does not stop: a process running as the same user on the runner that can list the
        directory, or that wins a race against `mktemp`. Against a same-uid adversary no script-level
        arrangement helps - it can simply read the copy - so the runner's own isolation is the real
        boundary. Stated here so the limit is not mistaken for a guarantee, and so nobody reads the private
        directory as proof against an attacker it does not stop.
        """
        binary = shlex.quote(config.binary)
        prefix = self._tofu_prefix(config)
        quoted = shlex.quote(plan_file)
        return (
            # A private directory, not a private *name* in a shared one. `chmod 400` only changes the
            # inode's mode: a same-uid process could still discover the path in the user-writable
            # `.opsbrain`, unlink or rename over it after the checksum, and have `tofu apply` run bytes
            # nobody verified. A `mktemp -d` directory is 0700 with a name this shell generated, so
            # finding it takes guessing rather than listing. Both files are removed on every exit path
            # including the refusal, so a saved plan cannot outlive the run either.
            f"held_dir=$(mktemp -d .opsbrain/apply.XXXXXX) || exit 78; "
            f"held=$held_dir/plan.tfplan; "
            f"held_gone() {{ command rm -rf $held_dir; command rm -f {quoted}; }}; "
            f"{prefix}cp -- {quoted} $held 2>/dev/null && chmod 400 $held; "
            f"actual=$(sha256sum $held 2>/dev/null | cut -d' ' -f1); "
            f'if [ -z "$actual" ] || [ "$actual" != {shlex.quote(expected_sha)} ]; then '
            f'held_gone; echo "@@OPSBRAIN-PLAN-MISMATCH $actual@@"; exit 78; fi; '
            f"{prefix}{binary} apply -input=false -no-color -lock-timeout=60s $held; "
            # The saved plan goes with the copy. Leaving it behind kept potentially sensitive plan
            # contents on the runner until some later `tofu plan` happened to be more than a day old -
            # or forever, if no further plan ever ran.
            f"rc=$?; held_gone; if [ $rc -eq 0 ]; then "
            f"{binary} plan -input=false -no-color -lock-timeout=60s -detailed-exitcode > /dev/null 2>&1; "
            "echo \"@@OPSBRAIN-POSTPLAN $?@@\"; fi; exit $rc")

    def engine_authorised(self, change: Any) -> bool:
        """Whether the decision engine has already authorised this change.

        The operator entry points used to answer "ask a human" the moment they saw a pending change, which
        is exactly the state an engine-approved change is in: issuance attaches an approval and leaves the
        change pending. So the autonomous path returned a human prompt every time and was unreachable in
        practice, however correct the engine was. Returns False when the engine is not deciding, and lets
        the gate raise when it is and the change is not authorised.
        """
        gate = getattr(self.changes, "gate", None)
        return bool(gate is not None and gate(change))

    def tofu_apply(self, change_id: str, wait_s: int | None = None) -> dict[str, Any]:
        pending = self.changes.get(change_id)
        name, config = self._stack(pending.target)
        access = self.require("tofu.apply", name)
        if (pending.state == "pending" and (access is Access.CONFIRM or pending.dangerous)
                and not self.engine_authorised(pending)):
            return self.approval_needed(pending)
        plan_file = str(pending.args.get("plan_file", ""))
        # Validated before the change is spent and before the path reaches a shell command.
        if not PLAN_PATH.fullmatch(plan_file):
            raise OpsError("corrupt change record: it does not name a saved plan")
        expected_sha = str(pending.details.get("plan_sha256", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
            raise OpsError(f"change {change_id} carries no plan digest; plan again")
        # No `content_hash` here on purpose: re-deriving the fingerprint on this side and comparing it to
        # the stored value is exactly the check that had the window. `consume` still burns the change under
        # its lock; the authoritative content check happens on the runner, atomically with the apply.
        change = self.changes.consume(change_id, "tofu.apply", name,
                                      needs_approval=access is Access.CONFIRM)
        # a saved plan file is applied: tofu itself refuses it when the state moved since the plan
        script = self._plan_apply_script(config, plan_file, expected_sha)
        job = self.start_job("tofu.apply", f"tofu apply {name}", config.runner, script,
                             meta={"stack": name, "change": change.id})
        return self.wait(job, wait_s)

    def _done_tofu_apply(self, job: Job, rc: int, text: str) -> dict[str, Any]:
        meta = self.artifacts.save("tofu-apply", job.title, text)
        out: dict[str, Any] = {"stack": job.meta["stack"], "change": job.meta["change"], "artifact": meta.id,
                               "ok": rc == 0, **parsers.tofu_text(text)}
        if rc == PLAN_MISMATCH_RC and (mismatch := PLANMISMATCH.search(text)):
            # Only on the exit code the script reserves for the refusal. A successful apply whose output
            # happens to contain a line matching the marker - a provisioner echoing it, say - would
            # otherwise be reported as "nothing was applied" while the infrastructure had in fact changed.
            return {**out, "ok": False, "plan_changed": True, "found": mismatch.group(1) or "no file",
                    "hint": "the saved plan on the runner is not the one that was approved; plan again"}
        if mismatch := PLANMISMATCH.search(text):
            # The marker arrived with a different exit code, so the apply's own result stands and this is
            # only noise worth reporting as such.
            out["marker_without_refusal"] = mismatch.group(1)
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
        if (pending.state == "pending" and access is Access.CONFIRM
                and not self.engine_authorised(pending)):
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
