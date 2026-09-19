from __future__ import annotations

import json

import pytest

from opsbrain.executor import Result
from opsbrain.operators import JSON_MARK
from opsbrain.util import OpsError

PLAN_JSON = json.dumps({"resource_changes": [
    {"address": "proxmox_vm.web", "change": {"actions": ["update"], "before": {"cores": 2, "pw": "TOPSECRETVALUE"},
                                             "after": {"cores": 4, "pw": "TOPSECRETVALUE"}}}]})
DESTROY_JSON = json.dumps({"resource_changes": [{"address": "proxmox_vm.db", "change": {"actions": ["delete"]}}]})
CHECK_CHANGED = ("TASK [common : motd] ***\nchanged: [ops]\nPLAY RECAP ***\n"
                 "ops : ok=5 changed=1 unreachable=0 failed=0 skipped=0\n")
CLEAN = "PLAY RECAP ***\nops : ok=5 changed=0 unreachable=0 failed=0 skipped=0\n"


def approve(ops, change_id: str, **kwargs) -> None:  # type: ignore[no-untyped-def]
    ops.changes.approve(change_id, **kwargs)  # what `opsbrain approve` does after the human typed "yes"


# ------------------------------------------------------------------------------------------------ tofu
def test_tofu_plan_without_changes(ops, fake) -> None:  # type: ignore[no-untyped-def]
    fake.on(r"tofu plan", "No changes. Your infrastructure matches the configuration.")
    result = ops.tofu_plan()
    assert result["state"] == "done" and result["changes"] is False and "change" not in result
    script = next(script for where, script in fake.calls if where == "ops-job")
    assert "cd /root/tofu && set -a && . /root/.tofu.env" in script and "-detailed-exitcode" in script


def test_tofu_apply_requires_human_approval_and_applies_the_saved_plan(ops, fake) -> None:  # type: ignore[no-untyped-def]
    fake.on(r"tofu plan", f"Plan: 0 to add, 1 to change, 0 to destroy.\n{JSON_MARK}\n{PLAN_JSON}\n", rc=2)
    plan = ops.tofu_plan()
    assert plan["change"].startswith("c-") and plan["resources"] == [
        {"addr": "proxmox_vm.web", "action": "change", "attrs": ["cores"]}]
    assert "TOPSECRETVALUE" not in json.dumps(plan)
    # the machine-readable plan (which may hold sensitive values) is never stored
    stored = ops.artifacts.read(plan["artifact"])["text"]
    assert "TOPSECRETVALUE" not in stored and "Plan: 0 to add" in stored

    refused = ops.tofu_apply(plan["change"])
    assert "opsbrain approve" in refused["next"]
    assert not any("tofu apply" in script for _, script in fake.calls)

    approve(ops, plan["change"])
    fake.on(r"tofu apply", "Apply complete! Resources: 0 added, 1 changed, 0 destroyed.\n@@OPSBRAIN-POSTPLAN 0@@\n")
    applied = ops.tofu_apply(plan["change"])
    assert applied["ok"] and applied["applied"]["changed"] == 1 and applied["post_plan_clean"] is True
    script = next(script for _, script in fake.calls if "tofu apply" in script)
    assert ".opsbrain/j-" in script and ".tfplan" in script
    with pytest.raises(OpsError, match="single use"):
        ops.tofu_apply(plan["change"])


def test_destructive_plan_is_flagged_and_needs_allow_destroy(ops, fake) -> None:  # type: ignore[no-untyped-def]
    fake.on(r"tofu plan", f"Plan: 0 to add, 0 to change, 1 to destroy.\n{JSON_MARK}\n{DESTROY_JSON}\n", rc=2)
    plan = ops.tofu_plan()
    assert plan["dangerous"] is True and plan["destroy"] == 1
    assert "--allow-destroy" in ops.tofu_apply(plan["change"])["next"]
    with pytest.raises(OpsError, match="--allow-destroy"):
        approve(ops, plan["change"])


def test_tofu_plan_error_reports_stale_lock(ops, fake) -> None:  # type: ignore[no-untyped-def]
    fake.on(r"tofu plan", "│ Error: Error acquiring the state lock\n│   ID:        9db590f1-b6fe-c5f2\n", rc=1)
    result = ops.tofu_plan()
    assert result["failed"] and result["state_lock"]["id"] == "9db590f1-b6fe-c5f2"
    assert "opsbrain approve" in ops.tofu_unlock("9db590f1-b6fe-c5f2")["next"]
    with pytest.raises(OpsError, match="invalid lock id"):
        ops.tofu_unlock("x; rm -rf /")


def test_tofu_sync_reports_remote_only_files(ops, fake) -> None:  # type: ignore[no-untyped-def]
    fake.on(r"base64 -d \| tar", "main.tf\nold.tf\n@@SYNCED@@\n")
    fake.on(r"tofu plan", "No changes.")
    assert ops.tofu_plan(sync=True)["synced"] == {"files": 1, "remote_only": ["old.tf"]}


# --------------------------------------------------------------------------------------------- ansible
def test_ansible_check_then_apply(ops, fake, repo) -> None:  # type: ignore[no-untyped-def]
    fake.on(r"--check", CHECK_CHANGED)
    check = ops.ansible_check("common", limit="ops")
    assert check["changed"] == 1 and check["green"] and check["change"].startswith("c-")
    assert "opsbrain approve" in ops.ansible_apply(check["change"])["next"]
    approve(ops, check["change"])
    fake.on(r"common\.yml --diff --limit ops$", CHECK_CHANGED)
    applied = ops.ansible_apply(check["change"])
    assert applied["state"] == "done" and applied["change"] == check["change"]
    command = fake.calls[-1][1]
    assert "--check" not in command and "--limit ops" in command


def test_ansible_apply_is_void_once_the_code_changed(ops, fake, repo) -> None:  # type: ignore[no-untyped-def]
    fake.on(r"--check", CHECK_CHANGED)
    check = ops.ansible_check("common", limit="ops")
    approve(ops, check["change"])
    (repo / "ansible" / "playbooks" / "common.yml").write_text("- hosts: all\n  become: true\n")
    with pytest.raises(OpsError, match="changed since"):
        ops.ansible_apply(check["change"])


def test_ansible_rejects_unknown_playbook_injection_and_unlimited_apply(ops, fake) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(OpsError, match="unknown playbook"):
        ops.ansible_check("../../etc/passwd")
    with pytest.raises(OpsError, match="invalid limit"):
        ops.ansible_check("common", limit="ops; rm -rf /")
    fake.on(r"--check", CHECK_CHANGED)
    check = ops.ansible_check("common")
    with pytest.raises(OpsError, match="needs a limit"):
        ops.ansible_apply(check["change"])


# ----------------------------------------------------------------------------------------------- drift
def test_drift_aggregates_all_layers(ops, fake) -> None:  # type: ignore[no-untyped-def]
    fake.on(r"tofu plan", "No changes.")
    fake.on(r"@@PLAYBOOK common@@", f"@@PLAYBOOK common@@\n{CLEAN}")
    fake.on(r"/export hide-sensitive", "# 2026-09-09 09:09:09 by RouterOS 7.16\r\n# Warning: netwatch delay\r\n"
                                       "/ip address\r\nadd address=10.0.0.1/24 interface=bridge\r\n")
    result = ops.drift_check()
    assert result["state"] == "done" and result["drift"] is False and result["rc"] == 0
    assert result["tofu"] == {"proxmox": "ok"} and result["ansible"] == {"common": "ok"} and result["network"] == "ok"

    fake.on(r"/export hide-sensitive", "/ip address\nadd address=10.0.0.2/24 interface=bridge\n")
    drifted = ops.drift_check()
    assert drifted["drift"] is True and drifted["network"]["changed_lines"] == 2


# ----------------------------------------------------------------------------------- hosts, k8s, docs
def test_hosts_status_and_restart_policy(ops, fake) -> None:  # type: ignore[no-untyped-def]
    fake.on(r"uptime_s", "uptime_s=864000\nload1=0.1\ncpus=4\nmem_used_pct=30\ndisks=/:20,\nfailed_units=\n")
    status = ops.hosts_status()
    assert status["total"] == 2 and "warn" not in status["hosts"]["pve"]  # the router is not a linux host
    with pytest.raises(OpsError, match="not listed"):
        ops.hosts_restart("ops", "sshd")
    assert "opsbrain approve" in ops.hosts_restart("ops", "caddy")["next"]
    with pytest.raises(OpsError, match="unknown host"):
        ops.hosts_ping(["nope"])


def test_ssh_goes_through_the_jump_host(ops) -> None:  # type: ignore[no-untyped-def]
    from opsbrain.executor import Executor
    argv = Executor(ops.config).ssh_argv("ops", "true")
    assert argv[-2:] == ["root@10.0.0.42", "true"] and argv[argv.index("-J") + 1] == "root@10.0.0.11:22"


def test_k8s_never_reads_secrets_and_allowed_refresh_runs_at_once(ops, fake) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(OpsError, match="kind must be one of"):
        ops.k8s_get("secrets")
    with pytest.raises(OpsError, match="invalid name"):
        ops.k8s_describe("pods", "--help")
    fake.on(r"get applications", json.dumps({"metadata": {"name": "web"}, "status": {
        "sync": {"status": "Synced", "revision": "abcdef1234"}, "health": {"status": "Healthy"}}}))
    done = ops.k8s_refresh("web")  # policy: k8s.refresh = allow
    assert done["now"] == {"name": "web", "sync": "Synced", "health": "Healthy", "rev": "abcdef12"}
    assert "opsbrain approve" in ops.k8s_restart("deployments", "web", "prod")["next"]


def test_docs_are_searchable_but_secrets_are_not(ops) -> None:  # type: ignore[no-untyped-def]
    assert ops.docs_search("tofu guests")["items"][0]["path"] == "docs/STATUS.md"
    status = ops.docs_status()
    assert "wireguard rotated" in status["last_entry"] and "hunter2secret" not in status["last_entry"]
    assert "old" not in status["last_entry"] and status["status_sections"] == ["2: Guests", "4: Hosts"]
    for path in ("docs/vault.md", "../outside.md", "ansible/playbooks/common.yml"):
        with pytest.raises(OpsError):
            ops.docs_read(path)


def test_observe_is_compact(ops, http) -> None:  # type: ignore[no-untyped-def]
    http.responses["/api/v1/query"] = {"status": "success", "data": {"result": [
        {"metric": {"__name__": "up", "job": "node", "instance": "a"}, "value": [0, "1"]},
        {"metric": {"__name__": "up", "job": "node", "instance": "b"}, "value": [0, "0"]}]}}
    result = ops.observe_query("up")
    assert result["common"] == {"job": "node"} and result["items"] == [{"instance": "a", "v": 1.0},
                                                                        {"instance": "b", "v": 0.0}]
    http.codes["https://example.com"] = 502
    assert ops.observe_http()["failing"] == ["site"]


def test_call_wrapper_audits_truncates_and_never_raises(ops) -> None:  # type: ignore[no-untyped-def]
    assert json.loads(ops.call("x", {}, lambda: (_ for _ in ()).throw(OpsError("nope")))) == {"error": "nope"}
    assert "internal: ZeroDivisionError" in ops.call("x", {}, lambda: 1 / 0)
    big = json.loads(ops.call("x", {"token": "glpat-abcdefghijklmnopqrstuv"}, lambda: {"rows": ["y" * 100] * 200}))
    assert big["truncated"] and big["artifact"].startswith("a-")
    stats = ops.audit.stats()
    assert stats["calls"] == 3 and stats["tokens_saved_estimate"] > 0
    assert "glpat-" not in ops.audit.path.read_text()


def test_running_job_returns_a_handle(ops, fake) -> None:  # type: ignore[no-untyped-def]
    fake.on(r"tofu plan", "No changes.")
    fake.poll_ssh = lambda *args, **kwargs: (None, "Refreshing state...\n")  # type: ignore[method-assign]
    view = ops.tofu_plan(wait_s=0)
    assert view["state"] == "running" and view["next"] == f"job action=status id={view['job']}"
    assert ops.overview()["running_jobs"][0]["id"] == view["job"]
    assert isinstance(Result(0, "").ok, bool)
