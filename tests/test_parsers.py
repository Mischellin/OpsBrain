from opsbrain import parsers
from opsbrain.util import compress_log, hoist_common

PLAN = {"resource_changes": [
    {"address": "vm.a", "change": {"actions": ["no-op"]}},
    {"address": "vm.b", "change": {"actions": ["update"], "before": {"cpu": 2, "token": "SECRET-BEFORE"},
                                   "after": {"cpu": 4, "token": "SECRET-BEFORE"}, "after_unknown": {}}},
    {"address": "vm.c", "change": {"actions": ["delete", "create"], "before": {"disk": 1}, "after": {"disk": 2},
                                   "replace_paths": [["disk"]]}},
    {"address": "vm.d", "change": {"actions": ["create"], "after": {"password": "SECRET-AFTER"}}},
    {"address": "vm.e", "change": {"actions": ["delete"]}}]}


def test_tofu_plan_summary_never_carries_values() -> None:
    summary = parsers.tofu_plan_json(PLAN)
    assert (summary["add"], summary["change"], summary["destroy"], summary["replace"]) == (1, 1, 1, 1)
    assert [row["addr"] for row in summary["resources"]] == ["vm.e", "vm.c", "vm.b", "vm.d"]  # dangerous first
    assert summary["resources"][2]["attrs"] == ["cpu"]
    assert summary["resources"][1]["forces_replace"] == ["disk"]
    assert "SECRET" not in str(summary)


def test_tofu_text_lock_and_errors() -> None:
    text = ("│ Error: Error acquiring the state lock\n│ Lock Info:\n"
            "│   ID:        9db590f1-b6fe-c5f2-2678-8804f089deba\n")
    facts = parsers.tofu_text(text)
    assert facts["state_lock"]["id"] == "9db590f1-b6fe-c5f2-2678-8804f089deba"
    assert parsers.tofu_text("Apply complete! Resources: 1 added, 2 changed, 0 destroyed.")["applied"] == {
        "added": 1, "changed": 2, "destroyed": 0}


ANSIBLE = """
PLAY [all] *****
TASK [common : install packages] ************
ok: [pve]
changed: [ops]
TASK [common : sshd config] ************
changed: [ops]
changed: [pve]
fatal: [web]: FAILED! => changed=false
  msg: No package matching 'foo' found
PLAY RECAP *********************************
ops                        : ok=10   changed=2    unreachable=0    failed=0    skipped=1
pve                        : ok=11   changed=1    unreachable=0    failed=0    skipped=1
web                        : ok=3    changed=0    unreachable=0    failed=1    skipped=0
quiet                      : ok=12   changed=0    unreachable=0    failed=0    skipped=0
"""


def test_ansible_summary() -> None:
    summary = parsers.ansible_run(ANSIBLE)
    assert summary["hosts"] == 4 and summary["changed"] == 3 and summary["failed"] == 1 and not summary["green"]
    assert "quiet" not in summary["recap"]  # plain-ok hosts cost nothing
    assert summary["changed_tasks"][1] == {"task": "common : sshd config", "hosts": ["ops", "pve"]}
    assert "No package matching" in summary["failures"][0]["msg"]


def test_ansible_only_unreachable_is_flagged_as_probable_flake() -> None:
    summary = parsers.ansible_run("PLAY RECAP ***\nops : ok=0 changed=0 unreachable=1 failed=0\n")
    assert "hint" in summary and not summary["green"]
    assert "error" in parsers.ansible_run("ERROR! the playbook could not be found")


def test_host_status_warns_only_on_anomalies() -> None:
    healthy = parsers.host_status("uptime_s=864000\nload1=0.2\ncpus=4\nmem_used_pct=40\ndisks=/:30,/var:50,\n"
                                  "failed_units=\n")
    assert "warn" not in healthy and healthy["disk_max_pct"] == 50
    sick = parsers.host_status("uptime_s=100\nload1=20\ncpus=4\nmem_used_pct=95\ndisks=/:91,\nfailed_units=a.service,\n"
                               "reboot_required=1\n")
    assert len(sick["warn"]) == 5 and sick["disks_over_85"] == {"/": 91} and sick["reboot_required"]


def test_mikrotik_normalise_drops_transient_lines() -> None:
    text = "# 2026-09-01 10:00:00 by RouterOS 7.15\r\n# software id = ABCD\r\n# Warning: netwatch\r\n/ip address\r\n"
    assert parsers.mikrotik_normalise(text) == ["# software id = <redacted>", "/ip address"]


def test_k8s_problem_pods_and_events() -> None:
    def pod(name: str, phase: str, ready: bool, restarts: int, waiting: str | None = None) -> dict:  # type: ignore[type-arg]
        state = {"waiting": {"reason": waiting}} if waiting else {"running": {}}
        return {"metadata": {"name": name, "namespace": "app"}, "spec": {"nodeName": "w1"},
                "status": {"phase": phase, "containerStatuses": [{"ready": ready, "restartCount": restarts,
                                                                  "state": state}]}}
    total, rows = parsers.k8s_pods_problems({"items": [pod("ok", "Running", True, 0), pod("flappy", "Running", True, 9),
                                                       pod("crash", "Running", False, 3, "CrashLoopBackOff"),
                                                       pod("job", "Succeeded", False, 0)]}, 5)
    assert total == 4 and [row["name"] for row in rows] == ["crash", "flappy"]
    assert rows[0]["status"] == "CrashLoopBackOff"
    events = parsers.k8s_events({"items": [
        {"type": "Normal", "reason": "Pulled", "involvedObject": {"kind": "Pod", "name": "a"}},
        {"type": "Warning", "reason": "BackOff", "count": 3, "lastTimestamp": "2026-01-01T00:00:00Z", "message": "x",
         "involvedObject": {"kind": "Pod", "name": "a", "namespace": "app"}},
        {"type": "Warning", "reason": "BackOff", "count": 2, "lastTimestamp": "2026-01-01T00:05:00Z", "message": "x",
         "involvedObject": {"kind": "Pod", "name": "a", "namespace": "app"}}]})
    assert events == [{"ns": "app", "obj": "Pod/a", "reason": "BackOff", "n": 5, "last": "2026-01-01T00:05:00Z",
                       "msg": "x"}]


def test_log_compression_and_label_hoisting() -> None:
    lines = [f"2026-01-01T00:00:{second:02d}Z connection to 10.0.0.{second} failed after {second}ms"
             for second in range(50)] + ["2026-01-01T00:01:00Z started"]
    summary = compress_log(lines)
    assert summary["lines"] == 51 and summary["patterns"][0]["n"] == 50 and len(summary["tail"]) == 8
    common, rows = hoist_common([{"job": "node", "instance": "a"}, {"job": "node", "instance": "b"}])
    assert common == {"job": "node"} and rows == [{"instance": "a"}, {"instance": "b"}]
