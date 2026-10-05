"""Pure parsers: raw tool output -> the few facts worth spending tokens on."""

from __future__ import annotations

import re
from typing import Any

from .util import clip

# ---------------------------------------------------------------------------------------------- tofu
_LOCK_ID = re.compile(r"ID:\s+([0-9a-fA-F-]{8,64})")
_PLAN_LINE = re.compile(r"Plan: (\d+) to add, (\d+) to change, (\d+) to destroy")
_APPLY_LINE = re.compile(r"Apply complete! Resources: (\d+) added, (\d+) changed, (\d+) destroyed")
_ERROR_BLOCK = re.compile(r"^(?:│ )?Error: (.+)$", re.MULTILINE)


def _changed_keys(before: Any, after: Any, unknown: Any) -> list[str]:
    keys: set[str] = set()
    if isinstance(before, dict) and isinstance(after, dict):
        keys = {key for key in before.keys() | after.keys() if before.get(key) != after.get(key)}
    if isinstance(unknown, dict):
        keys |= {key for key, value in unknown.items() if value}
    return sorted(keys)


def tofu_plan_json(document: dict[str, Any], *, max_items: int = 20) -> dict[str, Any]:
    """Summary of `tofu show -json <planfile>`. Only addresses, actions and attribute NAMES leave this
    function: the values (which may be sensitive) are never copied."""
    counts = {"add": 0, "change": 0, "destroy": 0, "replace": 0}
    resources: list[dict[str, Any]] = []
    for item in document.get("resource_changes", []):
        change = item.get("change", {})
        actions = list(change.get("actions", []))
        if actions in (["no-op"], ["read"], []):
            continue
        if "create" in actions and "delete" in actions:
            action = "replace"
        elif actions == ["create"]:
            action = "add"
        elif actions == ["delete"]:
            action = "destroy"
        else:
            action = "change"
        counts[action] += 1
        row: dict[str, Any] = {"addr": item.get("address", "?"), "action": action}
        if action in ("change", "replace"):
            row["attrs"] = _changed_keys(change.get("before"), change.get("after"), change.get("after_unknown"))[:12]
            if change.get("replace_paths"):
                row["forces_replace"] = [".".join(str(part) for part in path) for path in change["replace_paths"]][:6]
        resources.append(row)
    priority = {"destroy": 0, "replace": 1, "change": 2, "add": 3}
    resources.sort(key=lambda row: (priority[row["action"]], row["addr"]))
    out: dict[str, Any] = {**counts, "resources": resources[:max_items]}
    if len(resources) > max_items:
        out["more"] = len(resources) - max_items
    return out


def tofu_fingerprint(document: dict[str, Any]) -> list[Any]:
    """What the change hash is computed from: every non no-op address with its actions."""
    return sorted([item.get("address"), item.get("change", {}).get("actions")]
                  for item in document.get("resource_changes", [])
                  if item.get("change", {}).get("actions") not in (["no-op"], ["read"]))


def tofu_text(text: str) -> dict[str, Any]:
    """Facts readable from the human output: errors, a stale state lock, the plan / apply line."""
    out: dict[str, Any] = {}
    if match := _PLAN_LINE.search(text):
        out["plan_line"] = {"add": int(match[1]), "change": int(match[2]), "destroy": int(match[3])}
    if match := _APPLY_LINE.search(text):
        out["applied"] = {"added": int(match[1]), "changed": int(match[2]), "destroyed": int(match[3])}
    errors = [clip(message.strip(), 240) for message in _ERROR_BLOCK.findall(text)]
    if errors:
        out["errors"] = errors[:5]
    if "Error acquiring the state lock" in text:
        lock = _LOCK_ID.search(text)
        out["state_lock"] = {"id": lock[1] if lock else None,
                             "hint": "stale lock left by an interrupted apply: tofu action=unlock lock_id=<id>"}
    return out


# ------------------------------------------------------------------------------------------- ansible
_TASK = re.compile(r"^(?:TASK|RUNNING HANDLER) \[(.+?)\] \*+")
_RESULT = re.compile(r"^(changed|fatal|failed|unreachable): \[([^\]]+?)(?: -> [^\]]+)?\]")
_RECAP = re.compile(r"^(\S+)\s+: ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)")


def ansible_run(text: str, *, max_items: int = 20) -> dict[str, Any]:
    task = ""
    changed: dict[str, list[str]] = {}
    failures: list[dict[str, str]] = []
    recap: dict[str, dict[str, int]] = {}
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if match := _TASK.match(line):
            task = match[1]
        elif match := _RESULT.match(line):
            kind, host = match[1], match[2]
            if kind == "changed":
                changed.setdefault(task, []).append(host)
            else:
                detail = " ".join(part.strip() for part in lines[index:index + 4])
                failures.append({"task": task, "host": host, "kind": kind, "msg": clip(detail, 300)})
        elif match := _RECAP.match(line):
            recap[match[1]] = {"ok": int(match[2]), "changed": int(match[3]), "unreachable": int(match[4]),
                               "failed": int(match[5])}
    totals = {key: sum(row[key] for row in recap.values()) for key in ("changed", "unreachable", "failed")}
    out: dict[str, Any] = {
        "hosts": len(recap), **totals,
        "green": bool(recap) and totals["failed"] == 0 and totals["unreachable"] == 0,
        # only hosts that are not a plain "ok"
        "recap": {host: row for host, row in recap.items() if row["changed"] or row["unreachable"] or row["failed"]},
        "changed_tasks": [{"task": name, "hosts": hosts} for name, hosts in list(changed.items())[:max_items]],
    }
    if len(changed) > max_items:
        out["more_changed_tasks"] = len(changed) - max_items
    if failures:
        out["failures"] = failures[:max_items]
    if not recap:
        out["error"] = clip(" ".join(line for line in lines[-6:] if line.strip()), 400) or "no play recap"
    if totals["unreachable"] and not totals["failed"] and not totals["changed"]:
        out["hint"] = ("only `unreachable`: usually an SSH flake or a stale ControlMaster after a jump-node reboot "
                       "(rm -f ~/.ansible/cp/*). Re-run before calling it drift.")
    return out


def split_marked(text: str, marker: str) -> dict[str, str]:
    """`@@MARKER name@@` separated sections -> {name: body}."""
    sections: dict[str, str] = {}
    name: str | None = None
    buffer: list[str] = []
    pattern = re.compile(rf"^@@{re.escape(marker)} (.+?)@@$")
    for line in text.splitlines():
        if match := pattern.match(line):
            if name is not None:
                sections[name] = "\n".join(buffer)
            name, buffer = match[1], []
        else:
            buffer.append(line)
    if name is not None:
        sections[name] = "\n".join(buffer)
    return sections


# ---------------------------------------------------------------------------------------- host status
def host_status(text: str, ignore_units: frozenset[str] = frozenset()) -> dict[str, Any]:
    """Parses the `key=value` lines printed by the fixed status script; adds a `warn` list."""
    raw = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    out: dict[str, Any] = {}
    warn: list[str] = []

    def number(key: str) -> float | None:
        try:
            return float(raw[key])
        except (KeyError, ValueError):
            return None

    if (uptime := number("uptime_s")) is not None:
        out["uptime_d"] = round(uptime / 86_400, 1)
        if uptime < 900:
            warn.append("rebooted <15 min ago")
    load, cpus = number("load1"), number("cpus") or 1
    if load is not None:
        out["load1"] = load
        if load > 2 * cpus:
            warn.append(f"load {load} on {int(cpus)} cpu")
    if (memory := number("mem_used_pct")) is not None:
        out["mem_pct"] = int(memory)
        if memory >= 92:
            warn.append(f"memory {int(memory)}%")
    disks = {mount: int(percent) for mount, _, percent in
             (entry.partition(":") for entry in raw.get("disks", "").split(",") if ":" in entry)
             if percent.isdigit()}
    if disks:
        out["disk_max_pct"] = max(disks.values())
        full = {mount: percent for mount, percent in disks.items() if percent >= 85}
        if full:
            out["disks_over_85"] = full
            warn.append("disk " + ", ".join(f"{mount} {percent}%" for mount, percent in full.items()))
    failed = [unit for unit in raw.get("failed_units", "").split(",") if unit and unit not in ignore_units]
    if failed:
        out["failed_units"] = failed[:10]
        warn.append(f"{len(failed)} failed unit(s)")
    if raw.get("reboot_required") == "1":
        out["reboot_required"] = True
    if warn:
        out["warn"] = warn
    return out


# ------------------------------------------------------------------------------------------------ k8s
def _pod_row(pod: dict[str, Any]) -> dict[str, Any]:
    status = pod.get("status", {})
    containers = status.get("containerStatuses", []) or []
    restarts = sum(int(item.get("restartCount", 0)) for item in containers)
    ready = sum(1 for item in containers if item.get("ready"))
    reason = status.get("phase", "?")
    for item in containers:
        waiting = item.get("state", {}).get("waiting")
        if waiting:
            reason = waiting.get("reason", reason)
            break
    return {"ns": pod["metadata"].get("namespace"), "name": pod["metadata"].get("name"), "status": reason,
            "ready": f"{ready}/{len(containers)}", "restarts": restarts, "node": pod.get("spec", {}).get("nodeName")}


def k8s_pods_problems(document: dict[str, Any], restart_threshold: int) -> tuple[int, list[dict[str, Any]]]:
    pods = document.get("items", [])
    rows = []
    for pod in pods:
        row = _pod_row(pod)
        ready, _, total = row["ready"].partition("/")
        healthy = row["status"] == "Succeeded" or (row["status"] == "Running" and ready == total)
        if not healthy or row["restarts"] > restart_threshold:
            rows.append(row)
    rows.sort(key=lambda row: (row["status"] == "Running", -row["restarts"]))
    return len(pods), rows


def k8s_nodes(document: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for node in document.get("items", []):
        conditions = {item["type"]: item["status"] for item in node.get("status", {}).get("conditions", [])}
        row: dict[str, Any] = {"name": node["metadata"]["name"], "ready": conditions.get("Ready") == "True"}
        pressure = [kind for kind, value in conditions.items() if kind != "Ready" and value == "True"]
        if pressure:
            row["conditions"] = pressure
        if node.get("spec", {}).get("unschedulable"):
            row["cordoned"] = True
        rows.append(row)
    return rows


def argo_apps(document: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    apps = document.get("items", [])
    bad = []
    for app in apps:
        status = app.get("status", {})
        sync, health = status.get("sync", {}).get("status", "?"), status.get("health", {}).get("status", "?")
        if sync != "Synced" or health != "Healthy":
            row = {"app": app["metadata"]["name"], "sync": sync, "health": health}
            message = status.get("operationState", {}).get("message")
            if message:
                row["msg"] = clip(message, 200)
            bad.append(row)
    return len(apps), bad


def k8s_rows(kind: str, document: dict[str, Any]) -> list[dict[str, Any]]:
    """One compact row per object, fields chosen per kind."""
    rows: list[dict[str, Any]] = []
    for item in document.get("items", [document] if "metadata" in document else []):
        meta, spec, status = item.get("metadata", {}), item.get("spec", {}), item.get("status", {})
        row: dict[str, Any] = {"name": meta.get("name")}
        if meta.get("namespace"):
            row["ns"] = meta["namespace"]
        if kind in ("pods", "pod"):
            row = _pod_row(item)
        elif kind in ("deployments", "statefulsets", "daemonsets"):
            want = spec.get("replicas", status.get("desiredNumberScheduled", 0))
            row["ready"] = f"{status.get('readyReplicas', status.get('numberReady', 0))}/{want}"
            images = [c.get("image", "") for c in spec.get("template", {}).get("spec", {}).get("containers", [])]
            row["images"] = [image.rsplit("/", 1)[-1] for image in images]
        elif kind == "nodes":
            row = k8s_nodes({"items": [item]})[0]
            row["version"] = status.get("nodeInfo", {}).get("kubeletVersion")
        elif kind == "services":
            row["type"] = spec.get("type")
            row["ports"] = [f"{port.get('port')}/{port.get('protocol', 'TCP')}" for port in spec.get("ports", [])]
        elif kind == "ingresses":
            row["hosts"] = [rule.get("host") for rule in spec.get("rules", [])]
        elif kind in ("jobs", "cronjobs"):
            row["ok"], row["failed"] = status.get("succeeded", 0), status.get("failed", 0)
            if "schedule" in spec:
                row["schedule"], row["last"] = spec["schedule"], status.get("lastScheduleTime")
        elif kind in ("pvc", "persistentvolumeclaims"):
            row["phase"] = status.get("phase")
            row["size"] = status.get("capacity", {}).get("storage")
        elif kind.startswith("applications"):
            row["sync"] = status.get("sync", {}).get("status")
            row["health"] = status.get("health", {}).get("status")
            row["rev"] = str(status.get("sync", {}).get("revision", ""))[:8]
        elif kind.startswith("clusters"):  # CloudNativePG
            row["instances"] = f"{status.get('readyInstances', 0)}/{spec.get('instances', '?')}"
            row["phase"], row["primary"] = status.get("phase"), status.get("currentPrimary")
        rows.append(row)
    return rows


def k8s_events(document: dict[str, Any], *, max_items: int = 20) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for event in document.get("items", []):
        if event.get("type") == "Normal":
            continue
        involved = event.get("involvedObject", {})
        target = f"{involved.get('kind', '?')}/{involved.get('name', '?')}"
        key = (involved.get("namespace", ""), target, event.get("reason", ""))
        stamp = event.get("lastTimestamp") or event.get("eventTime") or ""
        row = merged.setdefault(key, {"ns": key[0], "obj": target, "reason": key[2], "n": 0, "last": "",
                                      "msg": clip(event.get("message", ""), 200)})
        row["n"] += int(event.get("count") or 1)
        row["last"] = max(row["last"], stamp)
    return sorted(merged.values(), key=lambda row: row["last"], reverse=True)[:max_items]


# ------------------------------------------------------------------------------------------- mikrotik
_MT_HEADER = re.compile(r"^# \d{4}-\d{2}-\d{2} .*by RouterOS")


def mikrotik_normalise(text: str) -> list[str]:
    """Drops what changes without anyone changing the router: CRs, the timestamp header, transient
    `# Warning:` lines (netwatch startup delay after a reboot), the software id and line wrapping."""
    lines: list[str] = []
    # RouterOS wraps long commands with a trailing backslash, and re-wraps them when a value changes length:
    # compare logical lines, so one changed comment is one changed line
    joined = re.sub(r"\\\n[ \t]*", "", text.replace("\r", ""))
    for line in joined.splitlines():
        if _MT_HEADER.match(line) or line.startswith("# Warning:"):
            continue
        lines.append("# software id = <redacted>" if line.startswith("# software id =") else line)
    while lines and not lines[-1].strip():
        lines.pop()
    return lines
