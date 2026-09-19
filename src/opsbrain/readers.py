"""Read side: knowledge (docs), hosts, Kubernetes, network (MikroTik) and observability.

The few mutations that live here (service restart, Argo refresh / sync, rollout restart) go through
`Core.gate`, like every other mutation.
"""

from __future__ import annotations

import difflib
import json
import re
import shlex
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from . import parsers
from .changes import Change, digest
from .core import Core
from .redact import redact_text
from .util import OpsError, clip, compress_log, hoist_common

_FORBIDDEN_DOC = re.compile(r"(?i)(vault|secret|\.env|\.vault_pass|\.key$|\.pem$|id_(rsa|ed25519)|rclone\.conf|"
                            r"discovery/out|\.tfstate|\.tfvars)")
_K8S_NAME = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
_K8S_LOG_TARGET = re.compile(r"^((deployment|deploy|statefulset|sts|daemonset|ds|job|pod)/)?[a-z0-9]([a-z0-9.-]{0,251}"
                             r"[a-z0-9])?$")
_SELECTOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./=!, ()-]{0,199}$")
_SINCE = re.compile(r"^[0-9]{1,4} ?(s|sec|m|min|h|hour|hours|d|day|days)( ago)?$|^[0-9T:. -]{8,25}$|"
                    r"^(today|yesterday)$")
_UNIT = re.compile(r"^[A-Za-z0-9@_.:-]{1,120}$")

K8S_KINDS = {
    "pods": "pods", "deployments": "deployments", "statefulsets": "statefulsets", "daemonsets": "daemonsets",
    "services": "services", "ingresses": "ingresses", "jobs": "jobs", "cronjobs": "cronjobs", "nodes": "nodes",
    "pvc": "persistentvolumeclaims", "namespaces": "namespaces", "configmaps": "configmaps",
    "hpa": "horizontalpodautoscalers", "applications": "applications.argoproj.io",
    "clusters": "clusters.postgresql.cnpg.io",
}  # `secrets` is deliberately absent: OpsBrain never reads Kubernetes Secrets

STATUS_SCRIPT = (
    "echo uptime_s=$(cut -d. -f1 /proc/uptime); echo load1=$(cut -d' ' -f1 /proc/loadavg); echo cpus=$(nproc); "
    "awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{if(t)printf \"mem_used_pct=%d\\n\",(t-a)*100/t}' /proc/meminfo; "
    "echo disks=$(df -P -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null | "
    "awk 'NR>1{gsub(\"%\",\"\",$5);printf \"%s:%s,\",$6,$5}'); "
    "echo failed_units=$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{printf \"%s,\",$1}'); "
    "if [ -f /var/run/reboot-required ]; then echo reboot_required=1; fi")


class Readers(Core):
    # ------------------------------------------------------------------------------------------ docs
    def _doc_files(self) -> list[Path]:
        files: dict[Path, None] = {}
        for pattern in self.config.docs.globs:
            for path in sorted(self.repo.glob(pattern)):
                relative = path.relative_to(self.repo).as_posix()
                if path.is_file() and not _FORBIDDEN_DOC.search(relative) and path.stat().st_size < 2_000_000:
                    files[path] = None
        return list(files)

    def _doc_path(self, relative: str) -> Path:
        path = (self.repo / relative).resolve()
        if not path.is_relative_to(self.repo) or _FORBIDDEN_DOC.search(path.relative_to(self.repo).as_posix()):
            raise OpsError(f"not readable: {relative!r}")
        if path not in self._doc_files():
            raise OpsError(f"not a knowledge file (see docs.globs): {relative!r}")
        return path

    def docs_search(self, query: str, limit: int = 8) -> dict[str, Any]:
        self.require("docs.read")
        terms = [term.lower() for term in re.findall(r"[\w./-]{2,}", query)][:8]
        if not terms:
            raise OpsError("empty query")
        hits: list[tuple[int, str, int, str]] = []
        for path in self._doc_files():
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            heading = ""
            for number, line in enumerate(lines, 1):
                if line.startswith("#"):
                    heading = line.lstrip("# ").strip()
                lowered = line.lower()
                score = sum(1 for term in terms if term in lowered)
                if score and score * 2 >= len(terms):
                    bonus = sum(1 for term in terms if term in heading.lower())
                    hits.append((score * 2 + bonus, path.relative_to(self.repo).as_posix(), number, line.strip()))
        hits.sort(key=lambda hit: (-hit[0], hit[1], hit[2]))
        rows = [{"path": path, "line": number, "text": clip(redact_text(text), 220)}
                for _, path, number, text in hits[:max(1, min(limit, 30))]]
        return {"hits": len(hits), "items": rows, "next": "docs action=read path=<path> start=<line>"}

    def docs_read(self, path: str, start: int = 1, lines: int = 60) -> dict[str, Any]:
        self.require("docs.read")
        content = self._doc_path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        start, lines = max(1, start), max(1, min(lines, 200))
        body = redact_text("\n".join(content[start - 1:start - 1 + lines]))
        return {"path": path, "total_lines": len(content), "start": start, "text": body}

    def docs_status(self) -> dict[str, Any]:
        """The current state in a few hundred tokens: last entry of the memory log + headings of the status file."""
        self.require("docs.read")
        out: dict[str, Any] = {}
        if self.config.docs.memory_file:
            text = self._doc_path(self.config.docs.memory_file).read_text(encoding="utf-8", errors="replace")
            entries = re.split(r"(?m)^(?=## )", text)
            out["last_entry"] = clip(redact_text(entries[-1].strip()), 2500)
        if self.config.docs.status_file:
            text = self._doc_path(self.config.docs.status_file).read_text(encoding="utf-8", errors="replace")
            out["status_sections"] = [f"{number}: {line.lstrip('# ').strip()}"
                                      for number, line in enumerate(text.splitlines(), 1) if line.startswith("##")][:40]
            out["status_file"] = self.config.docs.status_file
        return out

    # ----------------------------------------------------------------------------------------- hosts
    def _select_hosts(self, hosts: list[str] | None, tag: str | None, *, kind: str = "linux") -> list[str]:
        if hosts:
            for name in hosts:
                self.exec.host(name)
            return hosts
        names = [name for name, host in self.config.hosts.items()
                 if host.kind == kind and (tag is None or tag in host.tags)]
        if not names:
            raise OpsError("no hosts selected")
        return names

    def _parallel(self, names: list[str], script: str, timeout: float = 40) -> dict[str, Any]:
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda name: self.exec.run_ssh(name, script, timeout=timeout), names))
        return dict(zip(names, results, strict=True))

    def hosts_list(self) -> dict[str, Any]:
        return {"hosts": [{"name": name, "addr": host.address, **({"jump": host.jump} if host.jump else {}),
                           **({"tags": host.tags} if host.tags else {}),
                           **({"services": host.services} if host.services else {})}
                          for name, host in self.config.hosts.items()]}

    def hosts_ping(self, hosts: list[str] | None = None, tag: str | None = None) -> dict[str, Any]:
        self.require("hosts.read")
        names = self._select_hosts(hosts, tag)
        results = self._parallel(names, "true", timeout=25)
        down = {name: clip(result.out.strip().splitlines()[-1] if result.out.strip() else "timeout", 160)
                for name, result in results.items() if not result.ok}
        return {"up": len(names) - len(down), "total": len(names), "down": down}

    def hosts_status(self, hosts: list[str] | None = None, tag: str | None = None) -> dict[str, Any]:
        self.require("hosts.read")
        names = self._select_hosts(hosts, tag)
        results = self._parallel(names, STATUS_SCRIPT)
        ignore = frozenset(self.config.ignore_failed_units)
        rows: dict[str, Any] = {}
        for name, result in results.items():
            rows[name] = (parsers.host_status(result.out, ignore) if result.ok else {"warn": ["unreachable"]})
        attention = {name: row for name, row in rows.items() if row.get("warn")}
        # healthy hosts cost one word each; details only where something is off (or when asked for few hosts)
        if len(names) > 3:
            return {"total": len(names), "healthy": [name for name in names if name not in attention],
                    "attention": attention}
        return {"total": len(names), "hosts": rows}

    def _unit(self, host_name: str, service: str, *, configured_only: bool) -> str:
        host = self.exec.host(host_name)
        if not _UNIT.fullmatch(service):
            raise OpsError(f"invalid unit name: {service!r}")
        if configured_only and service not in host.services:
            raise OpsError(f"{service!r} is not listed in hosts.{host_name}.services")
        return service

    def hosts_services(self, host: str, service: str | None = None) -> dict[str, Any]:
        self.require("hosts.read", host)
        units = [self._unit(host, service, configured_only=False)] if service else self.exec.host(host).services
        if not units:
            raise OpsError(f"no services configured for {host}")
        script = "; ".join(f"echo {shlex.quote(unit)}=$(systemctl is-active {shlex.quote(unit)} 2>&1)"
                           for unit in units)
        result = self.exec.run_ssh(host, script, timeout=30)
        if not result.ok and "=" not in result.out:
            raise OpsError(f"{host}: {clip(result.out.strip(), 200)}")
        states = dict(line.split("=", 1) for line in result.out.splitlines() if "=" in line)
        return {"host": host, "services": states, "not_active": [u for u, s in states.items() if s != "active"]}

    def hosts_logs(self, host: str, service: str, lines: int = 200, since: str | None = None,
                   grep: str | None = None) -> dict[str, Any]:
        self.require("hosts.read", host)
        unit = self._unit(host, service, configured_only=False)
        command = f"journalctl -u {shlex.quote(unit)} -n {max(10, min(lines, 5000))} --no-pager -o short-iso"
        if since:
            if not _SINCE.fullmatch(since):
                raise OpsError(f"invalid since: {since!r} (e.g. '30 min ago', '2026-01-31 10:00')")
            command += f" --since {shlex.quote(since)}"
        if self.exec.host(host).sudo:
            command = "sudo -n " + command
        result = self.exec.run_ssh(host, command, timeout=60)
        if not result.ok:
            raise OpsError(f"{host}: {clip(result.out.strip(), 200)}")
        meta = self.artifacts.save("journal", f"{host} {unit}", result.out)
        selected = redact_text(result.out).splitlines()
        if grep:
            try:
                regex = re.compile(grep[:200], re.IGNORECASE)
            except re.error as exc:
                raise OpsError(f"invalid grep: {exc}") from exc
            selected = [line for line in selected if regex.search(line)]
        return {"host": host, "unit": unit, "artifact": meta.id, **compress_log(selected)}

    def hosts_restart(self, host: str, service: str, change_id: str | None = None) -> dict[str, Any]:
        unit = self._unit(host, service, configured_only=True)
        gate = self.gate("hosts.restart", host, change_id, summary=f"systemctl restart {unit} on {host}",
                         content_hash=digest(["hosts.restart", host, unit]), args={"service": unit})
        if not isinstance(gate, Change):
            return gate
        sudo = "sudo -n " if self.exec.host(host).sudo else ""
        result = self.exec.run_ssh(host, f"{sudo}systemctl restart {shlex.quote(unit)}; sleep 2; "
                                         f"systemctl is-active {shlex.quote(unit)}", timeout=90)
        state = result.out.strip().splitlines()[-1] if result.out.strip() else "unknown"
        return {"host": host, "unit": unit, "state": state, "ok": state == "active", "change": gate.id}

    # ------------------------------------------------------------------------------------------- k8s
    def _kubectl(self, *args: str, timeout: float = 60) -> str:
        k8s = self.config.k8s
        if k8s is None:
            raise OpsError("k8s is not configured")
        argv = [k8s.kubectl, "--request-timeout=30s"]
        if k8s.kubeconfig:
            argv += ["--kubeconfig", str(Path(k8s.kubeconfig).expanduser())]
        if k8s.context:
            argv += ["--context", k8s.context]
        result = self.exec.run_local([*argv, *args], timeout=timeout)
        if not result.ok:
            raise OpsError(f"kubectl: {clip(redact_text(result.out.strip()), 300)}")
        return result.out

    def _kubectl_json(self, *args: str) -> dict[str, Any]:
        text = self._kubectl(*args, "-o", "json")
        try:
            document: dict[str, Any] = json.loads(text[text.index("{"):])
        except ValueError as exc:
            raise OpsError("kubectl returned no JSON") from exc
        return document

    @staticmethod
    def _names(namespace: str | None = None, name: str | None = None) -> None:
        for label, value in (("namespace", namespace), ("name", name)):
            if value is not None and not _K8S_NAME.fullmatch(value):
                raise OpsError(f"invalid {label}: {value!r}")

    def _scope(self, namespace: str | None) -> list[str]:
        return ["-n", namespace] if namespace else ["-A"]

    def k8s_overview(self) -> dict[str, Any]:
        self.require("k8s.read")
        nodes = parsers.k8s_nodes(self._kubectl_json("get", "nodes"))
        total, problems = parsers.k8s_pods_problems(self._kubectl_json("get", "pods", "-A"),
                                                    self.config.k8s.restart_threshold if self.config.k8s else 5)
        out: dict[str, Any] = {"nodes": {"total": len(nodes), "not_ready": [n for n in nodes if not n["ready"]
                                                                            or len(n) > 2]},
                               "pods": {"total": total, "problems": self.capped(problems)}}
        try:
            argo = self.config.k8s.argocd_namespace if self.config.k8s else "argocd"
            apps, bad = parsers.argo_apps(self._kubectl_json("get", K8S_KINDS["applications"], "-n", argo))
            out["argo"] = {"apps": apps, "not_ok": bad[:self.max_items]}
        except OpsError:
            out["argo"] = "unavailable"
        return out

    def k8s_get(self, kind: str, namespace: str | None = None, name: str | None = None,
                selector: str | None = None) -> dict[str, Any]:
        self.require("k8s.read", namespace or "")
        if kind not in K8S_KINDS:
            raise OpsError(f"kind must be one of {sorted(K8S_KINDS)}")
        self._names(namespace, name)
        args = ["get", K8S_KINDS[kind], *([name] if name else [])]
        args += ["-n", namespace] if namespace else ([] if kind in ("nodes", "namespaces") else ["-A"])
        if selector:
            if not _SELECTOR.fullmatch(selector):
                raise OpsError(f"invalid selector: {selector!r}")
            args += ["-l", selector]
        return {"kind": kind, **self.capped(parsers.k8s_rows(kind, self._kubectl_json(*args)), 40)}

    def k8s_describe(self, kind: str, name: str, namespace: str | None = None) -> dict[str, Any]:
        self.require("k8s.read", namespace or "")
        if kind not in K8S_KINDS:
            raise OpsError(f"kind must be one of {sorted(K8S_KINDS)}")
        self._names(namespace, name)
        text = self._kubectl("describe", K8S_KINDS[kind], name, *(["-n", namespace] if namespace else []))
        meta = self.artifacts.save("describe", f"{kind}/{name}", text)
        clean = redact_text(text)
        _, _, events = clean.partition("\nEvents:")
        interesting = [line for line in clean.splitlines()
                       if re.match(r"^\s*(Status|Reason|Message|State|Last State|Exit Code|Ready|Restart Count|"
                                   r"Image|Node|Conditions|Type|Replicas)\b", line)]
        return {"artifact": meta.id, "facts": [clip(line.strip(), 160) for line in interesting[:25]],
                "events": [clip(line.strip(), 220) for line in events.strip().splitlines()[-8:]]}

    def k8s_logs(self, name: str, namespace: str, lines: int = 200, container: str | None = None,
                 previous: bool = False, grep: str | None = None) -> dict[str, Any]:
        self.require("k8s.read", namespace)
        if not _K8S_LOG_TARGET.fullmatch(name):
            raise OpsError(f"invalid target: {name!r} (pod name or deployment/<name>)")
        self._names(namespace, container)
        args = ["logs", name, "-n", namespace, f"--tail={max(10, min(lines, 5000))}"]
        args += ["-c", container] if container else ["--all-containers=true"]
        if previous:
            args.append("--previous")
        text = self._kubectl(*args)
        meta = self.artifacts.save("k8s-logs", f"{namespace}/{name}", text)
        selected = redact_text(text).splitlines()
        if grep:
            try:
                regex = re.compile(grep[:200], re.IGNORECASE)
            except re.error as exc:
                raise OpsError(f"invalid grep: {exc}") from exc
            selected = [line for line in selected if regex.search(line)]
        return {"artifact": meta.id, **compress_log(selected)}

    def k8s_events(self, namespace: str | None = None) -> dict[str, Any]:
        self.require("k8s.read", namespace or "")
        self._names(namespace)
        document = self._kubectl_json("get", "events", *self._scope(namespace))
        return {"warnings": parsers.k8s_events(document, max_items=self.max_items)}

    def k8s_refresh(self, app: str, change_id: str | None = None) -> dict[str, Any]:
        return self._argo(app, change_id, "k8s.refresh", "hard refresh of Argo CD application", [
            "annotate", K8S_KINDS["applications"], app, "argocd.argoproj.io/refresh=hard", "--overwrite"])

    def k8s_sync(self, app: str, change_id: str | None = None) -> dict[str, Any]:
        patch = json.dumps({"operation": {"initiatedBy": {"username": "opsbrain"},
                                          "sync": {"syncStrategy": {"hook": {}}}}})
        return self._argo(app, change_id, "k8s.sync", "sync of Argo CD application", [
            "patch", K8S_KINDS["applications"], app, "--type", "merge", "-p", patch])

    def _argo(self, app: str, change_id: str | None, capability: str, what: str, args: list[str]) -> dict[str, Any]:
        self._names(name=app)
        gate = self.gate(capability, app, change_id, summary=f"{what} {app}", content_hash=digest([capability, app]))
        if not isinstance(gate, Change):
            return gate
        namespace = self.config.k8s.argocd_namespace if self.config.k8s else "argocd"
        self._kubectl(*args, "-n", namespace)
        rows = parsers.k8s_rows("applications", self._kubectl_json("get", K8S_KINDS["applications"], app, "-n",
                                                                   namespace))
        return {"app": app, "done": capability, "now": rows[0] if rows else None, "change": gate.id}

    def k8s_restart(self, kind: str, name: str, namespace: str, change_id: str | None = None) -> dict[str, Any]:
        if kind not in ("deployments", "statefulsets", "daemonsets"):
            raise OpsError("kind must be deployments | statefulsets | daemonsets")
        self._names(namespace, name)
        target = f"{namespace}/{name}"
        gate = self.gate("k8s.restart", namespace, change_id, summary=f"rollout restart {kind}/{name} in {namespace}",
                         content_hash=digest(["k8s.restart", kind, target]))
        if not isinstance(gate, Change):
            return gate
        self._kubectl("rollout", "restart", f"{kind}/{name}", "-n", namespace)
        try:
            self._kubectl("rollout", "status", f"{kind}/{name}", "-n", namespace, "--timeout=150s", timeout=170)
            rolled = True
        except OpsError:
            rolled = False
        rows = parsers.k8s_rows(kind, self._kubectl_json("get", kind, name, "-n", namespace))
        return {"target": target, "rolled_out": rolled, "now": rows[0] if rows else None, "change": gate.id}

    # --------------------------------------------------------------------------------------- network
    def _router(self) -> str:
        if self.config.network is None:
            raise OpsError("network is not configured")
        return self.config.network.router

    def _live_export(self) -> list[str]:
        result = self.exec.run_ssh(self._router(), "/export hide-sensitive", timeout=90)
        if not result.ok or not result.out.strip():
            raise OpsError(f"cannot read the router export: {clip(result.out.strip(), 200) or 'empty'}")
        return parsers.mikrotik_normalise(redact_text(result.out))

    def network_export(self) -> dict[str, Any]:
        self.require("network.read")
        lines = self._live_export()
        meta = self.artifacts.save("mikrotik-export", "live /export hide-sensitive", "\n".join(lines))
        sections: dict[str, int] = {}
        current = ""
        for line in lines:
            if line.startswith("/"):
                current = line.strip()
                sections.setdefault(current, 0)
            elif current and line.strip():
                sections[current] += 1
        return {"artifact": meta.id, "lines": len(lines), "sections": sections}

    def network_drift(self) -> dict[str, Any]:
        self.require("network.read")
        network = self.config.network
        if network is None or not network.tracked_export:
            raise OpsError("network.tracked_export is not configured")
        tracked_path = (self.repo / network.tracked_export).resolve()
        if not tracked_path.is_relative_to(self.repo) or not tracked_path.is_file():
            raise OpsError(f"tracked export not found: {network.tracked_export}")
        tracked = parsers.mikrotik_normalise(tracked_path.read_text(encoding="utf-8", errors="replace"))
        live = self._live_export()
        diff = [line for line in difflib.unified_diff(tracked, live, "tracked", "live", n=0, lineterm="")
                if not line.startswith(("---", "+++", "@@"))]
        if not diff:
            return {"drift": False}
        meta = self.artifacts.save("mikrotik-diff", "tracked vs live", "\n".join(diff))
        return {"drift": True, "artifact": meta.id, "changed_lines": len(diff),
                "diff": [clip(line, 200) for line in diff[:30]],
                "note": "'-' only in the tracked file, '+' only on the router. OpsBrain never changes the router."}

    def network_print(self, path: str) -> dict[str, Any]:
        self.require("network.read")
        network = self.config.network
        if network is None or path not in network.print_paths:
            raise OpsError(f"path must be one of {network.print_paths if network else []}")
        result = self.exec.run_ssh(self._router(), f"{path} print without-paging", timeout=60)
        if not result.ok:
            raise OpsError(f"router: {clip(result.out.strip(), 200)}")
        meta = self.artifacts.save("mikrotik-print", path, result.out)
        lines = [line for line in redact_text(result.out).replace("\r", "").splitlines() if line.strip()]
        return {"artifact": meta.id, "lines": len(lines), "text": [clip(line, 200) for line in lines[:40]]}

    # --------------------------------------------------------------------------------------- observe
    def _prometheus(self) -> str:
        url = self.config.observe.prometheus_url
        if not url:
            raise OpsError("observe.prometheus_url is not configured")
        return url.rstrip("/")

    def observe_alerts(self) -> dict[str, Any]:
        self.require("observe.read")
        data = self.http.get_json(f"{self._prometheus()}/api/v1/alerts")
        grouped: dict[str, dict[str, Any]] = {}
        for alert in data.get("data", {}).get("alerts", []):
            labels = alert.get("labels", {})
            name = labels.get("alertname", "?")
            row = grouped.setdefault(f"{name}/{alert.get('state')}", {
                "alert": name, "state": alert.get("state"), "severity": labels.get("severity"), "n": 0, "on": [],
                "summary": clip(alert.get("annotations", {}).get("summary", ""), 160)})
            row["n"] += 1
            where = labels.get("instance") or labels.get("pod") or labels.get("job") or ""
            if where and len(row["on"]) < 6:
                row["on"].append(where)
        rows = sorted(grouped.values(), key=lambda row: (row["state"] != "firing", row["alert"]))
        return {"firing": sum(row["n"] for row in rows if row["state"] == "firing"), **self.capped(rows)}

    def observe_targets(self) -> dict[str, Any]:
        self.require("observe.read")
        data = self.http.get_json(f"{self._prometheus()}/api/v1/targets", {"state": "active"})
        targets = data.get("data", {}).get("activeTargets", [])
        down = [{"job": target.get("labels", {}).get("job"), "instance": target.get("labels", {}).get("instance"),
                 "error": clip(target.get("lastError", ""), 160)} for target in targets if target.get("health") != "up"]
        return {"total": len(targets), "down": down[:self.max_items]}

    def observe_query(self, expr: str, minutes: int = 0) -> dict[str, Any]:
        """Instant query, or with `minutes` a range reduced to min / avg / max / last per series."""
        self.require("observe.read")
        if not expr or len(expr) > 2000:
            raise OpsError("expr is required (max 2000 characters)")
        base = self._prometheus()
        if minutes <= 0:
            data = self.http.get_json(f"{base}/api/v1/query", {"query": expr})
        else:
            end = time.time()
            minutes = min(minutes, 7 * 24 * 60)
            data = self.http.get_json(f"{base}/api/v1/query_range", {
                "query": expr, "start": end - minutes * 60, "end": end, "step": max(15, minutes * 60 // 120)})
        if data.get("status") != "success":
            raise OpsError(f"prometheus: {clip(str(data.get('error', data)), 300)}")
        result = data["data"].get("result", [])
        if not isinstance(result, list):  # scalar / string
            return {"value": result}
        labels = [{key: value for key, value in series.get("metric", {}).items() if key != "__name__"}
                  for series in result]
        common, labels = hoist_common(labels)
        rows: list[dict[str, Any]] = []
        for series, own in zip(result, labels, strict=True):
            if "value" in series:
                rows.append({**own, "v": _number(series["value"][1])})
            else:
                values = [number for _, raw in series.get("values", []) if (number := _number(raw)) is not None]
                if values:
                    rows.append({**own, "min": min(values), "avg": round(sum(values) / len(values), 4),
                                 "max": max(values), "last": values[-1]})
        return {"series": len(rows), **({"common": common} if common else {}), **self.capped(rows, 30)}

    def observe_logs(self, query: str, minutes: int = 60, limit: int = 300) -> dict[str, Any]:
        self.require("observe.read")
        url = self.config.observe.loki_url
        if not url:
            raise OpsError("observe.loki_url is not configured")
        if not query or len(query) > 2000:
            raise OpsError("query (LogQL) is required")
        end = time.time()
        data = self.http.get_json(f"{url.rstrip('/')}/loki/api/v1/query_range", {
            "query": query, "limit": max(10, min(limit, 5000)), "direction": "backward",
            "start": int((end - min(minutes, 7 * 24 * 60) * 60) * 1e9), "end": int(end * 1e9)})
        entries = sorted((entry for stream in data.get("data", {}).get("result", [])
                          for entry in stream.get("values", [])), key=lambda entry: entry[0])
        lines = [entry[1] for entry in entries]
        meta = self.artifacts.save("loki", query, "\n".join(lines))
        return {"artifact": meta.id, **compress_log(redact_text("\n".join(lines)).splitlines())}

    def observe_http(self, name: str | None = None) -> dict[str, Any]:
        self.require("observe.read")
        checks = self.config.observe.http_checks
        if name is not None and name not in checks:
            raise OpsError(f"name must be one of {sorted(checks)}")
        selected = {name: checks[name]} if name else checks
        results = {key: self.http.check(url) for key, url in selected.items()}
        return {"checks": {key: {"code": code, "ms": ms} for key, (code, ms) in results.items()},
                "failing": [key for key, (code, _) in results.items() if not 200 <= code < 400]}


def _number(raw: Any) -> float | None:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return None if value != value else round(value, 4)  # NaN -> None
