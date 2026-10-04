"""MCP surface: 12 grouped tools. Tool schemas are paid for in every conversation, so descriptions are terse
and related operations share one tool with an `action` argument."""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .auto.config import all_reason_codes
from .auto.plan import ChangePlan
from .service import OpsBrain
from .util import OpsError, write_private

#: The steps a client performs to reach an autonomous apply, in order. The `autonomy` action table and the
#: instructions below both name these, because a flow the client is told about and a surface that cannot
#: carry it is worse than either one alone.
AUTONOMOUS_FLOW = ("review-plan", "decide", "postflight")

_COMMON = (
    "OpsBrain operates the infrastructure with compact answers. Start with `overview`, then `docs action=status` for "
    "the current state. Results are summaries; raw output is an artifact id - read it with `artifact` only when the "
    "summary is not enough. Long operations return a job id: poll with `job`. Reads are free. "
)
_TAIL = " Never ask for or handle credentials. There is no shell tool by design."

#: The manual workflow, stated for a server whose gate is not deciding.
INSTRUCTIONS = _COMMON + (
    "Mutations are two-step: plan/check returns a change id, a HUMAN approves it in a terminal with "
    "`opsbrain approve <id>`, then you call apply with change_id." + _TAIL
)


def build_instructions(config: Any) -> str:
    """The same instructions, with the mutation path the deployment actually has.

    Telling an autonomous deployment that a human must approve is not a harmless simplification: the
    installed gate rejects a hand-approved change that carries no engine approval, so a client following
    these instructions takes a path that is guaranteed to fail - and never discovers the `decide` action
    that would have worked.
    """
    if not (config.auto.enabled and config.auto.decision.autonomous):
        return INSTRUCTIONS
    # Every step is named in the `action=<step>` form the tool actually takes, and the flow is built from
    # the same tuple the action table dispatches on. Prose here that drifts from the table is a client
    # following the instructions into an action that does not exist.
    steps = ", then ".join(f"action={step}" for step in AUTONOMOUS_FLOW)
    return _COMMON + (
        f"Mutations need no human step. Call `autonomy` with {steps}, in that order: the plan goes in "
        "`document` as JSON for the first, the change id in `id` and the reviewed plan id in `plan` for "
        "the second, the verification report in `document` for the third. An APPROVE issues the approval "
        "the apply spends; a RETRY means review again; BLOCKED_AUTONOMOUSLY means it stopped and says why."
        + _TAIL
    )


def _need(value: Any, name: str) -> Any:
    if value is None or value == "":
        raise OpsError(f"`{name}` is required for this action")
    return value


def _dispatch(action: str, table: dict[str, Callable[[], Any]]) -> Any:
    if action not in table:
        raise OpsError(f"action must be one of {sorted(table)}")
    return table[action]()


def build_server(ops: OpsBrain) -> MCPServer:
    server = MCPServer("opsbrain", instructions=build_instructions(ops.config))

    @server.tool()
    def overview() -> str:
        """Inventory and what is in flight: hosts, tofu stacks, playbooks, pending changes, running jobs."""
        return ops.call("overview", {}, ops.overview)

    @server.tool()
    def docs(action: str = "status", query: str | None = None, path: str | None = None, start: int = 1,
             lines: int = 60, limit: int = 8) -> str:
        """Infrastructure knowledge from the repo. action: status (current state) | search (query) | read (path,
        start, lines)."""
        return ops.call("docs", {"action": action, "query": query, "path": path}, lambda: _dispatch(action, {
            "status": ops.docs_status,
            "search": lambda: ops.docs_search(_need(query, "query"), limit),
            "read": lambda: ops.docs_read(_need(path, "path"), start, lines)}))

    @server.tool()
    def hosts(action: str = "status", hosts: list[str] | None = None, tag: str | None = None,
              host: str | None = None, service: str | None = None, lines: int = 200, since: str | None = None,
              grep: str | None = None, change_id: str | None = None) -> str:
        """Hosts over ssh. action: list | ping | status (load, memory, disks, failed units; hosts/tag filter) |
        services (host) | logs (host, service, lines, since, grep) | restart (host, service; mutating)."""
        name = hosts
        return ops.call("hosts", {"action": action, "hosts": name, "tag": tag, "host": host, "service": service},
                        lambda: _dispatch(action, {
                            "list": ops.hosts_list,
                            "ping": lambda: ops.hosts_ping(name, tag),
                            "status": lambda: ops.hosts_status(name, tag),
                            "services": lambda: ops.hosts_services(_need(host, "host"), service),
                            "logs": lambda: ops.hosts_logs(_need(host, "host"), _need(service, "service"), lines,
                                                           since, grep),
                            "restart": lambda: ops.hosts_restart(_need(host, "host"), _need(service, "service"),
                                                                 change_id)}))

    @server.tool()
    def tofu(action: str = "plan", stack: str | None = None, change_id: str | None = None,
             lock_id: str | None = None, grep: str | None = None, sync: bool | None = None,
             wait_s: int | None = None) -> str:
        """OpenTofu on its runner. action: plan (summary + change id when there are changes) | apply (change_id;
        applies exactly the saved plan) | state (grep) | unlock (lock_id; stale state lock)."""
        return ops.call("tofu", {"action": action, "stack": stack, "change_id": change_id, "lock_id": lock_id},
                        lambda: _dispatch(action, {
                            "plan": lambda: ops.tofu_plan(stack, wait_s, sync),
                            "apply": lambda: ops.tofu_apply(_need(change_id, "change_id"), wait_s),
                            "state": lambda: ops.tofu_state(stack, grep),
                            "unlock": lambda: ops.tofu_unlock(_need(lock_id, "lock_id"), stack, change_id)}))

    @server.tool()
    def ansible(action: str = "playbooks", playbook: str | None = None, limit: str | None = None,
                tags: str | None = None, change_id: str | None = None, wait_s: int | None = None) -> str:
        """Ansible. action: playbooks | check (playbook, limit, tags; --check --diff, returns a change id when
        something would change) | apply (change_id; same playbook/limit/tags and unchanged code)."""
        return ops.call("ansible", {"action": action, "playbook": playbook, "limit": limit, "tags": tags,
                                    "change_id": change_id},
                        lambda: _dispatch(action, {
                            "playbooks": ops.ansible_playbooks,
                            "check": lambda: ops.ansible_check(_need(playbook, "playbook"), limit, tags, wait_s),
                            "apply": lambda: ops.ansible_apply(_need(change_id, "change_id"), wait_s)}))

    @server.tool()
    def k8s(action: str = "overview", kind: str | None = None, name: str | None = None,
            namespace: str | None = None, selector: str | None = None, container: str | None = None,
            lines: int = 200, previous: bool = False, grep: str | None = None, change_id: str | None = None) -> str:
        """Kubernetes / Argo CD. action: overview (only what is wrong) | get (kind, namespace, name, selector) |
        describe (kind, name) | logs (name or deployment/<name>, namespace) | events (warnings) | refresh (name=app)
        | sync (name=app) | restart (kind, name, namespace). Secrets are never readable."""
        return ops.call("k8s", {"action": action, "kind": kind, "name": name, "namespace": namespace},
                        lambda: _dispatch(action, {
                            "overview": ops.k8s_overview,
                            "get": lambda: ops.k8s_get(_need(kind, "kind"), namespace, name, selector),
                            "describe": lambda: ops.k8s_describe(_need(kind, "kind"), _need(name, "name"), namespace),
                            "logs": lambda: ops.k8s_logs(_need(name, "name"), _need(namespace, "namespace"), lines,
                                                         container, previous, grep),
                            "events": lambda: ops.k8s_events(namespace),
                            "refresh": lambda: ops.k8s_refresh(_need(name, "name"), change_id),
                            "sync": lambda: ops.k8s_sync(_need(name, "name"), change_id),
                            "restart": lambda: ops.k8s_restart(_need(kind, "kind"), _need(name, "name"),
                                                               _need(namespace, "namespace"), change_id)}))

    @server.tool()
    def network(action: str = "drift", path: str | None = None) -> str:
        """Router (read-only, always hide-sensitive). action: drift (tracked export vs live) | export (section
        sizes + artifact) | print (path from the configured allowlist)."""
        return ops.call("network", {"action": action, "path": path}, lambda: _dispatch(action, {
            "drift": ops.network_drift, "export": ops.network_export,
            "print": lambda: ops.network_print(_need(path, "path"))}))

    @server.tool()
    def drift(wait_s: int | None = None) -> str:
        """Code vs live infrastructure in one call: tofu plan, playbooks in --check, router export. Read-only."""
        return ops.call("drift", {}, lambda: ops.drift_check(wait_s))

    @server.tool()
    def observe(action: str = "alerts", expr: str | None = None, minutes: int = 0, limit: int = 300,
                name: str | None = None) -> str:
        """Monitoring. action: alerts | targets (down only) | query (expr=PromQL; minutes>0 = range reduced to
        min/avg/max/last) | logs (expr=LogQL, minutes, limit) | http (configured health checks)."""
        return ops.call("observe", {"action": action, "expr": expr, "minutes": minutes, "name": name},
                        lambda: _dispatch(action, {
                            "alerts": ops.observe_alerts, "targets": ops.observe_targets,
                            "query": lambda: ops.observe_query(_need(expr, "expr"), minutes),
                            "logs": lambda: ops.observe_logs(_need(expr, "expr"), minutes or 60, limit),
                            "http": lambda: ops.observe_http(name)}))

    @server.tool()
    def artifact(action: str = "list", id: str | None = None, start: int = 1, lines: int = 60,  # noqa: A002
                 pattern: str | None = None, context: int = 0) -> str:
        """Raw output kept on disk. action: list | read (id, start, lines; negative start counts from the end) |
        grep (id, pattern, context)."""
        return ops.call("artifact", {"action": action, "id": id, "pattern": pattern}, lambda: _dispatch(action, {
            "list": lambda: {"items": ops.artifacts.list()},
            "read": lambda: ops.artifacts.read(_need(id, "id"), start, lines),
            "grep": lambda: ops.artifacts.grep(_need(id, "id"), _need(pattern, "pattern"), context)}))

    @server.tool()
    def job(action: str = "status", id: str | None = None, wait_s: int | None = None) -> str:  # noqa: A002
        """Detached operations. action: status (id, wait_s) | list."""
        return ops.call("job", {"action": action, "id": id}, lambda: _dispatch(action, {
            "status": lambda: ops.wait(ops.jobs.get(_need(id, "id")), wait_s),
            "list": lambda: {"items": [item.brief() for item in ops.jobs.list()]}}))

    @server.tool()
    def change(action: str = "list", id: str | None = None) -> str:  # noqa: A002
        """Mutations waiting for a human. action: list | show (id) | discard (id). Approval is NOT available here:
        the user runs `opsbrain approve <id>` in a terminal."""
        return ops.call("change", {"action": action, "id": id}, lambda: _dispatch(action, {
            "list": lambda: {"items": [item.brief() for item in ops.changes.list()]},
            "show": lambda: (lambda item: {**item.brief(), "details": item.details})(ops.changes.get(_need(id, "id"))),
            "discard": lambda: ops.changes.discard(_need(id, "id")).brief()}))

    @server.tool()
    def autonomy(action: Literal[  # noqa: A002
        "status", "capabilities", "reviews", "evidence", "bundles", "verify_evidence", "reasons", "checks",
        "verify-plan", "review-plan", "decide", "postflight"
    ] = "status", limit: int = 20, id: str | None = None, plan: str | None = None,
        # `str`, never `str | None`: the MCP layer pre-parses a string argument into JSON whenever the
        # annotation is anything other than exactly `str`, so a client that did the obvious thing - sent
        # the plan as a JSON string - had it turned into a dict and then rejected it as not a string.
        # `review-plan` was unreachable over the real surface, and no test noticed because every one of
        # them called the Python method instead of the tool. An empty string is still "not supplied":
        # `_need` treats it as missing.
        document: str = "") -> str:
        """Autonomous pipeline; `review-plan` and `postflight` write, and neither applies anything.

        status: switches, mode, budget, evidence, verification
        capabilities: is the reviewer runnable; it never claims an unchecked model
        reviews / bundles / evidence: recent records
        verify_evidence: re-check a stored bundle, against the change it is bound to
        reasons: every reason code the pipeline can emit
        checks: what verification can demand, and why each check exists
        verify-plan: verify a change against the targets its own plan declared
        review-plan -> decide -> postflight: in order. The last three need `id` (the change) and `plan`;
            `review-plan` takes the plan as JSON in `document`, `postflight` the report in `document`
            too. An APPROVE issues the approval the apply spends, so nothing waits on a human.
        """
        return ops.call("autonomy", {"action": action, "id": id, "plan": plan},
                       lambda: _dispatch(action, {
            "status": ops.auto.overview,
            "capabilities": lambda: ops.auto.reviews.capabilities(),
            "reviews": lambda: {"items": ops.auto.reviews.list(limit)},
            "evidence": lambda: ops.auto.evidence_overview(),
            "bundles": lambda: {"items": ops.auto.evidence_list(limit)},
            "verify_evidence": lambda: ops.auto.verify_evidence(_need(id, "id")),
            "reasons": lambda: {"reasons": list(all_reason_codes())},
            "checks": lambda: {"observation": ops.auto.verify_overview(),
                               "available": ops.auto.verification_checks()},
            "verify-plan": lambda: ops.auto.verify_plan(_need(id, "id")),
            # Without this the advertised flow could not start: `decide` needs a preflight record, and
            # `review_plan` was reachable only from Python, so a client following the instructions always
            # ended at "no preflight record".
            "review-plan": lambda: ops.auto.review_plan(
                ChangePlan.from_dict(json.loads(_need(document, "document")))),
            "decide": lambda: ops.auto.decide_change(_need(id, "id"), _need(plan, "plan")),
            "postflight": lambda: ops.auto.postflight(_need(id, "id"), _need(plan, "plan"),
                                                     verification=(json.loads(_need(document, "document"))
                                                                   if document else None))}))

    return server


# ------------------------------------------------------------------------------------------------ HTTP
class BearerAuth:
    def __init__(self, app: ASGIApp, token: str):
        self.app, self.token = app, token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"] != "/healthz":
            headers = {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope["headers"]}
            supplied = headers.get("authorization", "").removeprefix("Bearer ").strip()
            if not secrets.compare_digest(supplied.encode(), self.token.encode()):
                await JSONResponse({"error": "unauthorized"}, status_code=401,
                                   headers={"WWW-Authenticate": "Bearer"})(scope, receive, send)
                return
        await self.app(scope, receive, send)


def http_token(data_dir: Path) -> str:
    """Bearer token of the loopback HTTP endpoint: generated once, 0600."""
    path = data_dir / "http.token"
    if not path.is_file():
        write_private(path, secrets.token_urlsafe(32))
    return path.read_text(encoding="utf-8").strip()


def build_http_app(ops: OpsBrain) -> ASGIApp:
    http = build_server(ops).streamable_http_app(
        json_response=True, stateless_http=True, host=ops.config.http.host,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True,
                                                     allowed_hosts=list(ops.config.http.allowed_hosts)))

    async def healthz(request: Any) -> JSONResponse:
        return JSONResponse({"ok": True})

    http.add_route("/healthz", healthz)
    return BearerAuth(http, http_token(ops.config.data_path))
