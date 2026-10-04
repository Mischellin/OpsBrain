"""The three P1 findings Codex raised on the v1 base (#2), tested from the outside.

All three are the same shape of mistake: a guard that exists, is documented, and is not applied on one
particular path. Each test below names the path, because "the guard is there" is exactly what the
original code looked like.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from opsbrain.config import Access
from opsbrain.util import OpsError


# ------------------------------------------------------------------- every tool result is redacted
def test_a_handler_that_forgets_to_sanitize_cannot_leak(ops) -> None:  # type: ignore[no-untyped-def]
    """`call` is the one place every result passes through, so that is where redaction belongs.

    Ansible failure details, k8s event messages and prometheus alert annotations all carry text nobody
    wrote a redaction call for.
    """
    def leaky(_: Any) -> dict[str, Any]:
        return {"detail": "connection failed: token=ghp_" + "a" * 36, "stderr": "password: hunter2"}

    out = ops.call("hosts", {"action": "status"}, leaky)
    text = json.dumps(out)
    assert "ghp_" not in text, "a raw credential reached the client through an unsanitised handler"
    assert "hunter2" not in text


def test_redaction_keeps_valid_json(ops) -> None:  # type: ignore[no-untyped-def]
    """Structure-aware redaction: the answer must still parse, or the client breaks instead of reading."""
    out = ops.call("hosts", {"action": "status"},
                   lambda: {"total": 2, "hosts": {"web-1": {"ok": True, "note": "password: hunter2"}}})
    json.loads(json.dumps(out))
    assert "hunter2" not in json.dumps(out)


# --------------------------------------------------- hosts.read policy applies to every selected host
def test_a_targeted_hosts_read_denial_blocks_a_batch(ops) -> None:  # type: ignore[no-untyped-def]
    """`hosts.read:pve: deny` was configured and the host was read anyway.

    `ping` and `status` asked about the bare capability and then freely selected hosts, so a targeted rule
    never participated in the decision.
    """
    ops.require = _policy(ops, {"hosts.read:pve": Access.DENY})
    for action in (ops.hosts_ping, ops.hosts_status):
        with pytest.raises(OpsError, match="pve"):
            action()
        with pytest.raises(OpsError, match="pve"):
            action(hosts=["pve"])


def test_a_tag_batch_respects_a_targeted_denial(ops) -> None:  # type: ignore[no-untyped-def]
    ops.require = _policy(ops, {"hosts.read:ops": Access.DENY})
    with pytest.raises(OpsError, match="ops"):
        ops.hosts_ping(hosts=["ops"])


def test_an_allowed_host_still_reads_under_the_same_policy(ops) -> None:  # type: ignore[no-untyped-def]
    ops.require = _policy(ops, {"hosts.read:ops": Access.DENY})
    ops.exec.rules.clear()
    ops.exec.on(r"true", "")
    answer = ops.hosts_ping(hosts=["pve"])
    assert answer["total"] == 1


def test_listing_the_inventory_respects_hosts_read(ops) -> None:  # type: ignore[no-untyped-def]
    """`hosts_list` never called `require` at all, and it returns addresses, jump chains and tags."""
    ops.require = _policy(ops, {"hosts.read": Access.DENY})
    with pytest.raises(OpsError, match="hosts.read"):
        ops.hosts_list()


# ------------------------------------------- an all-namespace k8s read needs every namespace allowed
def test_an_all_namespace_read_is_refused_when_a_namespace_is_denied(ops) -> None:  # type: ignore[no-untyped-def]
    """`-A` returns objects from namespaces the policy denies, and checking the empty target never sees that."""
    ops.exec.rules.clear()
    ops.exec.on(r"get namespaces", json.dumps({"items": [{"metadata": {"name": "prod"}},
                                                        {"metadata": {"name": "kube-system"}}]}) + "\n")
    ops.require = _policy(ops, {"k8s.read:prod": Access.DENY})
    with pytest.raises(OpsError, match="prod"):
        ops.k8s_get(kind="pods")


def test_an_all_namespace_read_is_allowed_when_every_namespace_is(ops) -> None:  # type: ignore[no-untyped-def]
    ops.exec.rules.clear()
    ops.exec.on(r"get namespaces", json.dumps({"items": [{"metadata": {"name": "prod"}}]}) + "\n")
    ops.exec.on(r"get pods", json.dumps({"items": []}) + "\n")
    ops.require = _policy(ops, {"k8s.read:prod": Access.ALLOW})
    assert ops.k8s_get(kind="pods")["kind"] == "pods"


def test_a_namespaced_read_is_unaffected_by_the_all_namespace_rule(ops) -> None:  # type: ignore[no-untyped-def]
    """Only the cluster-wide path needs every namespace; a normal read must not list them all."""
    ops.exec.rules.clear()
    ops.exec.on(r"get pods", json.dumps({"items": []}) + "\n")
    ops.require = _policy(ops, {"k8s.read:prod": Access.ALLOW})
    assert ops.k8s_get(kind="pods", namespace="prod")["kind"] == "pods"
    assert not any("get namespaces" in script for _, script in ops.exec.calls)


def _policy(ops: Any, rules: dict[str, Access]) -> Any:
    """A `require` bound to these rules, keeping the real error text."""
    from opsbrain.policy import decide

    def require(capability: str, target: str = "") -> None:
        access = decide(rules, capability, target)
        if access is Access.DENY:
            raise OpsError(f"{capability}{':' + target if target else ''} is denied by policy")

    return require
