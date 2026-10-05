import pytest

from opsbrain.changes import ChangeStore
from opsbrain.config import Access
from opsbrain.policy import decide
from opsbrain.util import OpsError


def test_defaults_and_deny_overrides() -> None:
    assert decide({}, "tofu.plan") is Access.ALLOW
    assert decide({}, "tofu.apply") is Access.CONFIRM
    assert decide({}, "something.new") is Access.CONFIRM
    rules = {"k8s.*": Access.DENY, "k8s.restart:dev": Access.ALLOW, "hosts.restart": Access.ALLOW}
    assert decide(rules, "k8s.restart", "dev") is Access.DENY  # a narrower allow cannot reopen a deny
    assert decide(rules, "hosts.restart", "web") is Access.ALLOW
    assert decide({"k8s.restart:dev": Access.ALLOW}, "k8s.restart", "prod") is Access.CONFIRM


def test_change_needs_approval_matching_hash_and_is_single_use(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = ChangeStore(tmp_path, 3600)
    change = store.create("tofu.apply", "proxmox", "plan", "h1")
    with pytest.raises(OpsError, match="not approved"):
        store.consume(change.id, "tofu.apply", "proxmox", needs_approval=True)
    store.approve(change.id)
    with pytest.raises(OpsError, match="changed since"):
        store.consume(change.id, "tofu.apply", "proxmox", needs_approval=True, content_hash="other")
    with pytest.raises(OpsError, match="is for"):
        store.consume(change.id, "ansible.apply", "proxmox", needs_approval=True)
    store.consume(change.id, "tofu.apply", "proxmox", needs_approval=True, content_hash="h1")
    with pytest.raises(OpsError, match="single use"):
        store.consume(change.id, "tofu.apply", "proxmox", needs_approval=True)


def test_destructive_change_needs_explicit_flag_even_when_policy_allows(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = ChangeStore(tmp_path, 3600)
    change = store.create("tofu.apply", "proxmox", "destroy vm", "h", dangerous=True)
    with pytest.raises(OpsError, match="destructive"):
        store.consume(change.id, "tofu.apply", "proxmox", needs_approval=False)
    with pytest.raises(OpsError, match="--allow-destroy"):
        store.approve(change.id)
    store.approve(change.id, allow_dangerous=True)
    store.consume(change.id, "tofu.apply", "proxmox", needs_approval=True)


def test_expired_change(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = ChangeStore(tmp_path, -1)
    change = store.create("tofu.apply", "proxmox", "plan", "h")
    with pytest.raises(OpsError, match="expired"):
        store.approve(change.id)
    assert store.list() == []
