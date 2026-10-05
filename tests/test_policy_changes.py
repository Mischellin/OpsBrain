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


def test_approve_and_discard_share_the_transition_lock(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A discarded change must not be re-approved, and a spent one must not be re-approved either.

    `consume` took a lock while `approve` and `discard` did not, so a racing `approve` could read PENDING,
    wait for `consume` to write APPLIED, and write APPROVED back over it - handing out a second run of a
    change that had already been applied. All three transitions now serialise on one lock.
    """
    store = ChangeStore(tmp_path, 3600)
    spent = store.create("tofu.apply", "proxmox", "already applied", "h")
    store.approve(spent.id)
    store.consume(spent.id, "tofu.apply", "proxmox", needs_approval=True)
    with pytest.raises(OpsError, match="is applied, not pending"):
        store.approve(spent.id)

    dropped = store.create("tofu.apply", "proxmox", "cancelled", "h")
    store.discard(dropped.id)
    with pytest.raises(OpsError, match="is discarded, not pending"):
        store.approve(dropped.id)
    with pytest.raises(OpsError, match="was discarded"):
        store.consume(dropped.id, "tofu.apply", "proxmox", needs_approval=False)


def test_a_change_id_is_validated_before_it_is_used_as_a_path(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = ChangeStore(tmp_path, 3600)
    store.create("tofu.apply", "proxmox", "plan", "h")
    for bad in ("../escape", "c-../../etc/passwd", "", "nope"):
        with pytest.raises(OpsError, match="invalid change id"):
            store.discard(bad)
        with pytest.raises(OpsError, match="invalid change id"):
            store.approve(bad)
    assert not list(tmp_path.glob("*escape*")), "nothing was created outside the store"
