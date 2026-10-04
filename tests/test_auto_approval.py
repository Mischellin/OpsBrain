"""#14 OPS-AUTO-05: an approval is bound to five inputs and is spent exactly once.

Two properties carry the whole issue and both are tested here from the outside:

* **staleness** - any of the plan, arguments, targets, evidence or policy moving makes the approval
  inapplicable, and it says *which* rather than the first thing it happened to notice;
* **single use** - two concurrent consumers, or a retry, must not run the same approved change twice.
  The race is tested with real threads against a real file lock, because a mock would not reproduce it.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

from opsbrain.auto.approval import (
    Approval,
    ApprovalBinding,
    ApprovalStore,
    LeaseState,
    StaleReason,
    binding_for,
    execute_once,
    stale_reasons,
    verify,
)
from opsbrain.util import OpsError, now


def a_binding(**overrides: Any) -> ApprovalBinding:
    base: dict[str, Any] = {"change_id": "c-1a2b3c4d", "subject": "tofu.apply:proxmox",
                            "plan_hash": "ph-original", "arguments_hash": "ah-original",
                            "targets": ("proxmox",), "evidence_ids": ("ev-aaaaaaaabbbbbbbb",),
                            "policy_version": "v1", "profile": "general", "created": now() - 10.0}
    return ApprovalBinding(**{**base, **overrides})


def current(**overrides: Any) -> dict[str, Any]:
    binding = a_binding()
    base: dict[str, Any] = {"plan_hash": binding.plan_hash, "arguments_hash": binding.arguments_hash,
                            "subject": binding.subject, "policy_version": binding.policy_version,
                            "targets": list(binding.targets), "evidence_ids": list(binding.evidence_ids)}
    return {**base, **overrides}


# -------------------------------------------------------------------------------- what it is bound to
def test_the_binding_covers_the_five_inputs_and_is_addressed_by_content() -> None:
    binding = a_binding()
    assert binding.id == f"ap-{binding.binding_hash[:16]}"
    for field in ("plan_hash", "arguments_hash", "targets", "evidence_ids", "policy_version"):
        assert field in binding.as_digest_source(), field


def test_a_binding_without_a_plan_or_a_change_is_refused() -> None:
    with pytest.raises(OpsError, match="name the change"):
        a_binding(change_id="  ")
    with pytest.raises(OpsError, match="hash of the plan"):
        a_binding(plan_hash="")


@pytest.mark.parametrize("field,value,reason", [
    ("plan_hash", "ph-swapped", StaleReason.PLAN_CHANGED),
    ("arguments_hash", "ah-swapped", StaleReason.ARGUMENTS_CHANGED),
    ("subject", "tofu.apply:other", StaleReason.SUBJECT_CHANGED),
    ("policy_version", "v2", StaleReason.POLICY_CHANGED),
    ("targets", ["prod"], StaleReason.TARGETS_CHANGED),
    ("evidence_ids", ["ev-ccccccccccdddddd"], StaleReason.EVIDENCE_CHANGED),
])
def test_every_bound_input_that_moves_makes_it_stale(field: str, value: Any, reason: StaleReason) -> None:
    """These are the five ways a "same" change can differ from the one a human approved."""
    assert reason.value in stale_reasons(a_binding(), current(**{field: value}))


def test_all_reasons_are_reported_not_just_the_first() -> None:
    """One at a time turns a fix-incrementally loop into N rounds, and hides the other movers."""
    reasons = stale_reasons(a_binding(), current(plan_hash="ph-2", policy_version="v2",
                                                evidence_ids=["ev-000000000000000f"]))
    assert set(reasons) == {StaleReason.PLAN_CHANGED.value, StaleReason.POLICY_CHANGED.value,
                            StaleReason.EVIDENCE_CHANGED.value}


def test_unchanged_inputs_are_not_stale() -> None:
    assert stale_reasons(a_binding(), current()) == ()
    approval = Approval(binding=a_binding())
    assert verify(approval, current()) == ()


def test_a_revoked_or_spent_approval_never_verifies() -> None:
    spent = Approval(binding=a_binding(), state=LeaseState.CONSUMED)
    assert verify(spent, current()) == ("approval_consumed",)
    revoked = Approval(binding=a_binding(), state=LeaseState.REVOKED)
    assert verify(revoked, current()) == ("approval_revoked",)


def test_an_expired_approval_never_verifies() -> None:
    assert verify(Approval(binding=a_binding(expires_s=1.0, created=1.0)), current()) == ("approval_expired",)


def test_a_binding_survives_a_round_trip() -> None:
    binding = a_binding()
    assert ApprovalBinding.from_dict(binding.to_dict()).binding_hash == binding.binding_hash


# ------------------------------------------------------------------------------------ spending once
def test_an_approval_is_spent_exactly_once(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    approval = store.issue(a_binding())
    spent = store.consume(approval.id, current())
    assert spent.state is LeaseState.CONSUMED and spent.consumed_at > 0
    with pytest.raises(OpsError, match="already spent"):
        store.consume(approval.id, current())


def test_a_stale_approval_cannot_be_spent_and_says_why(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    approval = store.issue(a_binding())
    with pytest.raises(OpsError, match="STALE") as excinfo:
        store.consume(approval.id, current(plan_hash="ph-swapped"))
    assert "plan_changed" in str(excinfo.value)
    assert store.get(approval.id).state is LeaseState.ISSUED, "a refused spend leaves it spendable"


def test_concurrent_consumers_run_the_work_exactly_once(tmp_path: Path) -> None:
    """Two processes, one approval: the whole point of a single-use lease."""
    store = ApprovalStore(tmp_path)
    approval = store.issue(a_binding())
    spent: list[str] = []
    refused: list[str] = []
    barrier = threading.Barrier(6)

    def consume() -> None:
        barrier.wait()
        try:
            store.consume(approval.id, current(), owner="t")
            spent.append("ok")
        except OpsError:
            refused.append("refused")

    threads = [threading.Thread(target=consume) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(spent) == 1, f"the work ran {len(spent)} times"
    assert len(refused) == 5


def test_a_retry_with_the_same_key_is_answered_rather_than_re_executed(tmp_path: Path) -> None:
    """A restart that retries must get the earlier answer, not a second apply."""
    store = ApprovalStore(tmp_path)
    approval = store.issue(a_binding())
    first = store.consume(approval.id, current(), owner="worker-1", idempotency_key="job-42")
    again = store.consume(approval.id, current(), owner="worker-2", idempotency_key="job-42")
    assert again.state is LeaseState.CONSUMED
    assert again.outcome.get("idempotency_key") == "job-42"
    assert again.lease_owner == "worker-1", "the retry was answered by the original spender"
    with pytest.raises(OpsError, match="already spent"):
        store.consume(approval.id, current(), owner="worker-3", idempotency_key="a-different-job")


def test_execute_once_records_the_outcome(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    approval = store.issue(a_binding())
    with execute_once(approval.id, store, current(), owner="w", idempotency_key="k") as spent:
        assert spent.state is LeaseState.CONSUMED
    assert store.get(approval.id).outcome["state"] == "executed"


def test_issuing_the_same_binding_twice_is_one_approval(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    first = store.issue(a_binding())
    second = store.issue(a_binding())
    assert first.id == second.id
    assert len(list(tmp_path.glob("ap-*.json"))) == 1


def test_an_expired_approval_is_not_issued(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    with pytest.raises(OpsError, match="older than"):
        store.issue(a_binding(created=1.0, expires_s=1.0))


def test_a_revoked_approval_cannot_be_spent(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    approval = store.issue(a_binding())
    store.revoke(approval.id, "policy tightened")
    with pytest.raises(OpsError, match="revoked"):
        store.consume(approval.id, current())


def test_an_unknown_or_malformed_id_is_refused(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    for bad in ("ap-zzzz", "not-an-approval", "ap-", "../../etc/passwd", "rv-12345678abcdef"):
        with pytest.raises(OpsError, match="invalid approval id"):
            store.consume(bad, current())


# ----------------------------------------------------------------------- binding a real Change
def test_the_binding_is_built_from_the_change_not_from_the_caller(tmp_path: Path) -> None:
    """A binding assembled from caller arguments is a binding the caller chose."""
    from opsbrain.changes import Change

    change = Change(id="c-1a2b3c4d", capability="ansible.apply", target="common.yml",
                    summary="ansible apply common.yml", hash="ph-1", created=now(), expires=now() + 3600,
                    args={"limit": "web-1", "tags": "nginx"})
    binding = binding_for(change, evidence_ids=["ev-aaaaaaaabbbbbbbb"], policy_version="v1")
    assert binding.change_id == "c-1a2b3c4d"
    assert binding.subject == "ansible.apply:common.yml"
    assert binding.plan_hash == "ph-1", "the plan hash comes from the change record"
    assert binding.targets == ("common.yml",)
    assert binding.evidence_ids == ("ev-aaaaaaaabbbbbbbb",)
    assert binding.arguments_hash and binding.policy_version == "v1"
    # A change whose arguments differ yields a different binding, so an approval cannot be carried over.
    other = Change(id="c-1a2b3c4d", capability="ansible.apply", target="common.yml", summary="x",
                   hash="ph-1", created=now(), expires=now() + 3600, args={"limit": "db-1"})
    assert binding_for(other).arguments_hash != binding.arguments_hash


# --------------------------------------------------- the same guarantee in the human change path
def test_consume_is_atomic_across_threads(tmp_path: Path) -> None:
    """`ChangeStore.consume` is the same single-use guarantee on the human approval path."""
    from opsbrain.changes import ChangeStore

    store = ChangeStore(tmp_path, 3600)
    change = store.create("tofu.apply", "proxmox", "tofu apply proxmox", "ph-1")
    store.approve(change.id, allow_dangerous=False)
    ok: list[int] = []
    failures: list[str] = []
    barrier = threading.Barrier(5)

    def run() -> None:
        barrier.wait()
        try:
            store.consume(change.id, "tofu.apply", "proxmox", needs_approval=True)
            ok.append(1)
        except OpsError as exc:
            failures.append(str(exc))

    threads = [threading.Thread(target=run) for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(ok) == 1, f"the change was consumed {len(ok)} times"
    assert len(failures) == 4
    assert store.get(change.id).state == "applied"


def test_a_swapped_plan_is_refused_at_apply(tmp_path: Path) -> None:
    """The approval is spent only against the fingerprint of the plan about to be applied."""
    from opsbrain.changes import ChangeStore

    store = ChangeStore(tmp_path, 3600)
    change = store.create("tofu.apply", "proxmox", "tofu apply proxmox", "ph-original",
                          args={"plan_file": ".opsbrain/j-1a2b3c4d.tfplan"})
    store.approve(change.id, allow_dangerous=False)
    assert store.get(change.id).state == "approved"
    with pytest.raises(OpsError, match="code or arguments changed"):
        store.consume(change.id, "tofu.apply", "proxmox", needs_approval=True, content_hash="ph-swapped")
    assert store.get(change.id).state == "approved", "a refused consume leaves the approval spendable"
    assert store.consume(change.id, "tofu.apply", "proxmox", needs_approval=True,
                         content_hash="ph-original").state == "applied"
