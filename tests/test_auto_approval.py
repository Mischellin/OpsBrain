"""#14 OPS-AUTO-05: an approval is bound to five inputs and is spent exactly once.

Two properties carry the whole issue and both are tested here from the outside:

* **staleness** - any of the plan, arguments, targets, evidence or policy moving makes the approval
  inapplicable, and it says *which* rather than the first thing it happened to notice;
* **single use** - two concurrent consumers, or a retry, must not run the same approved change twice.
  The race is tested with real threads against a real file lock, because a mock would not reproduce it.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from opsbrain.auto.approval import (
    AlreadySpent,
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
                            "profile": binding.profile,
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
    with pytest.raises(OpsError, match="already spent|has not finished"):
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
    store.record_outcome(approval.id, {"state": "executed", "at": now()})
    again = store.consume(approval.id, current(), owner="worker-2", idempotency_key="job-42")
    assert first.outcome.get("replayed") is None, "the first spend is the real one"
    assert again.state is LeaseState.CONSUMED
    assert again.outcome.get("idempotency_key") == "job-42"
    assert again.outcome.get("replayed") is True, "the retry is marked so execute_once will not re-enter"
    assert again.lease_owner == "worker-1", "the retry was answered by the original spender"
    with pytest.raises(OpsError, match="already spent"):
        store.consume(approval.id, current(), owner="worker-3", idempotency_key="a-different-job")


def test_a_lease_taken_but_never_finished_blocks_until_its_ttl_then_is_reclaimed(tmp_path: Path) -> None:
    """A crash between spending the lease and recording what happened.

    The lease used to be committed as spent before the work ran, so one crash left the change permanently
    unexecutable and the advertised `ttl_s` was never consulted by anything.
    """
    store = ApprovalStore(tmp_path, ttl_s=60.0)
    approval = store.issue(a_binding())
    held = store.consume(approval.id, current(), owner="worker-1", idempotency_key="job-42")
    assert held.outcome["executed"] is False, "taken, not finished"

    for key in ("job-42", "another-job"):
        with pytest.raises(OpsError, match="has not finished"):
            store.consume(approval.id, current(), owner="worker-2", idempotency_key=key)

    # Past the TTL the claim is stale, and taking it over is the caller's explicit decision.
    path = tmp_path / f"{approval.id}.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["consumed_at"] = round(now() - 3600.0, 3)
    path.write_text(json.dumps(document), encoding="utf-8")
    reclaimed = store.consume(approval.id, current(), owner="worker-2", idempotency_key="another-job")
    assert reclaimed.outcome["reclaimed"] is True
    assert reclaimed.lease_owner == "worker-2", "and the new owner is recorded"


def test_execute_once_records_the_outcome(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    approval = store.issue(a_binding())
    with execute_once(approval.id, store, current(), owner="w", idempotency_key="k") as spent:
        assert spent.state is LeaseState.CONSUMED
    assert store.get(approval.id).outcome["state"] == "executed"


def test_execute_once_does_not_re_enter_the_body_on_a_retry(tmp_path: Path) -> None:
    """A restart that retries must get the earlier answer, never a second apply.

    The first fix let the retry through the context manager, which re-ran the caller's mutation body -
    the exact thing the idempotency key exists to prevent. The retry is now refused, with the recorded
    outcome, before the body can be entered.
    """
    store = ApprovalStore(tmp_path)
    approval = store.issue(a_binding())
    runs: list[str] = []
    with execute_once(approval.id, store, current(), owner="w", idempotency_key="job-42") as spent:
        assert spent.state is LeaseState.CONSUMED
        runs.append("apply")
    with pytest.raises(AlreadySpent, match="already spent"), \
            execute_once(approval.id, store, current(), owner="w", idempotency_key="job-42"):
        runs.append("apply")
    assert runs == ["apply"], "the body ran exactly once"


def test_a_retry_without_an_idempotency_key_is_refused(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    approval = store.issue(a_binding())
    with execute_once(approval.id, store, current(), owner="w", idempotency_key="k"):
        pass
    with pytest.raises(OpsError, match="already spent"), \
            execute_once(approval.id, store, current(), owner="w", idempotency_key="other"):
        raise AssertionError("a second apply with a different key must not run")


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
    binding = binding_for(change, evidence_ids=["ev-aaaaaaaabbbbbbbb"], policy_version="v1",
                          evidence_expires_in_s=900.0)
    assert binding.change_id == "c-1a2b3c4d"
    assert binding.subject == "ansible.apply:common.yml"
    assert binding.plan_hash == "ph-1", "the plan hash comes from the change record"
    assert binding.targets == ("common.yml",)
    assert binding.evidence_ids == ("ev-aaaaaaaabbbbbbbb",)
    assert binding.arguments_hash and binding.policy_version == "v1"
    # A change whose arguments differ yields a different binding, so an approval cannot be carried over.
    other = Change(id="c-1a2b3c4d", capability="ansible.apply", target="common.yml", summary="x",
                   hash="ph-1", created=now(), expires=now() + 3600, args={"limit": "db-1"})
    assert binding_for(other, policy_version="v1").arguments_hash != binding.arguments_hash


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


def test_an_approval_whose_contents_do_not_match_its_name_is_refused(tmp_path: Path) -> None:
    """The id is derived from the binding, so a file under the wrong name is not the record that was issued.

    Without this, anything able to write the data file could author an approval for a change of its
    choosing, with no engine decision behind it - the same defect the change store had.
    """
    store = ApprovalStore(tmp_path)
    issued = store.issue(a_binding())
    other = a_binding(change_id="c-deadbeef")
    path = tmp_path / f"{issued.id}.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["binding"] = other.to_dict()
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(OpsError, match="does not match its contents"):
        store.get(issued.id)
    assert [row["id"] for row in store.list()] == [], "a file that is not its own identity is not listed"


def test_an_approval_does_not_outlive_its_evidence(tmp_path: Path) -> None:
    """Evidence is fresh for 900s and an approval is good for 3600s by default.

    An approval issued just inside the freshness boundary would otherwise stay executable for three
    quarters of an hour after the observations behind it stopped describing the world.
    """
    change = SimpleNamespace(id="c-0000a1b2", capability="tofu.apply", target="proxmox", hash="ph-1",
                             args={}, expired=False, expires=now() + 7200.0)
    generous = binding_for(change, evidence_ids=("ev-aaaaaaaabbbbbbbb",), expires_s=3600.0, policy_version="v1",
                           evidence_expires_in_s=3600.0)
    assert generous.expires_s == pytest.approx(3600.0, abs=5)
    capped = binding_for(change, evidence_ids=("ev-aaaaaaaabbbbbbbb",), expires_s=3600.0, policy_version="v1",
                         evidence_expires_in_s=600.0)
    assert capped.expires_s == pytest.approx(600.0, abs=5)


def test_the_evidence_cap_can_only_shorten_an_approval(tmp_path: Path) -> None:
    """A caller passing a larger number must not be able to widen an approval past its evidence."""
    change = SimpleNamespace(id="c-0000a1b2", capability="tofu.apply", target="proxmox", hash="ph-1",
                             args={}, expired=False, expires=now() + 7200.0)
    binding = binding_for(change, expires_s=300.0, evidence_expires_in_s=900.0, policy_version="v1")
    assert binding.expires_s == pytest.approx(300.0, abs=5), "the shorter of the two stands"


def test_revoking_a_spent_approval_erases_nothing(tmp_path: Path) -> None:
    """A terminal record is not negotiable, and the record of what ran is not ours to erase."""
    store = ApprovalStore(tmp_path)
    approval = store.issue(a_binding())
    store.consume(approval.id, current(), owner="worker-1", idempotency_key="job-42")
    store.record_outcome(approval.id, {"state": "executed", "at": 1.0})
    with pytest.raises(OpsError, match="already spent|has not finished"):
        store.revoke(approval.id, "too late")
    kept = store.get(approval.id)
    assert kept.state is LeaseState.CONSUMED
    assert kept.outcome["state"] == "executed", "the proof of what ran survived"
    replay = store.consume(approval.id, current(), owner="worker-2", idempotency_key="job-42")
    assert replay.state is LeaseState.CONSUMED, "idempotent replay still answers with the earlier outcome"


def test_revoking_twice_is_not_an_error(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    approval = store.issue(a_binding())
    assert store.revoke(approval.id, "first").state is LeaseState.REVOKED
    assert store.revoke(approval.id, "second").state is LeaseState.REVOKED


def test_an_expired_approval_does_not_block_issuing_a_fresh_one(tmp_path: Path) -> None:
    """`created` and `expires_s` are outside the binding hash, so a re-review lands on the same id.

    Returning the dead record forever left a change that is still open with no way to act on it: the only
    way forward was to replan from scratch.
    """
    store = ApprovalStore(tmp_path)
    stale = store.issue(a_binding())
    # Age the stored record rather than issuing an already-dead one: that is the real situation, a record
    # that was valid and then outlived its window while the change it covers stayed open.
    path = tmp_path / f"{stale.id}.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["binding"]["created"] = round(now() - 10_000.0, 3)
    path.write_text(json.dumps(document), encoding="utf-8")
    assert store.get(stale.id).binding.expired is True
    fresh = store.issue(a_binding())
    assert fresh.id == stale.id, "the same decision keeps its identity"
    assert fresh.binding.expired is False
    assert store.get(stale.id).state is LeaseState.ISSUED, "the live record replaced the dead one"


def test_a_spent_approval_is_never_replaced_by_a_re_issue(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    approval = store.issue(a_binding())
    store.consume(approval.id, current(), owner="worker-1", idempotency_key="job-42")
    with pytest.raises(OpsError, match="already spent|has not finished"):
        store.issue(a_binding())
    assert store.get(approval.id).lease_owner == "worker-1", "the spender is still on the record"


def test_reclassifying_a_change_under_a_stricter_profile_makes_its_approval_stale(tmp_path: Path) -> None:
    """The profile selects the evidence, the preconditions, the targets and whether autonomy may run at all.

    Reclassifying from `general` to `secrets` left the plan, the subject and the policy-version string
    untouched, so a comparison that covered those three never noticed - and the approval granted under the
    looser profile stayed spendable under the stricter one.
    """
    store = ApprovalStore(tmp_path)
    binding = a_binding(profile="general")
    store.issue(binding)
    assert stale_reasons(binding, current(profile="general")) == ()
    reasons = stale_reasons(binding, current(profile="secrets"))
    assert StaleReason.PROFILE_CHANGED.value in reasons
    with pytest.raises(OpsError, match="STALE"):
        store.consume(binding.id, current(profile="secrets"), owner="w", idempotency_key="k")


def test_spending_verifies_that_the_record_is_the_one_named(tmp_path: Path) -> None:
    """`get` checks the content-addressed identity; spending has to check it too, and that is the path
    that matters. A binding swapped in under a valid filename would otherwise be accepted by any caller
    whose `current` matched the substituted binding.
    """
    store = ApprovalStore(tmp_path)
    issued = store.issue(a_binding())
    other = a_binding(change_id="c-deadbeef", arguments_hash="other-arguments")
    path = tmp_path / f"{issued.id}.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["binding"] = other.to_dict()
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(OpsError, match="does not match its contents"):
        store.consume(issued.id, current(), owner="w", idempotency_key="k")


def test_an_automatic_retry_does_not_undo_a_revocation(tmp_path: Path) -> None:
    """Revocation is a decision by a person; a retry of the original issuance must not silently redo it."""
    store = ApprovalStore(tmp_path)
    approval = store.issue(a_binding())
    store.revoke(approval.id, "the target is not ours")
    with pytest.raises(OpsError, match="was revoked"):
        store.issue(a_binding())
    assert store.get(approval.id).state is LeaseState.REVOKED, "the withdrawal stands"


def test_binding_evidence_without_saying_how_long_it_lasts_is_refused() -> None:
    """The cap is not optional, because forgetting it is the common case and it fails open.

    `stale_reasons` compares the evidence *ids*; whether the bundle is still fresh is checked only here.
    Omitting the cap left an approval good for 3600s standing on evidence fresh for 900s.
    """
    change = SimpleNamespace(id="c-0000a1b2", capability="tofu.apply", target="proxmox", hash="ph-1",
                             args={}, expired=False, expires=now() + 7200.0)
    with pytest.raises(OpsError, match="how long that evidence stays usable"):
        binding_for(change, evidence_ids=("ev-aaaaaaaabbbbbbbb",), expires_s=3600.0,
                    policy_version="v1")
    # With no evidence bound there is nothing to cap against, and the ordinary lifetime stands.
    assert binding_for(change, expires_s=3600.0, policy_version="v1").expires_s == pytest.approx(3600.0, abs=5)


def test_one_malformed_record_does_not_take_the_whole_listing_down(tmp_path: Path) -> None:
    """`targets: null` raises `TypeError` out of `tuple()` deep in the constructor, not `OpsError`."""
    store = ApprovalStore(tmp_path)
    good = store.issue(a_binding())
    broken = tmp_path / f"{a_binding(change_id='c-0000c0de').id}.json"
    document = json.loads((tmp_path / f"{good.id}.json").read_text(encoding="utf-8"))
    document["binding"]["targets"] = None
    broken.write_text(json.dumps(document), encoding="utf-8")

    listed = store.list()
    assert [row["id"] for row in listed] == [good.id], "the valid record is still listed"


def test_a_shorter_reissue_replaces_a_live_longer_one(tmp_path: Path) -> None:
    """Lifetime is outside the binding hash, so a re-review under a shorter window has to be applied.

    The stored record had not aged out, so `issue` handed it back unchanged and the approval stayed
    spendable past the deadline the new decision asked for.
    """
    store = ApprovalStore(tmp_path)
    generous = store.issue(a_binding(expires_s=3600.0))
    assert generous.binding.expires_s == pytest.approx(3600.0, abs=5)
    tighter = store.issue(a_binding(expires_s=300.0))
    assert tighter.id == generous.id, "the same decision keeps its identity"
    assert store.get(generous.id).binding.expires_s == pytest.approx(300.0, abs=5)
    assert store.get(generous.id).state is LeaseState.ISSUED, "and the record is still usable"


def test_a_longer_reissue_never_widens_a_live_one(tmp_path: Path) -> None:
    """Tightening is one-way. A longer grant must not resurrect or extend what is already there."""
    store = ApprovalStore(tmp_path)
    store.issue(a_binding(expires_s=300.0))
    same = store.issue(a_binding(expires_s=3600.0))
    assert same.binding.expires_s == pytest.approx(300.0, abs=5), "the shorter deadline stands"


def test_a_shorter_reissue_still_may_not_resurrect_a_spent_approval(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    approval = store.issue(a_binding())
    store.consume(approval.id, current(), owner="worker-1", idempotency_key="job-42")
    with pytest.raises(OpsError, match="older than"):
        store.issue(a_binding(expires_s=1.0))
    assert store.get(approval.id).state is LeaseState.CONSUMED


def test_binding_for_rejects_a_reviewed_plan_with_a_message_that_names_the_right_path() -> None:
    """`AttributeError` from three frames down reads like a bug here rather than a wrong argument.

    The message must also not point at a method that does not exist in this tree - a reader sent to
    `AutoService.decide_change` from this PR finds nothing there.
    """
    from opsbrain.auto.plan import ChangePlan, ProposedChange

    plan = ChangePlan.build(
        objective="o", diagnosis="d",
        changes=[ProposedChange(capability="tofu.apply", target="proxmox", how="h", undo="revert it")],
        rollback="revert it", created=1_700_000_000.0)
    with pytest.raises(OpsError, match="binds the change record, not a reviewed plan") as raised:
        binding_for(plan, policy_version="v1")
    assert "decide_change" not in str(raised.value), "no reference to code that is not in this tree"


def test_a_shorter_reissue_still_cannot_resurrect_a_revoked_approval(tmp_path: Path) -> None:
    """Tightening a live approval only removes authority; rewriting a revoked one adds it back.

    `shortens` may bypass the "hand back the live record" shortcut and nothing else.
    """
    store = ApprovalStore(tmp_path)
    approval = store.issue(a_binding(expires_s=3600.0))
    store.revoke(approval.id, "the target is not ours")
    with pytest.raises(OpsError, match="was revoked"):
        store.issue(a_binding(expires_s=60.0))
    assert store.get(approval.id).state is LeaseState.REVOKED, "the withdrawal stands"


def test_an_expired_record_cannot_be_spent_even_before_its_own_clock_runs_out(tmp_path: Path) -> None:
    """Expiry is terminal by state, not only by the clock: it can be recorded explicitly.

    Checking `binding.expired` alone let an EXPIRED record past the revoked and spent branches and be
    rewritten as CONSUMED - the expired decision executing.
    """
    store = ApprovalStore(tmp_path)
    approval = store.issue(a_binding())
    path = tmp_path / f"{approval.id}.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["state"] = LeaseState.EXPIRED.value
    path.write_text(json.dumps(document), encoding="utf-8")
    assert store.get(approval.id).binding.expired is False, "its own clock has not run out"
    with pytest.raises(OpsError, match="expired, not usable"):
        store.consume(approval.id, current(), owner="worker-1", idempotency_key="job-42")
    assert store.get(approval.id).state is LeaseState.EXPIRED


def test_a_non_finite_lifetime_does_not_become_an_approval_valid_forever(tmp_path: Path) -> None:
    """Every comparison with NaN is false, so a NaN lifetime expires never.

    Both values reach the binding: the constructor takes a float, and Python's JSON decoder accepts a
    bare `NaN`. A lifetime policy code got wrong, or a record edited on disk, would otherwise be an
    authorisation that never lapses.
    """
    for field, value in (("expires_s", float("nan")), ("created", float("nan")),
                         ("expires_s", float("inf"))):
        with pytest.raises(OpsError, match="finite"):
            a_binding(**{field: value})


def test_an_expired_record_written_as_a_bare_nan_is_still_unusable(tmp_path: Path) -> None:
    """A record already on disk with a NaN lifetime is refused at read, not trusted."""
    store = ApprovalStore(tmp_path)
    approval = store.issue(a_binding())
    path = tmp_path / f"{approval.id}.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    path.write_text(json.dumps(document).replace('"expires_s": 3600.0', '"expires_s": NaN'), encoding="utf-8")
    with pytest.raises(OpsError, match="finite"):
        store.get(approval.id)


def test_a_creation_time_ahead_of_the_clock_is_refused(tmp_path: Path) -> None:
    """Finite and positive is not enough.

    A `created` a little ahead of the local clock computes a negative age, so `expired` is false and a
    nominal one-hour approval stays usable until that arbitrary future timestamp plus an hour - malformed
    input silently extending authority rather than failing.
    """
    from opsbrain.auto.approval import CLOCK_SKEW_S

    with pytest.raises(OpsError, match="in the future"):
        a_binding(created=now() + CLOCK_SKEW_S + 60.0)
    # Ordinary drift between the issuing and the spending process is absorbed, not rejected.
    assert a_binding(created=now() + 5.0).id


def test_an_approval_names_the_policy_version_it_was_granted_under() -> None:
    """A sentinel reading as "no policy version" is a value the caller has to mirror forever.

    `DecisionConfig.policy_version` defaults to `v1`, so an approval built with `"unset"` was refused the
    moment it was spent - or, worse, the caller mirrored `"unset"` so it would work, and the approval then
    never went stale when the configured policy version actually moved.
    """
    with pytest.raises(OpsError, match="policy version"):
        a_binding(policy_version="")
    change = SimpleNamespace(id="c-0000a1b2", capability="tofu.apply", target="proxmox", hash="ph-1",
                             args={}, expired=False, expires=now() + 7200.0)
    binding = binding_for(change, policy_version="v2")
    assert binding.policy_version == "v2", "the binding carries what the configuration said"
    assert binding_for(change, policy_version="v3").id != binding.id, "and a policy bump changes the identity"


def test_an_approval_for_another_change_is_stale(tmp_path: Path) -> None:
    """The change id is part of the binding's identity, so it belongs in the staleness check.

    Two records that agree on plan, arguments, subject, targets, evidence, policy and profile are
    otherwise interchangeable - and an approval issued for one could be spent against the other, skipping
    that record's own approval or revocation.
    """
    store = ApprovalStore(tmp_path)
    approval = store.issue(a_binding())
    with pytest.raises(OpsError, match="STALE"):
        store.consume(approval.id, current(change_id="c-99999999"), owner="w", idempotency_key="k")
    assert StaleReason.CHANGE_SWAPPED.value in stale_reasons(
        a_binding(), current(change_id="c-99999999"))
    assert stale_reasons(a_binding(), current()) == (), "and the matching change is not stale"
