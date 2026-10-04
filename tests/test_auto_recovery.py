"""#12 OPS-AUTO-09: a recovery loop that is bounded, and that does not inherit anybody's permission.

The properties under test are the ones that decide whether a loop is a repair or a way around the gate:

* progress is measured from facts, and a worker's claim that it worked is not one of them;
* a mutating step must bring its own plan and its own change, so the previous approval is never reused;
* an attempt whose outcome nobody observed is reconciled, not repeated;
* the state, the blockers, the history and the spend survive a restart;
* all four ceilings stop the loop, and none of them resets when the process does.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opsbrain.auto.recovery import (
    Attempt,
    Ceiling,
    Observation,
    Progress,
    Recovery,
    Step,
    Stop,
    measure,
    permits_new_change,
    reconciliation_required,
)
from opsbrain.util import OpsError


def broken(**extra: object) -> Observation:
    return Observation(fingerprints=frozenset({"systemd:unit-start:masked", "disk:free:low"}), **extra)


def fixed() -> Observation:
    return Observation(fingerprints=frozenset({"disk:free:low"}), verified=frozenset({"unit-started"}))


# ------------------------------------------------------------------ progress is measured, not reported
def test_a_failure_that_no_longer_reproduces_is_progress() -> None:
    out = measure(broken(), fixed())
    assert out.made
    assert out.resolved == ("systemd:unit-start:masked",)
    assert out.remaining == ("disk:free:low",)


def test_a_property_nobody_had_established_and_now_does_is_progress() -> None:
    before = Observation(fingerprints=frozenset({"a"}))
    after = Observation(fingerprints=frozenset({"a"}), verified=frozenset({"holds"}))
    out = measure(before, after)
    assert out.made and out.newly_verified == ("holds",), out.to_dict()


def test_a_worker_that_says_it_worked_while_the_same_failures_remain_is_not_progress() -> None:
    """The one sentence a loop would say for ever, while the unit stays masked."""
    out = measure(broken(), broken(), claimed=True)
    assert not out.made
    assert "claim is not a measurement" in out.why, out.why


def test_an_attempt_that_claims_success_and_also_fixed_something_is_progress_but_the_claim_is_noted() -> None:
    out = measure(broken(), fixed(), claimed=True)
    assert out.made
    assert "ignored its own claim" in out.why, out.why


def test_nothing_different_at_all_is_not_progress() -> None:
    assert not measure(broken(), broken()).made


# ------------------------------------------------------------------ the loop is bounded
def test_a_loop_stops_the_moment_an_attempt_makes_no_progress() -> None:
    loop = Recovery(change_id="c-1", permitted=(Step.REWRITE_PLAN.value,))
    loop.record(Step.REWRITE_PLAN.value, broken(), broken())
    assert loop.stop == Stop.NO_PROGRESS.value
    assert loop.next_step() is None
    assert "a human" in loop.report()["next"] or "nothing left" in loop.report()["next"], loop.report()["next"]


def test_a_step_that_stopped_working_is_not_tried_again_with_the_same_inputs() -> None:
    loop = Recovery(change_id="c-1", permitted=(Step.REWRITE_PLAN.value, Step.COLLECT_EVIDENCE.value))
    assert loop.next_step() == Step.REWRITE_PLAN.value
    loop.record(Step.REWRITE_PLAN.value, broken(), broken())
    assert loop.stop == Stop.NO_PROGRESS.value
    assert loop.next_step() is None, "a different plan for the same unmeasured failure is the same failure"


def test_every_ceiling_is_measured_against_what_this_loop_spent(tmp_path: Path) -> None:
    generous = Ceiling(max_repair_cycles=9, max_model_calls=99, max_spend_usd=0.0, max_wall_s=99_000)
    fresh = Recovery(change_id="c-1", permitted=(Step.REWRITE_PLAN.value,))
    assert fresh.blocked(generous) == (False, "")

    # One attempt that cost something, so the money ceiling has something to be measured against.
    loop = Recovery(change_id="c-1", permitted=(Step.REWRITE_PLAN.value,))
    loop.attempts.append(Attempt(number=1, step=Step.REWRITE_PLAN.value, before=broken(), after=fixed(),
                                 progress=Progress(made=True), spend_usd=0.05))
    for ceiling, expected in (
            (Ceiling(max_repair_cycles=0, max_model_calls=99, max_wall_s=99_000), "repair ceiling"),
            (Ceiling(max_repair_cycles=9, max_model_calls=0, max_wall_s=99_000), "call ceiling"),
            (Ceiling(max_repair_cycles=9, max_model_calls=99, max_spend_usd=0.01, max_wall_s=99_000),
             "spend ceiling"),
            (Ceiling(max_repair_cycles=9, max_model_calls=99, max_wall_s=0.0), "time ceiling")):
        hit, why = loop.blocked(ceiling)
        assert hit and expected in why, (expected, why)


def test_a_loop_does_not_retry_after_the_budget_is_gone() -> None:
    loop = Recovery(change_id="c-1", permitted=(Step.REWRITE_PLAN.value,))
    loop.attempts.append(Attempt(number=1, step=Step.REWRITE_PLAN.value, before=broken(), after=fixed(),
                                 progress=Progress(made=True), calls_used=10))
    hit, why = loop.blocked(Ceiling(max_repair_cycles=5, max_model_calls=10, max_wall_s=99_000))
    assert hit and "call ceiling" in why
    loop.stop_now(Stop.BUDGET_EXHAUSTED, why)
    assert loop.finished and loop.next_step() is None


def test_a_zero_spend_ceiling_means_no_limit_and_not_no_spending() -> None:
    loop = Recovery(change_id="c-1", permitted=(Step.REWRITE_PLAN.value,))
    loop.attempts.append(Attempt(number=1, step=Step.REWRITE_PLAN.value, before=broken(), after=fixed(),
                                 progress=Progress(made=True), spend_usd=99.0))
    assert not loop.blocked(Ceiling(max_repair_cycles=9, max_model_calls=99, max_spend_usd=0.0,
                                    max_wall_s=99_000))[0]


# ------------------------------------------------------------------ nothing is inherited
def test_a_mutating_step_is_permitted_only_with_its_own_plan_and_its_own_change(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The change that failed keeps its spent approval; the repair goes back through the gate.

    A retry naming the old plan and the old change inherits the old change's authorisation, which is
    exactly what the gate was installed to stop. So the refusal is on the *ids*, not on the intent.
    """
    from test_auto_decision import TOKEN, _autonomous_ops, _bundle, _plan_for_change

    from opsbrain.auto.config import AutoConfig, PolicyProfileConfig

    ops.config = ops.config.model_copy(update={"auto": AutoConfig(
        enabled=True, autonomy_token=TOKEN, review={"runner": "codex"},
        decision={"mode": "autonomous", "default_profile": "secrets"},
        profiles=[PolicyProfileConfig(name="secrets", extra_reviews=1, allowed_targets=["proxmox"],
                                      recovery_actions=["rewrite_plan", "collect_evidence"])])})
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id), profile="secrets")
    ops.auto.review_plan(plan)
    ops.auto.decide_change(change.id, plan.id)
    opened = ops.auto.start_recovery(change.id, plan.id)
    recovery_id = opened["id"]

    with pytest.raises(OpsError, match="needs its own plan and its own change"):
        ops.auto.record_recovery_attempt(recovery_id, Step.REWRITE_PLAN.value, before=broken().to_dict(),
                                         after=fixed().to_dict(), plan_id=plan.id, change_id="")
    with pytest.raises(OpsError, match="needs its own plan and its own change"):
        ops.auto.record_recovery_attempt(recovery_id, Step.REWRITE_PLAN.value, before=broken().to_dict(),
                                         after=fixed().to_dict())
    # Collect-evidence reads rather than mutates, so it stands on its own.
    report = ops.auto.record_recovery_attempt(recovery_id, Step.COLLECT_EVIDENCE.value,
                                              before=broken().to_dict(), after=fixed().to_dict(),
                                              calls_used=1)
    assert report["attempts"][0]["progress"]["made"] is True, report


def test_only_the_steps_that_touch_infrastructure_need_a_new_change() -> None:
    """Stated rather than inferred, and the exception is the point: collecting evidence is a read."""
    assert permits_new_change(Step.REWRITE_PLAN.value)
    assert permits_new_change(Step.ROLLBACK.value)
    assert not permits_new_change(Step.COLLECT_EVIDENCE.value), (
        "demanding a change for a read would mean the one safe step is the one nobody can take")


# ------------------------------------------------------------------ the profile has to say what may be tried
def test_a_profile_that_names_no_recovery_actions_gets_no_loop(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """`recovery_actions` was configured, documented, and never read; now nothing is tried unless it says so."""
    from test_auto_decision import _autonomous_ops, _bundle, _plan_for_change

    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    with pytest.raises(OpsError, match="names no recovery actions"):
        ops.auto.start_recovery(change.id, plan.id)


def test_a_loop_reads_the_actions_the_profile_permits(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from test_auto_decision import TOKEN, _autonomous_ops, _bundle, _plan_for_change

    from opsbrain.auto.config import AutoConfig, PolicyProfileConfig

    ops.config = ops.config.model_copy(update={"auto": AutoConfig(
        enabled=True, autonomy_token=TOKEN, review={"runner": "codex"},
        decision={"mode": "autonomous", "default_profile": "secrets"},
        profiles=[PolicyProfileConfig(name="secrets", extra_reviews=1, allowed_targets=["proxmox"],
                                      recovery_actions=["rewrite_plan", "not_a_real_step"])])})
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id), profile="secrets")
    ops.auto.review_plan(plan)
    ops.auto.decide_change(change.id, plan.id)
    report = ops.auto.start_recovery(change.id, plan.id)
    assert report["permitted"] == ["rewrite_plan"], (
        "a name the loop does not implement is not a permitted action, it is a typo in a security field")


# ------------------------------------------------------------------ an unknown outcome is looked at, not repeated
def test_an_attempt_nobody_observed_is_reconciled_before_anything_runs_again() -> None:
    """Repeating an unobserved operation is how a retry duplicates a side effect that had landed."""
    for result in ("failed", "rc", "error"):
        why = reconciliation_required({"result": result}, None)
        assert "unknown rather than failed" in why, (result, why)
    landed = reconciliation_required({"result": "ok"}, None)
    assert "could duplicate work that had already landed" in landed, landed
    assert reconciliation_required({"result": "ok"}, {"state": "resolved"}) == ""


# ------------------------------------------------------------------ the report and the restart
def test_the_report_carries_the_state_the_blockers_the_history_and_the_spend() -> None:
    loop = Recovery(change_id="c-1", permitted=(Step.COLLECT_EVIDENCE.value,))
    loop.record(Step.COLLECT_EVIDENCE.value, broken(), fixed(), calls_used=2, spend_usd=0.03,
                plan_id="pl-2", change_id="c-2")
    report = loop.report()
    assert report["state"]["remaining"] == ["disk:free:low"], report["state"]
    assert report["state"]["verified"] == ["unit-started"], report["state"]
    assert report["spend"] == {"calls": 2, "usd": 0.03, "elapsed_s": report["spend"]["elapsed_s"]}
    assert len(report["attempts"]) == 1 and report["attempts"][0]["change_id"] == "c-2"
    assert report["next"] == Step.REWRITE_PLAN.value or report["next"]


def test_a_restart_does_not_reset_the_budget_or_replay_an_attempt() -> None:
    """The ceilings are measured from the record, so a restart does not hand back a fresh allowance."""
    loop = Recovery(change_id="c-1", permitted=(Step.COLLECT_EVIDENCE.value, Step.REWRITE_PLAN.value))
    loop.record(Step.COLLECT_EVIDENCE.value, broken(), fixed(), calls_used=7, spend_usd=0.5)
    reloaded = Recovery.from_dict(json.loads(json.dumps(loop.to_dict())))
    assert reloaded.calls_used == 7 and reloaded.spend_usd == 0.5
    assert len(reloaded.attempts) == 1
    assert reloaded.blocked(Ceiling(max_repair_cycles=9, max_model_calls=7, max_wall_s=99_000))[0], (
        "a restart that resets the call ceiling turns one spend into many")
    assert reloaded.next_step() == Step.REWRITE_PLAN.value, "and the step that worked is not repeated"


def test_a_loop_whose_permitted_actions_were_widened_on_disk_is_refused() -> None:
    loop = Recovery(change_id="c-1", permitted=(Step.COLLECT_EVIDENCE.value,))
    document = loop.to_dict()
    document["permitted"].append(Step.ROLLBACK.value)
    with pytest.raises(OpsError, match="do not match its own digest"):
        Recovery.from_dict(document)


def test_a_loop_bound_to_another_change_is_not_this_loops_digest() -> None:
    loop = Recovery(change_id="c-1", permitted=(Step.REWRITE_PLAN.value,))
    document = loop.to_dict()
    document["change_id"] = "c-someone-else"
    with pytest.raises(OpsError, match="do not match its own digest"):
        Recovery.from_dict(document)


def test_a_discarded_change_gets_no_loop_at_all(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from test_auto_decision import TOKEN, _autonomous_ops, _bundle, _plan_for_change

    from opsbrain.auto.config import AutoConfig, PolicyProfileConfig

    ops.config = ops.config.model_copy(update={"auto": AutoConfig(
        enabled=True, autonomy_token=TOKEN, review={"runner": "codex"},
        decision={"mode": "autonomous", "default_profile": "secrets"},
        profiles=[PolicyProfileConfig(name="secrets", extra_reviews=1, allowed_targets=["proxmox"],
                                      recovery_actions=["rewrite_plan"])])})
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id), profile="secrets")
    ops.auto.review_plan(plan)
    ops.changes.discard(change.id)
    with pytest.raises(OpsError, match="was discarded"):
        ops.auto.start_recovery(change.id, plan.id)
