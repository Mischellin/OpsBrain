"""#13 OPS-AUTO-11: the whole chain, once, end to end, with no human `yes` anywhere.

The other suites test each gate on its own, which is the right way to find a defect and the wrong way to
find out whether the gates are *connected*. This one walks the path a real permitted change takes:

    evidence → an incorrect plan → a review finding → a corrected plan → preflight PASS → the policy
    engine's approval → apply → canary → deterministic verification → postflight → rollout → VERIFIED

Nothing here calls `opsbrain approve`, and nothing here stubs out a gate to make the next one reachable.
The `fake` executor and the `fake` reviewer stand in for the outside world - OpenTofu, ssh, Codex - and
nothing else: the review, the decision, the approval, the gate, the verification and the rollout are
the real ones.

The second test is the fixture from the issue that started all of this: a drop-in written to
`logrotate.d`, which holds logrotate's own configuration, while systemd reads `logrotate.service.d`.
The apply exits 0, the file exists, the unit is active, and nothing happened. It has to be stopped twice
- before the change is made, and again after it is applied by something that did not go through the
first door.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

pytestmark = pytest.mark.e2e

from opsbrain.auto.plan import ChangePlan, ProposedChange, Reversibility  # noqa: E402
from opsbrain.auto.recovery import Step  # noqa: E402
from opsbrain.auto.rollout import Host, Stage  # noqa: E402

#: Where systemd actually reads a unit's drop-ins, and where the failing fixture writes instead.
UNIT = "logrotate.service"
HOST = "ops"
RIGHT_DROP_IN = "/etc/systemd/system/logrotate.service.d/10-ops.conf"
WRONG_DROP_IN = "/etc/logrotate.d/10-ops.conf"
#: A `systemd:*` check is revision-bearing, so the fixture states the revision it is looking for; without
#: one the check is `UNKNOWN` rather than passing, which is the behaviour, not an obstacle.
APPLIED = "Sun 2026-10-04 03:00:00 UTC"


def _blocking(path: str) -> dict[str, Any]:
    """A review that stops a plan writing to `path`, in the contract's own document shape.

    Built with `response_document` rather than by hand: the strict parser rejects the whole document on
    a missing or misspelled field, and a hand-written one that does not parse comes back as
    `review_failed` - a verdict that says the reviewer crashed, not the one the test is about.
    """
    from opsbrain.auto.review import Finding, Severity, Verdict, response_document

    return response_document(Verdict.NEEDS_CHANGES, [
        Finding(Severity.BLOCKER, f"the plan writes to {path}, but systemd reads {RIGHT_DROP_IN}",
                required_property="correct_dropin_path")])


def _apply_command(change_id: str) -> str:
    return "Apply complete! Resources: 0 added, 1 changed, 0 destroyed.\n@@OPSBRAIN-POSTPLAN 0@@\n"


def _unit_plan(bundle_id: str, *, drop_in: str) -> Any:
    """A plan that installs a logrotate drop-in, at whichever path the caller names."""
    from test_auto_decision import PLAN_ARGS

    return ChangePlan.build(
        objective="make logrotate rotate web-1's logs on the schedule the operator asked for",
        diagnosis="the timer is enabled but its drop-in directory is wrong, so the unit runs with the "
                  "distribution defaults and never rotates",
        changes=[ProposedChange(capability="tofu.apply", target="proxmox", how=f"install a logrotate "
                                       f"drop-in into {drop_in}", arguments=dict(PLAN_ARGS),
                                declared_check="systemd:unit-active", reversible=Reversibility.ROLLBACK,
                                undo=f"rm -f {drop_in} && systemctl daemon-reload",
                                # What the step acts on, spelled out: verification builds its targets from
                                # these, and a `Target` needs a host, a resource and an expectation - none of
                                # which can be recovered from `target="proxmox"`.
                                profile="systemd", resource=UNIT, host=HOST, expectation=RIGHT_DROP_IN,
                                expected_revision=APPLIED)],
        evidence_refs=[bundle_id], evidence_bundle=bundle_id, targets=["proxmox"],
        versions={"systemd": "252"},
        post_checks=["systemd:unit-active", "systemd:drop-in"],
        preconditions=["web-1 is reachable"],
        rollback="systemctl revert logrotate.service",
        profile="secrets", created=1_700_000_000.0)


def _autonomous(ops: Any, tmp_path: Any, **decision: Any) -> Any:
    """The pipeline switched on, in the configuration an operator would write in YAML."""
    from test_auto_decision import TOKEN, _autonomous_ops

    from opsbrain.auto.config import AutoConfig, PolicyProfileConfig

    auto = AutoConfig(
        # Verification is scoped to what the plan acts on. Left at the default it would also run the http,
        # k8s, storage and drift checks, which this plan named no target for - four honest `NOT_RUN`s that
        # `overall_status` then has to carry, and a report about a logrotate drop-in that spends four fifths
        # of itself saying it did not check a Kubernetes workload.
        enabled=True, autonomy_token=TOKEN, review={"runner": "codex"}, verify={"profiles": ["systemd"]},
        decision={"mode": "autonomous", "default_profile": "secrets", **decision},
        profiles=[PolicyProfileConfig(name="secrets", classification="medium", extra_reviews=2,
                                      allowed_targets=["proxmox"], allowed_capabilities=["tofu.apply"],
                                      require_verification=["systemd:unit-active"],
                                      recovery_actions=["rewrite_plan", "collect_evidence"],
                                      allow_autonomous=True)])
    ops.config = ops.config.model_copy(update={"auto": auto})
    return _autonomous_ops(ops, tmp_path, **decision)


def _fixes_the_drop_in(ops: Any, tmp_path: Any) -> None:
    """What the outside world answers when the pipeline asks: the facts of a healthy unit."""
    from test_auto_verify import show

    ops.exec.on(r"systemctl show", show(drop_ins=RIGHT_DROP_IN))
    ops.exec.on(r"is-active", "active\n")
    ops.exec.on(r"tofu apply", _apply_command("c-1"))


def test_a_permitted_change_runs_the_whole_chain_without_a_human_yes(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The only arrangement in which "autonomous" means anything, walked once from the top.

    The interesting assertion is the middle one: the corrected plan is a *different plan*, reviewed in
    its own right, and the approval that finally issues is bound to that plan and not to the first.
    A loop that let the original approval carry a rewritten plan would make every review since the first
    decorative.
    """
    from test_auto_decision import _bundle

    from opsbrain.auto.rollout import StageState

    _autonomous(ops, tmp_path)
    _fixes_the_drop_in(ops, tmp_path)

    # 1. Evidence: real observations, bound to the change they are about.
    change = ops.changes.create("tofu.apply", "proxmox", "make logrotate rotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    bundle_id = _bundle(ops, tmp_path, change.id)
    assert bundle_id.startswith("ev-"), bundle_id

    # 2. An incorrect plan, and the review that says so. `FakeReviewer` matches on the request text, so
    # only the plan naming the wrong directory gets this answer.
    wrong = _unit_plan(bundle_id, drop_in=WRONG_DROP_IN)
    ops.auto.reviews._reviewer.on(WRONG_DROP_IN, _blocking(WRONG_DROP_IN))
    refused = ops.auto.review_plan(wrong)
    assert refused["approvable"] is False, refused
    assert refused["findings"][0]["severity"] == "BLOCKER", refused["findings"]

    # 3. The worker fixes it, and the corrected plan is reviewed on its own merits.
    right = _unit_plan(bundle_id, drop_in=RIGHT_DROP_IN)
    assert right.id != wrong.id
    approved = ops.auto.review_plan(right)
    assert approved["outcome"] == "approvable", approved
    assert len(ops.auto.preflight().get_by_plan(right.id)["review_refs"]) == 2, (
        "the profile's class is worth two independent reviews and both ran")

    # 4. The deterministic engine decides, and the approval it issues names *this* plan.
    decided = ops.auto.decide_change(change.id, right.id)
    assert decided["decision"]["decision"] == "APPROVE", decided["decision"].get("detail", decided)
    approval = decided["approval"]
    from opsbrain.auto.approval import ApprovalStore

    binding = ApprovalStore(ops.auto.root / "approvals").get(approval).binding
    assert binding.change_id == change.id and binding.subject == "tofu.apply:proxmox", binding
    assert ops.changes.get(change.id).details["plan_id"] == right.id, (
        "the change remembers the corrected plan, so a later judgement cannot be pointed at the first one")

    # 5. Apply: the gate spends the approval and nobody is asked.
    applied = ops.tofu_apply(change.id)
    assert applied["ok"] is True, applied

    # 6. Verification, from the plan's own declared checks.
    # `systemd:unit-start` starts something, so it is refused unless the plan declared it; `unit-active`
    # and `drop-in` are reads, and the pair is what distinguishes "the unit is up" from "this unit is up
    # with the configuration the change installed".
    report = ops.auto.verify_plan(right.id)
    assert report["status"] == "PASS", report
    assert report["is_pass"] is True
    # `outstanding` is absent rather than empty on a clean report, so this is the key's absence that
    # means "nothing left to establish" - and a report that quietly omitted it would look identical.
    assert "outstanding" not in report, report
    assert set(report["by_status"]) <= {"PASS"}, report["by_status"]

    # 7. Postflight: the model is shown the report and told it cannot authorise.
    judged = ops.auto.postflight(change.id, right.id, verification=report)
    assert judged["outcome"] == "confirmed", judged
    assert judged["review_id"].startswith("rv-")

    # 8. Rollout, one stage at a time, each stage gated on its own facts.
    stages = (Stage(targets=("ph-1",), checks=("systemd:unit-active", "systemd:drop-in"),
                    observation_s=5.0, label="canary"),
              Stage(targets=("ph-2", "ph-3"), checks=("systemd:unit-active", "systemd:drop-in"),
                    observation_s=5.0, label="rest"))
    hosts = {"ph-1": Host(name="ph-1"), "ph-2": Host(name="ph-2"), "ph-3": Host(name="ph-3")}
    opened = ops.auto.start_rollout(change.id, right.id, stages, hosts=hosts, strategy="saved_plans")
    assert opened["canary"] == "ph-1", opened
    for _ in stages:
        step = ops.auto.advance_rollout(opened["id"], report=report, postflight_outcome="confirmed",
                                        stages=stages)
        assert step["promoted"] is True, step
    assert step["complete"] is True
    assert all(state == StageState.PROMOTED.value for state in step["states"]), step["states"]

    # 9. The audit says all of it, in order, and nobody typed `yes`.
    events = [row.get("event") for row in ops.audit.entries()]
    for expected in ("preflight", "decision", "verified", "postflight", "rollout"):
        assert expected in events, f"{expected} left no trace: {events}"
    assert not any("yes" in json.dumps(row).lower() for row in ops.audit.entries()
                   if row.get("event") == "decision"), "no human step in the decision"


def test_a_drop_in_in_the_wrong_directory_never_reaches_a_change(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The fixture from the issue, stopped at the door.

    `logrotate.d` holds logrotate's own configuration; systemd reads `logrotate.service.d`. Everything the
    apply itself would report is green. What stops it is the review, and it stops *before* the change is
    made - which is the point of having a review at all.
    """
    from test_auto_decision import _bundle

    _autonomous(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "make logrotate rotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    bundle_id = _bundle(ops, tmp_path, change.id)
    wrong = _unit_plan(bundle_id, drop_in=WRONG_DROP_IN)
    ops.auto.reviews._reviewer.on(WRONG_DROP_IN, _blocking(WRONG_DROP_IN))

    reviewed = ops.auto.review_plan(wrong)
    assert reviewed["approvable"] is False

    # And there is no route from here to a mutation: no engine decision, and therefore no approval.
    refused = ops.auto.decide_change(change.id, wrong.id)
    assert refused["decision"]["decision"] == "BLOCKED_AUTONOMOUSLY", refused
    assert "opsbrain approve" not in json.dumps(refused)
    assert ops.changes.get(change.id).state == "pending", "nothing ran"


def test_a_rc_zero_apply_that_changed_nothing_does_not_reach_verified(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A successful return code is not the goal, and a postflight nobody measured is not a verdict.

    The same chain, with the unit active but the drop-in not in force: every signal the apply produced is
    green, the verification fails, and the rollout never opens a second stage.
    """
    from test_auto_decision import _bundle
    from test_auto_verify import show

    _autonomous(ops, tmp_path)
    ops.exec.on(r"systemctl show", show(drop_ins=WRONG_DROP_IN))
    ops.exec.on(r"is-active", "active\n")
    ops.exec.on(r"tofu apply", _apply_command("c-1"))
    change = ops.changes.create("tofu.apply", "proxmox", "make logrotate rotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    bundle_id = _bundle(ops, tmp_path, change.id)
    plan = _unit_plan(bundle_id, drop_in=RIGHT_DROP_IN)
    ops.auto.review_plan(plan)
    assert ops.auto.decide_change(change.id, plan.id)["decision"]["decision"] == "APPROVE"
    assert ops.tofu_apply(change.id)["ok"] is True

    report = ops.auto.verify_plan(plan.id)
    assert report["status"] == "FAIL", report
    # The postflight is given the report that exists, not the one that would have been convenient.
    judged = ops.auto.postflight(change.id, plan.id, verification=report)
    assert judged["outcome"] == "not_met", judged
    assert "roll back" in judged["next"]

    stages = (Stage(targets=("ph-1",), checks=("systemd:drop-in"), observation_s=5.0),
              Stage(targets=("ph-2",), checks=("systemd:drop-in"), observation_s=5.0))
    hosts = {"ph-1": Host(name="ph-1"), "ph-2": Host(name="ph-2")}
    opened = ops.auto.start_rollout(change.id, plan.id, stages, hosts=hosts, strategy="saved_plans")
    step = ops.auto.advance_rollout(opened["id"], report=report, postflight_outcome=judged["outcome"],
                                    stages=stages)
    assert step["promoted"] is False, "a failed stage does not open the next one"
    assert step["states"] == ["failed", "pending"], step["states"]


def test_the_recovery_loop_cannot_start_from_an_unfinished_change(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The loop opens for work that ran, and the change it repairs is not the change it may re-run."""
    from test_auto_decision import _bundle

    _autonomous(ops, tmp_path)
    _fixes_the_drop_in(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "make logrotate rotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    bundle_id = _bundle(ops, tmp_path, change.id)
    plan = _unit_plan(bundle_id, drop_in=RIGHT_DROP_IN)
    ops.auto.review_plan(plan)
    ops.auto.decide_change(change.id, plan.id)
    assert ops.tofu_apply(change.id)["ok"] is True

    loop = ops.auto.start_recovery(change.id, plan.id)
    assert loop["permitted"] == [Step.REWRITE_PLAN.value, Step.COLLECT_EVIDENCE.value]
    # A mutating attempt without its own plan and change is refused: the spent approval stays spent.
    with pytest.raises(Exception, match="needs its own plan and its own change"):
        ops.auto.record_recovery_attempt(loop["id"], Step.REWRITE_PLAN.value,
                                         before={"fingerprints": ["drop-in:not-in-force"]},
                                         after={"fingerprints": []})
