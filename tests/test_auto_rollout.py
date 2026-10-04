"""#11 OPS-AUTO-06: a staged rollout that can be stopped, and that cannot be widened while it runs.

The properties under test are the ones that make the staging worth anything. A rollout that keeps going
after a failed stage is a slower apply; one whose stages can be edited mid-flight measured something
narrower than what was eventually done; and one that promotes a stage nobody measured has replaced
"applied" with "applied and nobody checked".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opsbrain.auto.rollout import (
    MIN_QUORUM,
    CanaryChoice,
    Host,
    Rollout,
    Stage,
    StageState,
    Stop,
    gate,
    select_canary,
    stageable,
)
from opsbrain.auto.verify import CheckResult, CheckStatus, VerificationReport
from opsbrain.util import OpsError


def report(status: CheckStatus, *, observation_s: float = 30.0, change_id: str = "c-1") -> VerificationReport:
    return VerificationReport(change_id=change_id, status=status, captured=1.0,
                              results=(CheckResult(check="systemd:unit-start", profile="systemd", target="web-1",
                                                   status=status, captured=1.0, detail=""),),
                              evidence_refs=(), observation_s=observation_s)


def two_host_stages() -> tuple[Stage, ...]:
    return (Stage(targets=("web-1",), checks=("systemd:unit-start",), observation_s=30.0, label="canary"),
            Stage(targets=("web-2", "web-3"), checks=("systemd:unit-start",), observation_s=30.0,
                  label="rest"))


def topology() -> dict[str, Host]:
    return {
        "web-1": Host(name="web-1"),
        "web-2": Host(name="web-2"),
        "web-3": Host(name="web-3"),
    }


# ------------------------------------------------------------------ the canary is chosen, not guessed
def test_the_canary_is_the_first_eligible_host_in_the_rollouts_own_order() -> None:
    hosts = topology()
    hosts["web-1"] = Host(name="web-1", canary_eligible=False, ineligible_reason="it is the only one left")
    assert select_canary(hosts, ("web-2", "web-3")).host == "web-2"
    assert select_canary(hosts, ("web-3", "web-2")).host == "web-3", "the rollout's order decides, not a dict's"


def test_a_host_something_else_depends_on_is_not_a_canary() -> None:
    """A canary that is a dependency of another host in the same rollout is an outage, not a probe."""
    hosts = topology()
    hosts["web-1"] = Host(name="web-1", depended_on_by=("web-2",))
    assert select_canary(hosts, ("web-1", "web-2")).host == "web-2", "web-1 is skipped, not chosen"
    # When the dependency is the only candidate, the rollout does not start on it.
    choice = select_canary({"web-1": hosts["web-1"]}, ("web-1",))
    assert not choice.found
    assert "depended on by web-2" in choice.reason, choice.reason


def test_a_canary_that_breaks_its_quorum_is_skipped_for_one_that_does_not() -> None:
    """Taking a member of a replicated service is only safe while a majority remains."""
    hosts = topology()
    hosts["web-1"] = Host(name="web-1", quorum_group="pg", quorum_size=MIN_QUORUM)
    assert select_canary(hosts, ("web-1", "web-2")).host == "web-2", (
        "web-1 is the first name but not a safe probe; the rollout is not refused for a lucky ordering")
    # The same host in a group large enough to survive losing one member is fine.
    hosts["web-1"] = Host(name="web-1", quorum_group="pg", quorum_size=5)
    assert select_canary(hosts, ("web-1", "web-2")).host == "web-1"


def test_a_rollout_whose_only_host_breaks_its_quorum_does_not_start() -> None:
    hosts = topology()
    hosts["web-1"] = Host(name="web-1", quorum_group="pg", quorum_size=MIN_QUORUM)
    choice = select_canary({"web-1": hosts["web-1"]}, ("web-1",))
    assert not choice.found
    assert "quorum group 'pg'" in choice.reason, choice.reason
    assert "fewer than 2" in choice.reason, choice.reason


def test_the_refusal_lists_why_each_candidate_did_not_qualify() -> None:
    """An operator who cannot make a canary out of their topology needs to know which rule applied."""
    hosts = {
        "web-1": Host(name="web-1", canary_eligible=False, ineligible_reason="the only session"),
        "web-2": Host(name="web-2", quorum_group="pg", quorum_size=1),
    }
    choice = select_canary(hosts, ("web-1", "web-2"))
    assert not choice.found
    assert "web-1: not eligible (the only session)" in choice.reason, choice.reason
    assert "web-2:" in choice.reason and "quorum" in choice.reason, choice.reason


def test_a_rollout_starting_from_an_unknown_host_stops_before_it_starts() -> None:
    """No topology is not the same as a safe topology, and it is checked before anything is applied."""
    choice = select_canary(topology(), ("web-9",))
    assert not choice.found
    assert "no topology is known about it" in choice.reason, choice.reason
    assert select_canary(topology(), ("web-9", "web-1")).host == "web-1", (
        "an unknown name in the list is not a reason to refuse a host that is known")


def test_an_ineligible_host_is_refused_with_the_reason_it_was_given() -> None:
    hosts = {"web-1": Host(name="web-1", canary_eligible=False,
                           ineligible_reason="it holds the only session for the load balancer")}
    choice = select_canary(hosts, ("web-1",))
    assert choice == CanaryChoice(reason="no host in this stage could serve as a canary: web-1: not "
                                         "eligible (it holds the only session for the load balancer)")


# ------------------------------------------------------------------ which changes may be staged at all
def test_an_opentofu_plan_is_not_stageable_and_says_why() -> None:
    """`-target` does not make an apply gradual; it makes it decide less."""
    reason = stageable("tofu.apply", strategy="-target=web-1")
    assert "not stageable" in reason
    assert "-target" in reason, "the refusal names the thing that would have been tempting"
    assert stageable("tofu.apply", strategy="apply") != ""


def test_ansible_advances_host_groups_and_nothing_else() -> None:
    assert stageable("ansible.apply", strategy="host_groups") == ""
    assert "host groups" in stageable("ansible.apply", strategy="serial")


def test_a_stateful_kubernetes_workload_is_not_canaried() -> None:
    """A second pod is not a stand-in for the first when the first holds the only copy of the data."""
    assert "stateful" in stageable("k8s.apply", rollout_method="canary", stateful=True)


def test_a_pod_disruption_budget_the_rollout_cannot_read_stops_it() -> None:
    reason = stageable("k8s.apply", rollout_method="canary", pod_disruption_budget="web-pdb")
    assert "web-pdb" in reason
    assert stageable("k8s.apply", rollout_method="canary") == ""
    assert "unknown rollout method" in stageable("k8s.apply", rollout_method="vibes")


def test_a_capability_with_no_strategy_is_refused_rather_than_guessed() -> None:
    assert "no rollout strategy" in stageable("cloud.redeploy")


# ------------------------------------------------------------------ the gate between stages
def test_a_pass_with_a_postflight_promotes_the_stage() -> None:
    stage = two_host_stages()[0]
    assert gate(stage, report(CheckStatus.PASS), postflight_outcome="confirmed") == (
        True, Stop.NONE, "the stage's checks passed and the postflight did not contradict them")


def test_a_failed_stage_stops_the_rollout() -> None:
    promoted, stop, _ = gate(two_host_stages()[0], report(CheckStatus.FAIL), postflight_outcome="confirmed")
    assert not promoted
    assert stop is Stop.CHECK_FAILED


def test_an_unknown_stage_stops_the_rollout_and_is_not_a_pass() -> None:
    """A check that could not reach its target said nothing, and nothing is not good news."""
    promoted, stop, why = gate(two_host_stages()[0], report(CheckStatus.UNKNOWN), postflight_outcome="confirmed")
    assert not promoted
    assert stop is Stop.CHECK_UNKNOWN
    assert "UNKNOWN" in why, why


def test_checks_that_never_ran_stop_the_rollout() -> None:
    promoted, stop, why = gate(two_host_stages()[0], report(CheckStatus.NOT_RUN), postflight_outcome="confirmed")
    assert not promoted
    assert stop is Stop.CHECK_UNKNOWN
    assert "NOT_RUN" in why, why


def test_a_stage_observed_for_less_than_it_asked_for_is_not_promoted() -> None:
    """`observation_s` is the difference between "it is up" and "it has been up since the change"."""
    stage = two_host_stages()[0]
    promoted, stop, why = gate(stage, report(CheckStatus.PASS, observation_s=2.0), postflight_outcome="confirmed")
    assert not promoted
    assert stop is Stop.CHECK_UNKNOWN
    assert "asked to be observed for 30s" in why, why


def test_a_postflight_that_says_the_goal_was_missed_stops_the_next_stage() -> None:
    for outcome in ("not_met", "unclear"):
        promoted, stop, why = gate(two_host_stages()[1], report(CheckStatus.PASS), postflight_outcome=outcome)
        assert not promoted, outcome
        assert stop is Stop.POSTFLIGHT_NOT_MET, outcome
        assert outcome in why, why


def test_no_report_at_all_is_a_stop_rather_than_an_exception() -> None:
    promoted, stop, why = gate(two_host_stages()[0], None, postflight_outcome="confirmed")
    assert not promoted
    assert stop is Stop.CHECK_UNKNOWN
    assert "no report" in why, why


# ------------------------------------------------------------------ the stage list cannot move under it
def test_widening_the_stages_mid_flight_is_refused() -> None:
    rollout = Rollout(change_id="c-1", plan_id="pl-1", plan_hash="ab" * 16, stages=two_host_stages(),
                      canary="web-1", created=1.0)
    widened = (rollout.stages[0], Stage(targets=("web-2", "web-3", "web-4", "db-1"),
                                        checks=("systemd:unit-start",), observation_s=30.0, label="rest"))
    with pytest.raises(OpsError, match="changed since this rollout was created"):
        rollout.assert_unchanged(widened, "pl-1", "ab" * 16)
    rollout.assert_unchanged(rollout.stages, "pl-1", "ab" * 16), "the same stages still pass"


def test_editing_a_stored_stage_list_without_its_digest_is_caught_on_load() -> None:
    """The digest is re-derived on load rather than read off the record.

    It is a binding, not a seal: whoever changes the stages can recompute it, and pretending otherwise
    would be the more dangerous claim. What it does catch is the realistic accident - a stage list
    edited in place, or written by a different version of this code - and it does so before a single
    target is touched.
    """
    rollout = Rollout(change_id="c-1", plan_id="pl-1", plan_hash="ab" * 16, stages=two_host_stages(),
                      canary="web-1", created=1.0)
    document = rollout.to_dict()
    document["stages"][1]["targets"].append("web-9")
    with pytest.raises(OpsError, match="do not match its own digest"):
        Rollout.from_dict(document)
    # A precondition quietly dropped from a stage is caught the same way.
    relaxed = rollout.to_dict()
    relaxed["stages"][0]["preconditions"] = ["web-1 answers"]
    relaxed["stages_digest"] = rollout.stages_digest
    with pytest.raises(OpsError, match="do not match its own digest"):
        Rollout.from_dict(relaxed)


def test_changing_the_plan_or_its_hash_is_also_a_change_of_shape() -> None:
    rollout = Rollout(change_id="c-1", plan_id="pl-1", plan_hash="ab" * 16, stages=two_host_stages(),
                      canary="web-1", created=1.0)
    with pytest.raises(OpsError, match="changed since this rollout was created"):
        rollout.assert_unchanged(rollout.stages, "pl-2", "ab" * 16)
    with pytest.raises(OpsError, match="changed since this rollout was created"):
        rollout.assert_unchanged(rollout.stages, "pl-1", "cd" * 16)


# ------------------------------------------------------------------ a restart resumes
def test_a_restart_resumes_at_the_first_stage_that_did_not_happen() -> None:
    """Not "start again": a stage that was already promoted is never entered twice."""
    stages = two_host_stages()
    rollout = Rollout(change_id="c-1", plan_id="pl-1", plan_hash="ab" * 16, stages=stages,
                      canary="web-1", created=1.0)
    rollout.states[0] = StageState.PROMOTED.value
    assert rollout.current == 1
    assert not rollout.complete

    reloaded = Rollout.from_dict(json.loads(json.dumps(rollout.to_dict())))
    assert reloaded.current == 1, "the state is durable, so a restart does not replay the canary"
    assert reloaded.states[0] == StageState.PROMOTED.value


def test_a_finished_rollout_reports_itself_complete() -> None:
    rollout = Rollout(change_id="c-1", plan_id="pl-1", plan_hash="ab" * 16, stages=two_host_stages(),
                      canary="web-1", created=1.0)
    rollout.states = [StageState.PROMOTED.value, StageState.PROMOTED.value]
    assert rollout.complete


def test_a_stage_with_no_targets_is_not_a_stage() -> None:
    with pytest.raises(OpsError, match="covers nothing"):
        Stage(targets=())


def test_a_record_round_trips(tmp_path: Path) -> None:
    rollout = Rollout(change_id="c-0000a1b2", plan_id="pl-0000a1b2", plan_hash="ab" * 16,
                      stages=two_host_stages(), canary="web-1", created=1.0)
    document = rollout.to_dict()
    assert document["id"].startswith("ro")
    again = Rollout.from_dict(json.loads(json.dumps(document)))
    assert again.to_dict() == document


# ------------------------------------------------------------------ the whole thing, through the service
def test_a_permitted_rollout_promotes_stage_by_stage_without_a_human_yes(ops, tmp_path) -> None:
    """Plan, review, decide, apply, then stage by stage - with no `opsbrain approve` anywhere.

    The point of the rollout is that the stages after the first are reached *because the gate opened*,
    not because the first one returned zero. So the test asserts the state of each stage, not just the
    final verdict.
    """
    from test_auto_decision import _autonomous_ops, _bundle, _plan_for_change

    _autonomous_ops(ops, tmp_path)
    # The change is bound to the fingerprint the apply will re-derive, so the apply is the real one and
    # not a stub: the rollout is entered from a change that actually ran.
    change = ops.changes.create("ansible.apply", "common", "restart logrotate",
                                ops._ansible_hash("common", "web", None),
                                args={"playbook": "common", "limit": "web"}, details={})
    plan = _plan_for_change(target="common", capability="ansible.apply",
                            arguments={"playbook": "common", "limit": "web"},
                            bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    assert ops.auto.decide_change(change.id, plan.id)["decision"]["decision"] == "APPROVE"
    ops.exec.on(r"ansible-playbook", "changed=1 ok=1\n")
    assert ops.ansible_apply(change.id)["state"] == "done"

    stages = two_host_stages()
    opened = ops.auto.start_rollout(change.id, plan.id, stages, hosts=topology(), strategy="host_groups")
    assert opened["canary"] == "web-1", opened

    first = ops.auto.advance_rollout(opened["id"], report=report(CheckStatus.PASS).to_dict(),
                                     postflight_outcome="confirmed", stages=stages)
    assert first["promoted"] is True and first["states"] == ["promoted", "pending"], first
    second = ops.auto.advance_rollout(opened["id"], report=report(CheckStatus.PASS).to_dict(),
                                      postflight_outcome="confirmed", stages=stages)
    assert second["promoted"] is True and second["complete"] is True, second
    # A finished rollout is not re-entered.
    assert ops.auto.advance_rollout(opened["id"], report=report(CheckStatus.PASS).to_dict(),
                                    postflight_outcome="confirmed", stages=stages)["promoted"] is True


def test_a_lost_connection_stops_the_rollout_and_the_next_stage_never_starts(ops, tmp_path) -> None:
    """A host that stopped answering reported nothing, and nothing must not promote anything."""
    from test_auto_decision import _autonomous_ops, _bundle, _plan_for_change

    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("ansible.apply", "common", "restart logrotate",
                                ops._ansible_hash("common", "web", None),
                                args={"playbook": "common", "limit": "web"}, details={})
    plan = _plan_for_change(target="common", capability="ansible.apply",
                            arguments={"playbook": "common", "limit": "web"},
                            bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    ops.auto.decide_change(change.id, plan.id)
    stages = two_host_stages()
    opened = ops.auto.start_rollout(change.id, plan.id, stages, hosts=topology(), strategy="host_groups")

    lost = ops.auto.advance_rollout(opened["id"], report=report(CheckStatus.UNKNOWN).to_dict(),
                                    postflight_outcome="confirmed", stages=stages)
    assert lost["promoted"] is False
    assert lost["stop"] == "check_unknown", lost
    assert lost["states"] == ["failed", "pending"], "the second stage never started"
    assert "the next one does not start" not in lost["next"]
    # And the rollout stays stopped: a second attempt on the same stage does not promote it either.
    again = ops.auto.advance_rollout(opened["id"], report=report(CheckStatus.PASS).to_dict(),
                                     postflight_outcome="confirmed", stages=stages)
    assert again["promoted"] is True and again["current"] == 1, (
        "a fresh pass may retry the stage; what it may not do is skip past one that failed")


def test_widening_the_stages_mid_flight_is_refused_by_the_service(ops, tmp_path) -> None:
    from test_auto_decision import _autonomous_ops, _bundle, _plan_for_change

    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("ansible.apply", "common", "restart logrotate",
                                ops._ansible_hash("common", "web", None),
                                args={"playbook": "common", "limit": "web"}, details={})
    plan = _plan_for_change(target="common", capability="ansible.apply",
                            arguments={"playbook": "common", "limit": "web"},
                            bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    ops.auto.decide_change(change.id, plan.id)
    stages = two_host_stages()
    opened = ops.auto.start_rollout(change.id, plan.id, stages, hosts=topology(), strategy="host_groups")
    ops.auto.advance_rollout(opened["id"], report=report(CheckStatus.PASS).to_dict(),
                             postflight_outcome="confirmed", stages=stages)
    widened = (stages[0], Stage(targets=("web-2", "web-3", "db-1"), checks=stages[1].checks,
                                observation_s=30.0, label="rest"))
    with pytest.raises(OpsError, match="changed since this rollout was created"):
        ops.auto.advance_rollout(opened["id"], report=report(CheckStatus.PASS).to_dict(),
                                 postflight_outcome="confirmed", stages=widened)


def test_a_rollout_refuses_to_open_without_a_canary(ops, tmp_path) -> None:
    from test_auto_decision import _autonomous_ops, _bundle, _plan_for_change

    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("ansible.apply", "common", "restart logrotate",
                                ops._ansible_hash("common", "web", None),
                                args={"playbook": "common", "limit": "web"}, details={})
    plan = _plan_for_change(target="common", capability="ansible.apply",
                            arguments={"playbook": "common", "limit": "web"},
                            bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    ops.auto.decide_change(change.id, plan.id)
    with pytest.raises(OpsError, match="no canary to start with"):
        ops.auto.start_rollout(change.id, plan.id, two_host_stages(), hosts={}, strategy="host_groups")


def test_a_tofu_change_cannot_be_rolled_out_in_stages_at_all(ops, tmp_path) -> None:
    """The refusal names `-target`, because that is what an operator would otherwise reach for."""
    from test_auto_decision import _autonomous_ops, _bundle, _plan_for_change

    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    ops.auto.decide_change(change.id, plan.id)
    with pytest.raises(OpsError, match="-target"):
        ops.auto.start_rollout(change.id, plan.id, two_host_stages(), hosts=topology(), strategy="-target=web-1")


def test_rollback_runs_the_plans_own_undo_and_only_the_plans_own_undo(ops, tmp_path) -> None:
    from test_auto_decision import _autonomous_ops, _bundle, _plan_for_change

    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("ansible.apply", "common", "restart logrotate",
                                ops._ansible_hash("common", "web", None),
                                args={"playbook": "common", "limit": "web"}, details={})
    plan = _plan_for_change(target="common", capability="ansible.apply",
                            arguments={"playbook": "common", "limit": "web"},
                            bundle_id=_bundle(ops, tmp_path, change.id))
    ops.auto.review_plan(plan)
    ops.auto.decide_change(change.id, plan.id)
    stages = two_host_stages()
    opened = ops.auto.start_rollout(change.id, plan.id, stages, hosts=topology(), strategy="host_groups")
    ops.auto.advance_rollout(opened["id"], report=report(CheckStatus.PASS).to_dict(),
                             postflight_outcome="confirmed", stages=stages)
    undone = ops.auto.rollback_rollout(opened["id"])
    assert undone["rolled_back"] is True
    assert undone["undo"] == plan.rollback, "the undo is the plan's own, not a generic script"
    stored = Rollout.from_dict(ops.auto.rollouts().get(opened["id"]))
    assert stored.states == ["rolled_back", "rolled_back"], stored.states


def test_irreversible_work_is_not_rolled_back_by_a_generic_script(ops, tmp_path) -> None:
    """There is no undo to run, and inventing one is a second unplanned change to infrastructure."""
    from test_auto_decision import _autonomous_ops, _bundle

    from opsbrain.auto.plan import ChangePlan, ProposedChange, Reversibility

    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("ansible.apply", "common", "drop the old nodes",
                                ops._ansible_hash("common", "web", None),
                                args={"playbook": "common", "limit": "web"}, details={})
    plan = ChangePlan.build(
        objective="drain the old nodes", diagnosis="they hold state nothing else has",
        changes=[ProposedChange(capability="ansible.apply", target="common", how="drain and remove",
                                arguments={"playbook": "common", "limit": "web"},
                                reversible=Reversibility.IRREVERSIBLE, irreversible_reason="state is not "
                                "replicated anywhere else")],
        evidence_refs=[_bundle(ops, tmp_path, change.id)], evidence_bundle=_bundle(ops, tmp_path, change.id),
        targets=["common"], post_checks=["systemctl show logrotate.service"], rollback="",
        preconditions=["drained"], profile="general", created=1_700_000_000.0)
    ops.auto.review_plan(plan)
    ops.auto.decide_change(change.id, plan.id)
    stages = two_host_stages()
    opened = ops.auto.start_rollout(change.id, plan.id, stages, hosts=topology(), strategy="host_groups")
    out = ops.auto.rollback_rollout(opened["id"])
    assert out["rolled_back"] is False
    assert "no reversible undo" in out["reason"], out["reason"]
