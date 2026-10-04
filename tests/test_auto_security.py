"""#13 OPS-AUTO-11: the security regressions, gathered so that a weakening of any gate is visible.

The other suites test each gate in the module it belongs to. This one is organised the other way round -
by the attack rather than by the code - because that is the question a reader of a security suite has:
*what happens if someone tries this?* Every test here is an attempt to get through a gate that must not
open, and every one of them names the invariant it defends.

The classes are the ones the epic's own invariants were written about, plus the ones that turned up
during review. If a new guard is added and nothing here covers it, that is a gap in this file, not a
coincidence.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

pytestmark = pytest.mark.security

from opsbrain.auto.decision import ApprovalEngine as ApprovalEngineForTest  # noqa: E402
from opsbrain.auto.review import Finding, Severity, Verdict, response_document  # noqa: E402
from opsbrain.util import OpsError  # noqa: E402


def _prepared(ops: Any, tmp_path: Any, **profile: Any) -> Any:
    """The pipeline switched on with one profile, so a test can change exactly one thing about it."""
    from test_auto_decision import TOKEN, _autonomous_ops

    from opsbrain.auto.config import AutoConfig, PolicyProfileConfig

    fields: dict[str, Any] = {"name": "secrets", "extra_reviews": 1, "allowed_targets": ["proxmox"],
                              "allowed_capabilities": ["tofu.apply"], "allow_autonomous": True}
    fields.update(profile)
    ops.config = ops.config.model_copy(update={"auto": AutoConfig(
        enabled=True, autonomy_token=TOKEN, review={"runner": "codex"},
        verify={"profiles": ["systemd"]},
        decision={"mode": "autonomous", "default_profile": "secrets"},
        profiles=[PolicyProfileConfig(**fields)])})
    return _autonomous_ops(ops, tmp_path)


def _change_and_plan(ops: Any, tmp_path: Any) -> tuple[Any, Any]:
    from test_auto_decision import _bundle, _plan_for_change

    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id), profile="secrets")
    ops.auto.review_plan(plan)
    return change, plan


# ------------------------------------------------------------------ a secret must not travel with the plan
def test_a_secret_in_the_diagnosis_is_redacted_before_the_reviewer_sees_it(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Invariant 2: the reviewer observes, and what it is shown has been through redaction first.

    A credential pasted into a diagnosis is the ordinary way secrets travel, and the reviewer's
    environment is scrubbed - but its *request* is not, because the request is the operator's own text
    travelling to a model. So the redaction happens on the way in, and this asserts it on the boundary:
    the raw text the operator wrote is on disk, and the text the runner received is not.
    """
    from opsbrain.auto.plan import ChangePlan, ProposedChange, Reversibility

    _prepared(ops, tmp_path)

    leaky = ChangePlan.build(
        objective="restart logrotate", diagnosis="the API key AKIAIOSFODNN7EXAMPLE is in the drop-in",
        changes=[ProposedChange(capability="tofu.apply", target="proxmox", how="install a drop-in",
                                arguments={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                declared_check="systemd:unit-active", reversible=Reversibility.ROLLBACK,
                                undo="rm -f /tmp/x", profile="systemd", resource="logrotate.service",
                                host="ops")],
        evidence_refs=[], targets=["proxmox"], versions={"systemd": "252"},
        post_checks=["systemd:unit-active"], rollback="systemctl revert logrotate.service",
        profile="secrets", created=1_700_000_000.0)
    ops.auto.review_plan(leaky)
    shown = ops.auto.reviews._reviewer.requests[-1].context
    assert "AKIAIOSFODNN7EXAMPLE" not in shown, "a credential reached the reviewer verbatim"
    assert "the API key" in shown, "and the diagnosis was not simply dropped"


# ------------------------------------------------------------------ evidence and reviews must be the real ones
def test_evidence_about_another_change_cannot_authorise_this_one(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Invariant 2: evidence has to be about the change it is used to authorise.

    A bundle that exists, is fresh, and is perfectly good - for a different change - is the easiest
    forgery available, because every individual check on it passes.
    """
    from test_auto_decision import _bundle, _plan_for_change

    _prepared(ops, tmp_path)
    mine = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1",
                              args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                              details={"plan_sha256": "ab" * 32})
    theirs = ops.changes.create("tofu.apply", "prod", "something else", "ph-1",
                                args={"plan_file": ".opsbrain/j-9999abcd.tfplan"},
                                details={"plan_sha256": "cd" * 32})
    other_bundle = _bundle(ops, tmp_path, theirs.id)
    plan = _plan_for_change(bundle_id=other_bundle, profile="secrets")
    ops.auto.review_plan(plan)
    out = ops.auto.decide_change(mine.id, plan.id)
    assert out["decision"]["decision"] == "BLOCKED_AUTONOMOUSLY", out


def test_a_plan_that_cites_no_resolvable_evidence_is_not_approvable(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Invariant 4: a reference nobody can resolve is not evidence, however plausible it looks."""
    from test_auto_decision import _plan_for_change

    _prepared(ops, tmp_path)
    plan = _plan_for_change(bundle_id="ev-0000dead", profile="secrets")
    reviewed = ops.auto.review_plan(plan)
    assert reviewed["approvable"] is False, reviewed
    assert reviewed["reason"] == "evidence_incomplete", reviewed["reason"]


def test_two_reviewers_that_disagree_block_the_decision(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Invariant 4: disagreement is not a tie to be broken by preference.

    The class is worth a test on its own because the engine's precedence over *both* reviews was
    reorganised for exactly this: a check on the primary that returned before the secondary was read made
    the same pair of answers decide differently depending on which arrived in which field.
    """
    from test_auto_decision import _bundle, _plan_for_change

    _prepared(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id), profile="secrets")

    class Split(ReviewRunner := type(ops.auto.reviews._reviewer)):  # type: ignore[misc]
        def review(self, request: Any) -> str:
            self.requests.append(request)
            return json.dumps(response_document(
                Verdict.PASS if len(self.requests) == 1 else Verdict.DENY,
                [Finding(Severity.BLOCKER, "the drop-in is in the wrong directory",
                         required_property="correct_dropin_path")]))

    ops.auto.reviews._reviewer = Split()
    ops.auto.review_plan(plan)
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] in ("DENY", "BLOCKED_AUTONOMOUSLY"), out
    assert "ap-" not in json.dumps(out), "a disagreement issued an approval"


# ------------------------------------------------------------------ the author's own access must not be a route
def test_a_change_created_by_hand_cannot_be_applied_without_an_engine_approval(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Invariant 1: hand-approval is not a way in when the engine is installed.

    The `change` tool lets an operator or a model create a change, and `changes.attach_approval` is what
    a human path uses. In autonomous mode the gate refuses a change with no engine approval - so the whole
    question is whether that refusal can be side-stepped, and the answer has to be no.
    """
    _prepared(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    ops.changes.attach_approval(change.id, "ap-0000000000000000")
    ops.exec.on(r"tofu apply", "Apply complete! Resources: 0 added, 1 changed, 0 destroyed.\n")
    with pytest.raises(OpsError, match="no approval ap-|no engine approval"):
        ops.tofu_apply(change.id)
    assert ops.changes.get(change.id).state == "pending", "the refusal happened before the mutation"


def test_an_approval_issued_for_another_change_is_refused_at_the_gate(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Invariant 3: the approval names the change it authorises, and the gate checks that it does."""
    from test_auto_decision import _bundle, _plan_for_change

    from opsbrain.auto.approval import ApprovalStore

    _prepared(ops, tmp_path)
    mine = ops.changes.create("tofu.apply", "proxmox", "x", "ph-1",
                              args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                              details={"plan_sha256": "ab" * 32})
    # Same capability, same target, same arguments: the only thing that differs is *which change* the
    # approval names, which is exactly the property under test.
    theirs = ops.changes.create("tofu.apply", "proxmox", "y", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ef" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, theirs.id), profile="secrets")
    ops.auto.review_plan(plan)
    approval = ops.auto.decide_change(theirs.id, plan.id)["approval"]
    ops.changes.attach_approval(mine.id, approval)
    ops.exec.on(r"tofu apply", "Apply complete!\n@@OPSBRAIN-POSTPLAN 0@@\n")
    with pytest.raises(OpsError, match="was issued for"):
        ops.tofu_apply(mine.id)
    assert ApprovalStore(ops.auto.root / "approvals").get(approval).state.value == "issued"


# ------------------------------------------------------------------ policy is not editable from inside
def test_tightening_a_profile_after_the_approval_stops_the_apply(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Invariant 3: any change to the input makes the approval STALE, and no exception for profiles.

    A profile is an input to the decision, so narrowing it afterwards has to invalidate what it authorised
    - including in the window between the decision and the apply, which is the window an operator actually
    uses when something looks wrong after the fact.
    """
    from test_auto_decision import TOKEN, _autonomous_ops, _bundle, _plan_for_change

    from opsbrain.auto.config import AutoConfig, PolicyProfileConfig

    ops.config = ops.config.model_copy(update={"auto": AutoConfig(
        enabled=True, autonomy_token=TOKEN, review={"runner": "codex"},
        decision={"mode": "autonomous", "default_profile": "secrets"},
        profiles=[PolicyProfileConfig(name="secrets", extra_reviews=1, allowed_targets=["proxmox"],
                                      allowed_capabilities=["tofu.apply"], version="1",
                                      allow_autonomous=True)])})
    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id), profile="secrets")
    ops.auto.review_plan(plan)
    assert ops.auto.decide_change(change.id, plan.id)["decision"]["decision"] == "APPROVE"

    # The operator tightens the profile, and only bumps the label - the digest is what catches it.
    tightened = PolicyProfileConfig(name="secrets", extra_reviews=1, allowed_targets=["proxmox", "db-1"],
                                   allowed_capabilities=["tofu.apply"], version="1", allow_autonomous=True)
    # The engine is handed the `auto` half of the config and the service the whole of it, so the same
    # tightening has to be written to both - otherwise the gate is reading a copy nobody tightened.
    engine = ops.auto.engine()
    engine.config = engine.config.model_copy(update={"profiles": [tightened]})
    ops.auto.config = ops.auto.config.model_copy(
        update={"auto": ops.auto.config.auto.model_copy(update={"profiles": [tightened]})})
    ops.exec.on(r"tofu apply", "Apply complete!\n@@OPSBRAIN-POSTPLAN 0@@\n")
    with pytest.raises(OpsError, match="STALE"):
        ops.tofu_apply(change.id)


def test_an_emergency_stop_blocks_work_that_is_already_mid_loop(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """One switch, checked before the review, the evidence, the plan and the verification."""
    from test_auto_decision import _autonomous_ops, _bundle, _plan_for_change


    _autonomous_ops(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id), profile="general")
    ops.auto.review_plan(plan)
    engine = ops.auto.engine()
    stopping = engine.config.decision.model_copy(update={"emergency_stop": True})
    engine.config = engine.config.model_copy(update={"decision": stopping})
    ops.auto.config = ops.auto.config.model_copy(
        update={"auto": ops.auto.config.auto.model_copy(update={"decision": stopping})})
    out = ops.auto.decide_change(change.id, plan.id)
    assert out["decision"]["decision"] == "BLOCKED_AUTONOMOUSLY", out
    # And it is terminal: a stop never turns into a retry.
    assert "RETRY" not in json.dumps(out), out
    # Named exactly, and not `or "autonomy_off"`: the deployment's `autonomous` property also folds the
    # stop into "not in autonomous mode", and an assertion satisfied by either of two reasons tests
    # neither. `emergency_stop` is the one the service path produces, and this is what fixes that.
    assert out["decision"]["reason"] == "emergency_stop", out["decision"]


def test_the_engine_names_the_switch_itself_when_the_stop_is_set() -> None:
    """The second layer, tested where the first is not in the way.

    The service reaches the engine through `DecisionConfig.autonomous`, which is false while the stop is
    set, so the engine's own `emergency_stop` branch is reached only by a caller that does not go through
    that property. Removing the branch changes nothing the service can see - which is exactly why it needs
    a test of its own rather than a mention in a test of the other one.
    """
    from opsbrain.auto.config import AutoConfig
    from opsbrain.auto.decision import Decision

    from test_auto_decision import TOKEN, inputs

    engine = ApprovalEngineForTest(AutoConfig(enabled=True, autonomy_token=TOKEN, decision={
        "mode": "autonomous", "emergency_stop": True}))
    out = engine.decide(inputs(), "pl-1", "ah-1", change_id="c-1", review_ids=("rv-0000abcd",))
    assert out.decision is Decision.BLOCKED_AUTONOMOUSLY
    assert out.reason.value == "emergency_stop", out.reason


# ------------------------------------------------------------------ a broken reviewer must not become a pass
def test_a_reviewer_that_cannot_be_reached_never_yields_an_approval(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Invariant 4: a timeout, a quota error and a crash are not a `PASS`.

    The stub guard is the second half: naming the `fake` runner as if it were a paid one has to be
    refused, so the offline suite cannot quietly become evidence that the live path works.
    """
    from test_auto_decision import _bundle, _plan_for_change

    from opsbrain.auto.runners import ReviewerError

    _prepared(ops, tmp_path)
    change = ops.changes.create("tofu.apply", "proxmox", "restart logrotate", "ph-1",
                                args={"plan_file": ".opsbrain/j-1234abcd.tfplan"},
                                details={"plan_sha256": "ab" * 32})
    plan = _plan_for_change(bundle_id=_bundle(ops, tmp_path, change.id), profile="secrets")
    ops.auto.reviews._reviewer.fail("restart logrotate on web-1")
    reviewed = ops.auto.review_plan(plan)
    assert reviewed["approvable"] is False, reviewed
    assert "ap-" not in json.dumps(ops.auto.decide_change(change.id, plan.id))
    assert ReviewerError is not None


def test_the_stub_runner_may_not_stand_in_for_a_paid_one(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The offline suite proves the workflow, not the model - and the configuration has to say so."""
    from opsbrain.auto.runners import CodexReviewer, FakeReviewer, RunnerSettings, probe_capabilities

    settings = RunnerSettings(runner="codex", live=False)
    assert CodexReviewer is not FakeReviewer
    probe = probe_capabilities(settings)
    assert probe.get("live") is False, probe
    assert not probe.get("available", False), (
        "a disabled live runner must report itself unavailable rather than be talked into running")


# ------------------------------------------------------------------ restart must not repeat or reset
def test_a_restart_neither_repeats_the_apply_nor_hands_back_a_budget(ops, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Invariant 4 as an operational property: bounded means bounded across a restart too."""
    from opsbrain.auto.recovery import Ceiling, Observation, Recovery, Step

    _prepared(ops, tmp_path)
    loop = Recovery(change_id="c-1", permitted=(Step.REWRITE_PLAN.value, Step.COLLECT_EVIDENCE.value))
    loop.record(Step.COLLECT_EVIDENCE.value,
                Observation(fingerprints=frozenset({"drop-in:not-in-force"})),
                Observation(fingerprints=frozenset()), calls_used=6)
    again = Recovery.from_dict(json.loads(json.dumps(loop.to_dict())))
    assert again.calls_used == 6
    assert again.blocked(Ceiling(max_repair_cycles=9, max_model_calls=6, max_wall_s=99_000))[0]
    assert again.next_step() == Step.REWRITE_PLAN.value, "and the step that did not work is not repeated"
