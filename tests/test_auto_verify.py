"""#8 OPS-AUTO-07: deterministic verification of the state a change actually produced.

Most of what follows is negative, and for one reason: a verification that cannot tell "the apply returned
0" from "the system is now in the intended state" is a rubber stamp with a status field. So each test names
the thing that must *not* become a PASS - a green apply whose drop-in landed in the wrong directory, a
binary that ran fine instead of the unit that was actually changed, a 200 that only ever covered one URL,
an unreachable host, a half-reported workload status, a revision that does not belong to the change.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import pytest

from opsbrain.auto.config import AutoConfig
from opsbrain.auto.verify import (
    REGISTRY,
    Check,
    CheckResult,
    CheckStatus,
    Target,
    VerificationReport,
    Verifier,
    drift_repo_live,
    http_target,
    k8s_target,
    overall_status,
    register,
    repo_target,
    storage_target,
    unit_target,
)
from opsbrain.executor import Result
from opsbrain.util import OpsError

UNIT = "logrotate.service"
HOST = "ops"
#: What the change plan said it installed. systemd only reads `<unit>.service.d/`, so this path is the
#: whole difference between "the drop-in is in force" and "a file exists somewhere".
INTENDED_DROP_IN = "/etc/systemd/system/logrotate.service.d/10-ops.conf"
#: Where the file actually landed. It is readable, plausible and *not a drop-in of the unit at all*.
WRONG_DROP_IN = "/etc/logrotate.d/10-ops.conf"
APPLIED = "Sun 2026-10-04 03:00:00 UTC"
HEALTH = "https://example.com/healthz"
#: The name this endpoint is configured under. Verification resolves a plan's URL through
#: `observe.http_checks`; a bare address nobody declared is refused, not contacted.
HEALTH_NAME = "healthz"


class Clock:
    """A clock the test moves, so capture times and observation windows are exact instead of flaky."""

    def __init__(self, at: float = 1_000.0) -> None:
        self.at = at

    def __call__(self) -> float:
        return self.at


def verifier(ops: Any, clock: Clock | None = None, **verify: Any) -> Verifier:
    """A verifier with the observation window switched off.

    The window is a rule about *time* and is exercised on its own in the `observation_window` tests; every
    other test here is about what was observed, and `observation_s=0` keeps it from failing for that reason.
    """
    return Verifier(AutoConfig(enabled=True, verify={"observation_s": 0, **verify}), ops, clock=clock or Clock())


def show(*, active: str = "active", sub: str = "running", drop_ins: str = "", started: str | None = APPLIED) -> str:
    """The `systemctl show` capture. Every field is settable, because the point of these checks is that a
    green apply can leave any one of them wrong while the others look perfect."""
    lines = [f"ActiveState={active}", f"SubState={sub}", "UnitFileState=enabled",
             f"FragmentPath=/lib/systemd/system/{UNIT}", f"DropInPaths={drop_ins}"]
    if started is not None:
        lines.append(f"ExecMainStartTimestamp={started}")
    return "\n".join(lines) + "\n"


def rollout(*, revision: str | None = "7", replicas: int = 3, updated: int = 3, ready: int | None = 3,
            generation: int = 5, observed: int = 5) -> str:
    """A workload `kubectl -o json` document. A `None` field is *absent from the status*, which is the
    partial-data case: it must not collapse into a zero."""
    metadata: dict[str, Any] = {"generation": generation}
    if revision is not None:
        metadata["annotations"] = {"deployment.kubernetes.io/revision": revision}
    status: dict[str, Any] = {"replicas": replicas, "updatedReplicas": updated, "observedGeneration": observed}
    if ready is not None:
        status["readyReplicas"] = ready
    return json.dumps({"metadata": metadata, "spec": {"replicas": replicas}, "status": status})


def status_of(status: CheckStatus) -> CheckResult:
    """A bare result, for testing the status rule itself rather than any one check."""
    return CheckResult(check="x", profile="p", target="t", status=status, captured=0.0, detail="")


def the_unit(host: str = HOST, **overrides: Any) -> Target:
    return unit_target(host, UNIT, **{"drop_in": INTENDED_DROP_IN, **overrides})


# ------------------------------------------------------------------------------------- #8 criterion 1
def test_a_green_apply_with_the_wrong_drop_in_does_not_pass_verification(ops, fake) -> None:  # type: ignore[no-untyped-def]
    """The regression fixture of #8: rc=0 everywhere, the unit is active, and the drop-in is not in force.

    Every signal the plan itself produced is green - the apply exited 0, the binary ran, `is-active` says
    active - and the only thing that notices is the effective drop-in chain. Weaken `systemd:drop-in`,
    drop it from the required set, or make it trust the apply's exit code, and this test goes green.
    """
    fake.on(r"tofu apply", "Apply complete! Resources: 0 added, 1 changed, 0 destroyed.\n")
    fake.on(r"/usr/sbin/logrotate", "rotation written\n")
    fake.on(r"is-active", "active\n")
    fake.on(r"systemctl show", show(drop_ins=WRONG_DROP_IN))

    report = verifier(ops).verify("chg-1", [the_unit()], checks=["systemd:unit-active", "systemd:drop-in"],
                                applied_at=1_000.0)

    assert report.is_pass is False
    assert report.status is CheckStatus.FAIL
    failed = report.with_status(CheckStatus.FAIL)
    assert [result.check for result in failed] == ["systemd:drop-in"]
    assert INTENDED_DROP_IN in failed[0].detail and WRONG_DROP_IN in failed[0].detail
    assert "still not part of the unit" in failed[0].does_not_prove


def test_the_wrong_drop_in_fixture_is_indistinguishable_from_success_to_a_naive_check(ops, fake) -> None:  # type: ignore[no-untyped-def]
    """Why the naive answer cannot be the whole answer: on the fixture above `systemd:unit-active` passes.

    A check that reads only whether the unit is active is satisfied by a unit that was started before the
    change. The pair of results is the point - one green half is not a verification.
    """
    fake.on(r"systemctl show", show(drop_ins=WRONG_DROP_IN))
    report = verifier(ops).verify("chg-1", [the_unit()], checks=["systemd:unit-active", "systemd:drop-in"],
                                applied_at=1_000.0)
    by_check = {result.check: result for result in report.results}
    assert by_check["systemd:unit-active"].status is CheckStatus.PASS
    assert by_check["systemd:drop-in"].status is CheckStatus.FAIL
    assert report.status is CheckStatus.FAIL


def test_a_green_apply_with_nothing_to_verify_is_not_a_verification(ops, fake) -> None:  # type: ignore[no-untyped-def]
    """Nothing ran, so nothing is known. `ok=True` here is how a change with no plan gets waved through."""
    fake.on(r".*", "rc 0\n")
    report = verifier(ops).verify("chg-1", [])
    assert report.status is CheckStatus.NOT_RUN
    assert report.is_pass is False
    assert {result.status for result in report.results} == {CheckStatus.NOT_RUN}
    assert all("was named by the change plan" in result.reason for result in report.results)


# ------------------------------------------------------------------------------------- #8 criterion 2
def test_running_the_binary_directly_does_not_substitute_for_checking_the_unit(ops, fake) -> None:  # type: ignore[no-untyped-def]
    """Executing the thing by hand proves the binary works, not that the unit is in the intended state.

    The fixture is maximally accommodating: the binary exits 0 and a *different* unit is active. The
    verifier still has to ask the unit manager about `logrotate.service`, and it has to find the drop-in
    missing there.
    """
    fake.on(r"/usr/sbin/logrotate", "rotation written\n")
    fake.on(r"is-active", "active\n")
    fake.on(r"systemctl show", show(active="failed", sub="failed", drop_ins=WRONG_DROP_IN))

    report = verifier(ops).verify("chg-1", [the_unit()], checks=["systemd:unit-active", "systemd:drop-in"],
                                applied_at=1_000.0)

    assert report.status is CheckStatus.FAIL
    assert {result.check for result in report.with_status(CheckStatus.FAIL)} == {"systemd:unit-active",
                                                                                "systemd:drop-in"}
    asked = " ".join(script for _, script in fake.calls)
    assert f"systemctl show {UNIT}" in asked, "the unit manager must be asked about the unit that changed"
    assert "/usr/sbin/logrotate" not in asked, "the verifier must not verify by re-running the binary"
    assert all(result.target == f"{HOST}/{UNIT}" for result in report.results)


# ------------------------------------------------------------------------------------- #8 criterion 3
def test_a_successful_http_probe_records_its_boundary_and_observation_window(ops, http) -> None:  # type: ignore[no-untyped-def]
    """A 200 is a narrow, real fact. What it must not be allowed to become is "nothing is broken"."""
    http.codes[HEALTH] = 200
    clock = Clock(1_000.0)
    report = Verifier(AutoConfig(enabled=True), ops, clock=clock).verify(
        "chg-9", [http_target(HEALTH_NAME, HEALTH)], checks=["http:reachable"], applied_at=900.0)

    assert report.status is CheckStatus.PASS
    result = report.results[0]
    assert result.observation_s == 100.0, "the window the claim rests on has to be in the record"
    assert report.observation_s == 100.0
    assert HEALTH in result.proves and "100s" in result.proves
    assert "absence of regressions" in result.does_not_prove
    assert "after the observation window closes" in result.does_not_prove
    assert report.boundary() == {"proves": [result.proves], "does_not_prove": [result.does_not_prove]}
    assert report.brief()["does_not_prove"] == [result.does_not_prove]


def test_an_http_probe_inside_a_too_short_window_is_unknown_not_pass(ops, http) -> None:  # type: ignore[no-untyped-def]
    """A service that answers for two seconds and then dies has not been verified to be up."""
    http.codes[HEALTH] = 200
    clock = Clock(1_010.0)
    early = Verifier(AutoConfig(enabled=True), ops, clock=clock).verify(
        "chg-9", [http_target(HEALTH_NAME, HEALTH)], checks=["http:reachable"], applied_at=1_000.0)
    assert early.status is CheckStatus.UNKNOWN and early.is_pass is False
    assert "observation window too short" in early.results[0].reason
    assert early.results[0].detail.startswith(f"{HEALTH_NAME}:")

    clock.at = 1_040.0  # the same endpoint, once the 30s window has passed
    settled = Verifier(AutoConfig(enabled=True), ops, clock=clock).verify(
        "chg-9", [http_target(HEALTH_NAME, HEALTH)], checks=["http:reachable"], applied_at=1_000.0)
    assert settled.status is CheckStatus.PASS and settled.results[0].observation_s == 40.0

    unmoved = Verifier(AutoConfig(enabled=True), ops, clock=Clock(1_000.0)).verify(
        "chg-9", [http_target(HEALTH_NAME, HEALTH)], checks=["http:reachable"])
    assert unmoved.status is CheckStatus.UNKNOWN, "a plan that recorded no apply time has no window to claim"


def test_an_unreachable_http_endpoint_is_unknown_not_a_failure(ops, http) -> None:  # type: ignore[no-untyped-def]
    """A refused connection and a filtered port look the same from the outside; guessing would be worse."""
    http.codes[HEALTH] = 0
    report = verifier(ops).verify("chg-9", [http_target(HEALTH_NAME, HEALTH)], checks=["http:reachable"],
                                applied_at=1_000.0)
    result = report.results[0]
    assert result.status is CheckStatus.UNKNOWN
    assert "no answer from" in result.reason
    assert report.status is CheckStatus.UNKNOWN


def test_a_failing_http_status_is_a_failure_not_an_unknown(ops, http) -> None:  # type: ignore[no-untyped-def]
    http.codes[HEALTH] = 502
    report = verifier(ops).verify("chg-9", [http_target(HEALTH_NAME, HEALTH)], checks=["http:reachable"],
                                applied_at=1_000.0)
    assert report.status is CheckStatus.FAIL
    assert "HTTP 502" in report.results[0].detail
    http.codes[HEALTH] = 200
    strict = verifier(ops).verify("chg-9", [http_target(HEALTH_NAME, HEALTH, expected_status=204)],
                                 checks=["http:reachable"], applied_at=1_000.0)
    assert strict.status is CheckStatus.FAIL and "the plan expected 204" in strict.results[0].detail


# ------------------------------------------------------------------------------------- #8 criterion 4
def test_an_unknown_target_is_unknown_not_pass(ops, fake) -> None:  # type: ignore[no-untyped-def]
    """An unknown host and an unknown workload are both "I could not look", never "I looked and it was fine"."""
    ghost = verifier(ops).verify("chg-1", [the_unit(host="nosuchhost")], checks=["systemd:unit-active"],
                             applied_at=1_000.0)
    assert ghost.status is CheckStatus.UNKNOWN and ghost.is_pass is False
    assert "unknown host" in ghost.results[0].reason

    fake.on(r"get deployments web", 'Error from server (NotFound): deployments.apps "web" not found\n', rc=1)
    missing = verifier(ops).verify("chg-1", [k8s_target("web", namespace="prod")], checks=["k8s:rollout"],
                                applied_at=1_000.0)
    assert missing.status is CheckStatus.UNKNOWN
    assert "unknown target" in missing.results[0].reason


def test_a_lost_connection_is_unknown_not_pass(ops, fake) -> None:  # type: ignore[no-untyped-def]
    """Two ways of not getting an answer: the host went away, and the capture ran out of time."""
    fake.on(r"systemctl show", "ssh: connect to host ops port 22: No route to host\n", rc=255)
    lost = verifier(ops).verify("chg-1", [the_unit()], checks=["systemd:unit-active"], applied_at=1_000.0)
    assert lost.status is CheckStatus.UNKNOWN
    assert lost.results[0].reason.startswith("connection lost")

    fake.rules.clear()
    fake.on(r"systemctl show", Result(124, "", timed_out=True))
    slow = verifier(ops).verify("chg-1", [the_unit()], checks=["systemd:unit-active"], applied_at=1_000.0)
    assert slow.status is CheckStatus.UNKNOWN
    assert slow.results[0].reason.startswith("timed out")


def test_partial_data_is_unknown_not_pass(ops, fake) -> None:  # type: ignore[no-untyped-def]
    """Half a status is not a rollout of zero replicas, and unparseable output is not a healthy workload."""
    fake.on(r"get deployments web", rollout(ready=None))
    absent = verifier(ops).verify("chg-1", [k8s_target("web", namespace="prod")], checks=["k8s:rollout"],
                              applied_at=1_000.0)
    assert absent.status is CheckStatus.UNKNOWN
    assert "incomplete data" in absent.results[0].reason and "readyReplicas" in absent.results[0].reason

    fake.rules.clear()
    fake.on(r"get deployments web", "not json at all\n")
    garbage = verifier(ops).verify("chg-1", [k8s_target("web", namespace="prod")], checks=["k8s:rollout"],
                               applied_at=1_000.0)
    assert garbage.status is CheckStatus.UNKNOWN and "no usable JSON" in garbage.results[0].reason

    fake.rules.clear()
    fake.on(r"systemctl show", "LoadState=loaded\n")
    trimmed = verifier(ops).verify("chg-1", [the_unit()], checks=["systemd:unit-active"], applied_at=1_000.0)
    assert trimmed.status is CheckStatus.UNKNOWN
    assert "no ActiveState" in trimmed.results[0].reason

    fake.rules.clear()
    fake.on(r"df -Pk /var", "something went wrong\n", rc=1)
    unread = verifier(ops).verify("chg-1", [storage_target("/var", host=HOST, min_free_pct=20)],
                                checks=["storage:capacity"], applied_at=1_000.0)
    assert unread.status is CheckStatus.UNKNOWN
    assert "cannot read the filesystem state" in unread.results[0].reason


def test_an_unknown_revision_is_unknown_not_pass(ops, fake) -> None:  # type: ignore[no-untyped-def]
    """A workload that reports no revision, or somebody else's, is not evidence about this change."""
    fake.on(r"get deployments web", rollout(revision=None))
    anonymous = verifier(ops).verify("chg-7", [k8s_target("web", namespace="prod", expected_revision="7")],
                                   checks=["k8s:rollout"], applied_at=1_000.0)
    assert anonymous.status is CheckStatus.UNKNOWN and anonymous.is_pass is False
    assert "unknown revision" in anonymous.results[0].reason

    fake.rules.clear()
    fake.on(r"get deployments web", rollout(revision="6"))
    stale = verifier(ops).verify("chg-7", [k8s_target("web", namespace="prod", expected_revision="7")],
                                checks=["k8s:rollout"], applied_at=1_000.0)
    assert stale.status is CheckStatus.UNKNOWN
    assert "revision mismatch" in stale.results[0].reason
    assert stale.results[0].revision == "6", "the observed revision is kept even when it is not ours"


# ------------------------------------------------------------------------------------- #8 criterion 5
def test_before_and_after_captures_reveal_the_change(ops, fake) -> None:  # type: ignore[no-untyped-def]
    """The same check, run either side of the apply, has to say different things.

    This is the property that makes the report a measurement rather than a formality: the revision moves
    from nothing to the moment the new configuration took over, and the statuses move with it.
    """
    clock = Clock(1_000.0)
    fake.on(r"systemctl show", show(active="inactive", sub="dead", drop_ins="", started=None))
    before = verifier(ops, clock=clock).verify("chg-1", [the_unit()],
                                              checks=["systemd:unit-active", "systemd:drop-in"],
                                              applied_at=None)
    assert before.status is CheckStatus.FAIL
    assert before.results[0].revision is None, "nothing was running, so there is no revision to report"

    clock.at = 1_040.0
    fake.rules.clear()
    fake.on(r"systemctl show", show(drop_ins=INTENDED_DROP_IN))
    after = verifier(ops, clock=clock).verify("chg-1", [the_unit()],
                                             checks=["systemd:unit-active", "systemd:drop-in"],
                                             applied_at=1_000.0)
    assert after.status is CheckStatus.PASS
    assert after.results[0].revision == APPLIED
    assert after.results[0].revision != before.results[0].revision
    assert after.captured > before.captured


def test_a_regression_after_a_passing_verification_is_detected(ops, fake) -> None:  # type: ignore[no-untyped-def]
    """Nothing about a pass is durable. The same target, the same check, a different answer."""
    fake.on(r"systemctl show", show(drop_ins=INTENDED_DROP_IN))
    first = verifier(ops).verify("chg-1", [the_unit()], checks=["systemd:drop-in"], applied_at=1_000.0)
    assert first.status is CheckStatus.PASS

    fake.rules.clear()
    fake.on(r"systemctl show", show(drop_ins=WRONG_DROP_IN))
    second = verifier(ops).verify("chg-2", [the_unit()], checks=["systemd:unit-active", "systemd:drop-in"],
                                applied_at=2_000.0)
    assert second.status is CheckStatus.FAIL
    assert {result.check for result in second.with_status(CheckStatus.FAIL)} == {"systemd:drop-in"}
    assert second.by_status() == {"PASS": 1, "FAIL": 1}
    assert second.change_id == "chg-2", "a later report is a new fact, not an amendment of the first"


def test_results_are_bound_to_the_applied_change(ops, fake) -> None:  # type: ignore[no-untyped-def]
    """A result is a statement about a change. The change is named, and the revision has to match it."""
    fake.on(r"get deployments web", rollout(revision="7"))
    mine = verifier(ops).verify("chg-7", [k8s_target("web", namespace="prod", expected_revision="7")],
                               checks=["k8s:rollout"], applied_at=1_000.0, evidence_refs=["ev-0000abcd"])
    assert mine.change_id == "chg-7"
    assert mine.results[0].revision == "7"
    assert mine.results[0].target == "web"
    assert mine.evidence_refs == ("ev-0000abcd",), "the evidence the change was judged on travels with it"
    assert "chg-7" in json.dumps(mine.to_dict())

    unbound = verifier(ops).verify("chg-7", [k8s_target("web", namespace="prod")], checks=["k8s:rollout"],
                                applied_at=1_000.0)
    assert unbound.status is CheckStatus.PASS, "a plan that declared no revision is not made to guess one"
    assert unbound.results[0].revision == "7", "the observed revision is recorded either way"

    with pytest.raises(OpsError, match="name the change"):
        verifier(ops).verify("   ", [the_unit()])


def test_every_result_records_target_capture_time_revision_and_evidence(ops, fake) -> None:  # type: ignore[no-untyped-def]
    """The four things a record has to carry, so a verdict is checkable later instead of taken on trust."""
    fake.on(r"systemctl show", show(drop_ins=INTENDED_DROP_IN))
    clock = Clock(1_000.0)
    report = verifier(ops, clock=clock).verify("chg-1", [the_unit()],
                                               checks=["systemd:unit-active", "systemd:drop-in"],
                                               applied_at=900.0, evidence_refs=["ev-0000abcd"])
    assert len(report.results) == 2
    for result in report.results:
        assert result.target == f"{HOST}/{UNIT}"
        assert result.captured == 1_000.0
        assert result.revision == APPLIED
        assert result.evidence_refs and all(ref.startswith("a-") for ref in result.evidence_refs)
        assert result.proves and result.does_not_prove
        assert ops.artifacts.read(result.evidence_refs[0])["id"] == result.evidence_refs[0]
    assert report.evidence_refs == ("ev-0000abcd",)


# ----------------------------------------------------------------------------------------- the contract
def test_the_four_statuses_do_not_collapse_into_a_boolean(ops, fake) -> None:  # type: ignore[no-untyped-def]
    """Four outcomes, and only one of them authorises anything. A boolean would have hidden three."""
    assert [status.value for status in CheckStatus] == ["PASS", "FAIL", "UNKNOWN", "NOT_RUN"]
    fake.on(r"systemctl show", show(active="inactive", sub="dead"))
    failing = verifier(ops).verify("chg-1", [the_unit()], checks=["systemd:unit-active"], applied_at=1_000.0)
    fake.rules.clear()
    fake.on(r"systemctl show", "LoadState=loaded\n")
    unknown = verifier(ops).verify("chg-1", [the_unit()], checks=["systemd:unit-active"], applied_at=1_000.0)
    fake.rules.clear()
    fake.on(r"systemctl show", show(drop_ins=INTENDED_DROP_IN))
    passing = verifier(ops).verify("chg-1", [the_unit()], checks=["systemd:unit-active"], applied_at=1_000.0)
    unrun = verifier(ops).verify("chg-1", [the_unit()], checks=["storage:capacity"])
    statuses = {failing.status, unknown.status, passing.status, unrun.status}
    assert statuses == set(CheckStatus)
    assert [report.is_pass for report in (failing, unknown, passing, unrun)] == [False, False, True, False]
    assert [result.is_pass for result in unrun.results] == [False]


def test_the_overall_status_ranks_fail_over_unknown_over_not_run() -> None:
    """The rule in one place: FAIL dominates, then UNKNOWN, then NOT_RUN; only all-PASS is a PASS."""
    assert overall_status([]) is CheckStatus.NOT_RUN
    assert overall_status([status_of(CheckStatus.PASS), status_of(CheckStatus.PASS)]) is CheckStatus.PASS
    assert overall_status([status_of(CheckStatus.PASS), status_of(CheckStatus.FAIL),
                           status_of(CheckStatus.UNKNOWN)]) is CheckStatus.FAIL
    assert overall_status([status_of(CheckStatus.PASS), status_of(CheckStatus.UNKNOWN),
                           status_of(CheckStatus.NOT_RUN)]) is CheckStatus.UNKNOWN
    assert overall_status([status_of(CheckStatus.PASS), status_of(CheckStatus.NOT_RUN)]) is CheckStatus.NOT_RUN
    # unreachable in practice: `unknown_is_not_pass` cannot be turned off, and even then it never passes
    assert overall_status([status_of(CheckStatus.UNKNOWN)], unknown_is_not_pass=False) is CheckStatus.NOT_RUN


def test_a_required_check_without_a_target_is_not_run(ops) -> None:  # type: ignore[no-untyped-def]
    report = verifier(ops).verify("chg-1", [http_target(HEALTH_NAME, HEALTH)], checks=["systemd:unit-active"])
    result = report.results[0]
    assert result.status is CheckStatus.NOT_RUN
    assert "no systemd target was named" in result.reason
    assert report.status is CheckStatus.NOT_RUN


def test_an_unknown_check_name_is_refused_instead_of_skipped(ops) -> None:  # type: ignore[no-untyped-def]
    """A typo in a policy row must not quietly drop a required check and let the rest of the set pass."""
    with pytest.raises(OpsError, match="unknown verification check: 'systemd:unit-actve'"):
        verifier(ops).verify("chg-1", [the_unit()], checks=["systemd:unit-actve"])
    with pytest.raises(OpsError, match="unknown verification profile: 'systemdd'"):
        verifier(ops).verify("chg-1", [the_unit()], checks=["systemdd"])


def test_the_check_ceiling_is_enforced(ops) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(OpsError, match="the configured limit is 2"):
        verifier(ops, max_checks=2).verify("chg-1", [the_unit()], checks=["systemd"])


def test_profiles_disabled_in_config_run_nothing(ops) -> None:  # type: ignore[no-untyped-def]
    narrow = verifier(ops, profiles=["http"])
    assert narrow.available() == ("http:reachable",)
    assert len(narrow.describe()) == 1 and narrow.describe()[0]["why"]
    with pytest.raises(OpsError, match="unknown verification check"):
        narrow.verify("chg-1", [the_unit()], checks=["systemd:unit-active"])
    unknown_profile = verifier(ops, profiles=["nosuchprofile"])
    assert unknown_profile.available() == ()
    assert unknown_profile.verify("chg-1", [the_unit()]).status is CheckStatus.NOT_RUN


# -------------------------------------------------------------------------------------- state-changing
def test_a_state_changing_check_is_not_run_unless_the_plan_declared_it(ops, fake) -> None:  # type: ignore[no-untyped-def]
    """Starting a service is an action. It must be declared in advance, and refused loudly otherwise."""
    fake.on(r"systemctl start", "")
    fake.on(r"systemctl show", show(drop_ins=INTENDED_DROP_IN))

    refused = verifier(ops).verify("chg-1", [the_unit()], checks=["systemd:unit-start"],
                                declared=["systemd:unit-start"])
    result = refused.results[0]
    assert result.status is CheckStatus.NOT_RUN
    assert "allow_state_changing_checks is false" in result.reason
    assert refused.status is CheckStatus.NOT_RUN
    assert not any("systemctl start" in script for _, script in fake.calls), "nothing may have been started"

    undeclared = verifier(ops, allow_state_changing_checks=True).verify(
        "chg-1", [the_unit()], checks=["systemd:unit-start"], applied_at=1_000.0)
    assert undeclared.results[0].status is CheckStatus.NOT_RUN
    assert "the stored change does not declare it" in undeclared.results[0].reason
    assert not any("systemctl start" in script for _, script in fake.calls)


def test_a_declared_state_changing_check_runs_and_says_that_it_acted(ops, fake) -> None:  # type: ignore[no-untyped-def]
    fake.on(r"systemctl start", "")
    fake.on(r"systemctl show", show(drop_ins=INTENDED_DROP_IN))
    report = verifier(ops, allow_state_changing_checks=True).verify(
        "chg-1", [the_unit()], checks=["systemd:unit-start"], applied_at=1_000.0,
        declared=["systemd:unit-start"])
    result = report.results[0]
    assert report.status is CheckStatus.PASS
    assert result.state_changing is True
    assert "systemctl start" in result.proves
    assert "started logrotate.service" in result.detail
    assert any(f"systemctl start {UNIT}" in script for _, script in fake.calls)

    fake.rules.clear()
    fake.on(r"systemctl start", "Job for logrotate.service failed\n", rc=1)
    failed = verifier(ops, allow_state_changing_checks=True).verify(
        "chg-1", [the_unit()], checks=["systemd:unit-start"], applied_at=1_000.0,
        declared=["systemd:unit-start"])
    assert failed.status is CheckStatus.FAIL
    assert "exited 1" in failed.results[0].detail


def test_only_the_declared_action_is_disguised_as_nothing(ops) -> None:  # type: ignore[no-untyped-def]
    """Every other check is read-only, and says so. `unit-active` must never be the one that starts it."""
    assert [check.name for check in REGISTRY.values() if check.state_changing] == ["systemd:unit-start"]
    assert REGISTRY["systemd:unit-active"].settles is True
    assert REGISTRY["systemd:drop-in"].state_changing is False
    assert {check.profile for check in REGISTRY.values()} == {"systemd", "http", "k8s", "storage", "drift"}


# ---------------------------------------------------------------------------------- other profiles
def test_a_mid_rollout_workload_fails_and_still_records_its_revision(ops, fake) -> None:  # type: ignore[no-untyped-def]
    fake.on(r"get deployments web", rollout(revision="8", replicas=3, updated=1, ready=1, generation=6,
                                           observed=6))
    report = verifier(ops).verify("chg-7", [k8s_target("web", namespace="prod", expected_revision="8")],
                                checks=["k8s:rollout"], applied_at=1_000.0)
    result = report.results[0]
    assert result.status is CheckStatus.FAIL
    assert result.revision == "8", "a failing rollout still has to say which revision it saw"
    assert "1/3 ready" in result.detail and "revision 8" in result.detail
    assert "a scheduling fact" in result.does_not_prove

    fake.rules.clear()
    fake.on(r"get deployments web", rollout(generation=6, observed=5))
    behind = verifier(ops).verify("chg-7", [k8s_target("web", namespace="prod")], checks=["k8s:rollout"],
                               applied_at=1_000.0)
    assert behind.status is CheckStatus.FAIL
    assert "observedGeneration 5/6" in behind.results[0].detail


def test_storage_needs_a_declared_floor_and_then_compares_against_it(ops, fake) -> None:  # type: ignore[no-untyped-def]
    row = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 104857600 20971520 83886080 20% /\n"
    fake.on(r"df -Pk /var", row)
    floorless = verifier(ops).verify("chg-1", [storage_target("/var", host=HOST)], checks=["storage:capacity"],
                                    applied_at=1_000.0)
    assert floorless.status is CheckStatus.UNKNOWN
    assert "no free-space floor" in floorless.results[0].reason

    roomy = verifier(ops).verify("chg-1", [storage_target("/var", host=HOST, min_free_pct=20)],
                                checks=["storage:capacity"], applied_at=1_000.0)
    assert roomy.status is CheckStatus.PASS
    assert "80.0% free" in roomy.results[0].detail

    fake.rules.clear()
    fake.on(r"df -Pk /var", "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                            "/dev/sda1 104857600 99614720 5242880 95% /\n")
    full = verifier(ops).verify("chg-1", [storage_target("/var", host=HOST, min_free_pct=20)],
                              checks=["storage:capacity"], applied_at=1_000.0)
    assert full.status is CheckStatus.FAIL
    assert "required at least 20%" in full.results[0].detail
    assert "the trend" in full.results[0].does_not_prove


def test_drift_compares_the_file_on_the_host_with_the_file_in_the_repo(ops, fake, repo) -> None:  # type: ignore[no-untyped-def]
    (repo / "ansible" / "files").mkdir(parents=True, exist_ok=True)
    (repo / "ansible" / "files" / "motd.conf").write_text("managed by opsbrain\n")
    target = repo_target("ansible/files/motd.conf", "/etc/motd.conf", host=HOST)
    same = hashlib.sha256(b"managed by opsbrain\n").hexdigest()
    fake.on(r"sha256sum /etc/motd.conf", f"{same}  /etc/motd.conf\n")
    matched = verifier(ops).verify("chg-1", [target], checks=["drift:repo-live"], applied_at=1_000.0)
    assert matched.status is CheckStatus.PASS
    assert matched.results[0].revision == same

    fake.rules.clear()
    fake.on(r"sha256sum /etc/motd.conf", f"{'0' * 64}  /etc/motd.conf\n")
    drifted = verifier(ops).verify("chg-1", [target], checks=["drift:repo-live"], applied_at=1_000.0)
    assert drifted.status is CheckStatus.FAIL
    assert "differs from the repo copy" in drifted.results[0].detail
    assert drifted.results[0].target == f"{HOST}/ansible/files/motd.conf"
    assert "one file compared is one file compared" in drifted.results[0].does_not_prove

    fake.rules.clear()
    fake.on(r"sha256sum /etc/motd.conf", "sha256sum: /etc/motd.conf: No such file or directory\n", rc=1)
    vanished = verifier(ops).verify("chg-1", [target], checks=["drift:repo-live"], applied_at=1_000.0)
    assert vanished.status is CheckStatus.UNKNOWN and "incomplete data" in vanished.results[0].reason


def test_drift_needs_both_sides_to_exist(ops) -> None:  # type: ignore[no-untyped-def]
    """A comparison with nothing to compare against is UNKNOWN, not "no drift"."""
    local = verifier(ops).verify("chg-1", [repo_target("ansible/files/motd.conf", "/etc/motd.conf", host="")],
                               checks=["drift:repo-live"], applied_at=1_000.0)
    assert local.status is CheckStatus.UNKNOWN and "needs a live host" in local.results[0].reason
    missing_repo = verifier(ops).verify("chg-1", [repo_target("nope/nope.conf", "/etc/nope.conf", host=HOST)],
                                   checks=["drift:repo-live"], applied_at=1_000.0)
    assert missing_repo.status is CheckStatus.UNKNOWN
    assert "cannot read the repo copy" in missing_repo.results[0].reason


# --------------------------------------------------------------------------------------------- reports
def test_the_report_carries_the_change_the_boundary_and_what_is_still_outstanding(ops, fake) -> None:  # type: ignore[no-untyped-def]
    fake.on(r"systemctl show", show(drop_ins=WRONG_DROP_IN))
    report = verifier(ops).verify("chg-1", [the_unit()], checks=["systemd:unit-active", "systemd:drop-in"],
                                applied_at=1_000.0, evidence_refs=["ev-0000abcd"])
    document = report.to_dict()
    assert document["change_id"] == "chg-1"
    assert document["status"] == "FAIL" and document["is_pass"] is False
    assert document["by_status"] == {"PASS": 1, "FAIL": 1}
    assert document["evidence_refs"] == ["ev-0000abcd"]
    assert document["does_not_prove"] == report.boundary()["does_not_prove"]
    assert len(document["results"]) == 2
    brief = report.brief()
    assert brief["status"] == "FAIL" and brief["checks"] == 2
    assert [row["check"] for row in brief["outstanding"]] == ["systemd:drop-in"]
    assert "is not in the effective drop-in chain" in brief["outstanding"][0]["detail"]
    assert brief["outstanding"][0]["reason"] == "", "a FAIL is an answer, not an absence of one"
    assert "does_not_prove" in brief


def test_a_registered_check_is_replaceable_and_keeps_its_declaration() -> None:
    """A deployment overrides a check without editing the Verifier - and the override has to declare itself."""
    original = REGISTRY["storage:capacity"]
    try:  # the registry is module-global: a failed assertion must not leave the override behind
        replacement = register(Check("storage:capacity", "storage", drift_repo_live, why="temporary override"))
        assert replacement is REGISTRY["storage:capacity"] and replacement is not original
        assert replacement.why == "temporary override" and replacement.settles is False
        assert replacement.profile == original.profile
    finally:
        register(original)
    assert REGISTRY["storage:capacity"] is original


def test_targets_name_what_they_expect_so_a_check_can_refuse_to_guess() -> None:
    """An expectation is what turns a measurement into a verdict; a target without one says so."""
    assert unit_target(HOST, UNIT, drop_in=INTENDED_DROP_IN).expect("drop_in") == INTENDED_DROP_IN
    assert unit_target(HOST, UNIT).expect("drop_in") is None
    assert k8s_target("web", namespace="prod").expect("namespace") == "prod"
    assert storage_target("/var", min_free_pct=20).expect("min_free_pct") == "20"
    assert http_target(HEALTH_NAME, HEALTH).label == HEALTH_NAME
    assert unit_target(HOST, UNIT).label == f"{HOST}/{UNIT}"
    assert Target("unit", UNIT).expected == ()


def test_verification_report_is_immutable_so_a_result_cannot_be_edited_after_the_fact() -> None:
    report = VerificationReport(change_id="chg-1", status=CheckStatus.NOT_RUN, results=(), captured=1.0)
    with pytest.raises(Exception):  # noqa: B017 - frozen dataclasses raise FrozenInstanceError
        report.status = CheckStatus.PASS  # type: ignore[misc]
    assert report.boundary() == {"proves": [], "does_not_prove": []}
    assert report.by_status() == {}


# ------------------------------------------------------------------------------ wiring into the service
def _service(tmp_path: Any) -> Any:
    from opsbrain.auto.service import AutoService
    from opsbrain.config import Config

    return AutoService(Config(repo=str(tmp_path), data_dir=str(tmp_path / "data"),
                              auto=AutoConfig(enabled=True)))


def test_verification_is_bound_to_a_core_only_by_the_owner(tmp_path: Any) -> None:
    from opsbrain.util import OpsError

    auto = _service(tmp_path)
    assert auto.verify_overview() == {"bound": False}
    with pytest.raises(OpsError, match="needs a Core"):
        auto.verifier()


def test_core_binds_itself_so_verification_is_available(tmp_path: Any) -> None:
    from opsbrain.config import Config
    from opsbrain.service import OpsBrain

    ops = OpsBrain(Config(repo=str(tmp_path), data_dir=str(tmp_path / "data"),
                          auto=AutoConfig(enabled=True)))
    view = ops.auto.verify_overview()
    assert view["bound"] is True
    assert view["observation_s"] == 30
    assert "systemd:unit-active" in view["available"]
    assert ops.auto.verification_checks(), "the tool surface must say what it can demand"


def test_verification_cannot_act_by_default(tmp_path: Any) -> None:
    from opsbrain.config import Config
    from opsbrain.service import OpsBrain

    ops = OpsBrain(Config(repo=str(tmp_path), data_dir=str(tmp_path / "data"),
                          auto=AutoConfig(enabled=True)))
    assert ops.auto.verify_overview()["allow_state_changing_checks"] is False
    acting = [row["check"] for row in ops.auto.verification_checks() if row["state_changing"]]
    assert acting == ["systemd:unit-start"]


def test_verifying_through_a_disabled_service_is_refused(tmp_path: Any) -> None:
    from opsbrain.auto.service import AutoService
    from opsbrain.auto.verify import unit_target
    from opsbrain.config import Config
    from opsbrain.util import OpsError

    auto = AutoService(Config(repo=str(tmp_path), data_dir=str(tmp_path / "data"),
                             auto=AutoConfig(enabled=False)))
    with pytest.raises(OpsError, match="disabled"):
        auto.verify_change("c-11111111", [unit_target("web-1", "logrotate.service")])


# ============================== P1 round 2 on #17: findings against the verification fixes themselves
def test_an_option_like_unit_name_is_refused(ops, fake) -> None:  # type: ignore[no-untyped-def]
    """`-` turns the name into an option for systemctl, and shlex.quote does not change that."""
    fake.on(r"systemctl show", show())
    report = verifier(ops).verify("chg-1", [unit_target(HOST, "--now")], checks=["systemd:unit-active"],
                               applied_at=1_000.0)
    assert report.is_pass is False
    assert "invalid unit name" in report.results[0].reason
    assert not any("systemctl" in script for _, script in fake.calls), "nothing was executed"


@pytest.mark.parametrize("kind", ["deployment", "deployments"])
def test_a_real_resource_type_reaches_kubectl_unchanged(ops, fake, kind) -> None:  # type: ignore[no-untyped-def]
    fake.on(f"get {re.escape(kind)} api", rollout(revision="7"))
    verifier(ops).verify("chg-1", [k8s_target("api", kind=kind, expected_revision="7")],
                        checks=["k8s:rollout"], applied_at=1_000.0)
    assert any(f"get {kind} api" in script for _, script in fake.calls), \
        "the resource type the plan asked for is the one kubectl received"


@pytest.mark.parametrize("kind", ["apps/v1", "deployment.apps", "deploymnt"])
def test_an_unsupported_kind_is_refused_before_anything_runs(ops, fake, kind) -> None:  # type: ignore[no-untyped-def]
    fake.on(r"get ", rollout())
    report = verifier(ops).verify("chg-1", [k8s_target("api", kind=kind)], checks=["k8s:rollout"],
                               applied_at=1_000.0)
    assert report.is_pass is False
    assert "unsupported workload kind" in report.results[0].reason
    assert not fake.calls, "nothing was sent to the cluster"


def test_a_profile_and_its_member_select_one_check_not_two(ops, fake) -> None:  # type: ignore[no-untyped-def]
    """`['systemd', 'systemd:unit-start']` is one request written twice, and a state-changing check is an
    action: running it twice is a second action nobody planned."""
    fake.on(r"systemctl show", show())
    fake.on(r"systemctl start", "")
    selected = verifier(ops).select(["systemd", "systemd:unit-start"])
    assert [check.name for check in selected].count("systemd:unit-start") == 1
    assert len(verifier(ops).select(["systemd", "systemd:unit-active"])) == len(
        verifier(ops).select(["systemd"])), "asking for a profile and a member is the same request twice"


def test_a_deployment_manifest_is_not_persisted_with_its_environment(ops, fake, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Inline env values are routinely credentials, and a verification artifact is not a secrets store."""
    document = json.loads(rollout(revision="7"))
    document["spec"]["template"] = {"spec": {"containers": [
        {"name": "api", "env": [{"name": "LICENSE", "value": "ghp_" + "e" * 36}]}]}}
    fake.on(r"get deployments api", json.dumps(document))
    report = verifier(ops).verify("chg-1", [k8s_target("api", expected_revision="7")], checks=["k8s:rollout"],
                               applied_at=1_000.0)
    stored = "".join(path.read_text(encoding="utf-8", errors="replace")
                     for path in tmp_path.rglob("*.json") if path.is_file())
    assert "ghp_" not in stored, "a credential from the manifest reached a stored artifact"
    assert "e" * 36 not in stored
    assert report.status is not None
