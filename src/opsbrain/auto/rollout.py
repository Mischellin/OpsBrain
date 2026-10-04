"""OPS-AUTO-06: canary rollout, with a gate between every stage.

A change that applied cleanly and passed its own checks has still only been proven on itself. The
question a rollout answers is different: *does this hold everywhere it is about to go?* That is answered
by going to one place, looking, and only then going to the next - and by stopping when the looking does
not come out right.

Three properties keep the rollout from becoming a slower, wider version of the thing it is supposed to
protect against:

* **The stage list is fixed when the rollout is created, and re-checked before every promotion.** A
  rollout that can be widened while it runs is not a staged rollout with gates; it is one apply with
  extra steps, and the gates measured something narrower than what was eventually done. `plan_id`,
  `plan_hash`, the preconditions and the stages are all in `stages_digest`, which is compared against
  the stages being run rather than against the record that was stored.
* **A stage is promoted only on facts that were observed for that stage.** A check that did not run, ran
  for too short, or came back `UNKNOWN` stops the rollout, exactly as a `FAIL` does. "No news" and "good
  news" are not the same answer, and the difference is the whole reason the gate exists.
* **A restart resumes; it never re-runs what already happened.** Stage outcomes are durable, and a
  stage is entered under a claim so a second process cannot run the same stage twice.

The canary is chosen from what is actually known about the topology - quorum membership, what depends on
what, and what a stage is allowed to touch - rather than from a host name or a `replica` flag. When
there is no safe canary the answer is that there is none, and the rollout does not start.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ..util import OpsError, digest, new_id, now
from .verify import CheckStatus


class StageState(StrEnum):
    """Where one stage is. There is no state meaning "probably fine"."""

    PENDING = "pending"
    RUNNING = "running"
    PROMOTED = "promoted"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class Stop(StrEnum):
    """Why a rollout stopped. `UNKNOWN` is a stop, never a pass."""

    NONE = "none"
    CHECK_FAILED = "check_failed"
    CHECK_UNKNOWN = "check_unknown"
    POSTFLIGHT_NOT_MET = "postflight_not_met"
    PRECONDITION_FAILED = "precondition_failed"
    STAGES_CHANGED = "stages_changed"
    NO_CANARY = "no_canary"
    NOT_STAGEABLE = "not_stageable"


@dataclass(frozen=True)
class Stage:
    """One stage: the targets it covers, and what must be true before and after it.

    `preconditions` are names, not prose, for the same reason the profile's requirements are names: a
    precondition matched by searching a sentence is not a precondition.
    """

    targets: tuple[str, ...]
    checks: tuple[str, ...] = ()
    preconditions: tuple[str, ...] = ()
    observation_s: float = 0.0
    label: str = ""

    def __post_init__(self) -> None:
        if not self.targets:
            raise OpsError("a stage with no targets covers nothing; it is not a stage")
        if self.observation_s < 0:
            raise OpsError("a stage cannot observe for a negative time")

    def to_dict(self) -> dict[str, Any]:
        return {"targets": list(self.targets), "checks": list(self.checks),
                "preconditions": list(self.preconditions), "observation_s": self.observation_s,
                "label": self.label}

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> Stage:
        return cls(tuple(document.get("targets", ())), tuple(document.get("checks", ())),
                   tuple(document.get("preconditions", ())), float(document.get("observation_s", 0.0) or 0.0),
                   str(document.get("label", "") or ""))


@dataclass(frozen=True)
class Host:
    """What is actually known about one host, as opposed to what its name suggests.

    `quorum_group` and `quorum_size` are what make "take one host" a decision rather than a guess: taking
    a member of a replicated service is only safe while the group keeps a majority, and the group size
    is what says how large a majority is.
    """

    name: str
    quorum_group: str = ""
    quorum_size: int = 0
    #: What this host must be up for, on this host. A canary that something else depends on is not a canary.
    depended_on_by: tuple[str, ...] = ()
    canary_eligible: bool = True
    ineligible_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "quorum_group": self.quorum_group, "quorum_size": self.quorum_size,
                "depended_on_by": list(self.depended_on_by), "canary_eligible": self.canary_eligible,
                "ineligible_reason": self.ineligible_reason}


@dataclass(frozen=True)
class CanaryChoice:
    """The host to try first, or the reason there is not one."""

    host: str = ""
    reason: str = ""

    @property
    def found(self) -> bool:
        return bool(self.host)


#: The fewest members a quorum group may be left with. A majority of one is a single point of failure.
MIN_QUORUM = 2


def select_canary(hosts: dict[str, Host], targets: tuple[str, ...]) -> CanaryChoice:
    """Pick the one host to try first, out of what the topology actually says.

    Four things disqualify a host, and each is a way a "random host" canary takes the service down:

    * it is not eligible by its own account of itself;
    * something else in this rollout depends on it, so a canary failure is not a canary - it is an
      outage for a host that was never asked;
    * taking it drops its quorum group below `MIN_QUORUM`;
    * it is not in this rollout at all.

    A disqualified host is *skipped*, not fatal: a rollout may well have a safe second host, and refusing
    the whole thing because the first name is unlucky would be a rollout that never runs. The refusal
    comes when no host in the rollout qualifies, and it lists why each one did not - an operator who
    cannot make a canary out of their topology needs to know which of the four reasons applied.

    The first eligible host in the rollout's own order wins, so the choice is deterministic and does not
    depend on dictionary iteration order.
    """
    rejected: list[str] = []
    for name in targets:
        host = hosts.get(name)
        if host is None:
            rejected.append(f"{name}: no topology is known about it")
        elif not host.canary_eligible:
            rejected.append(f"{name}: not eligible ({host.ineligible_reason})")
        elif host.depended_on_by:
            rejected.append(f"{name}: depended on by {', '.join(host.depended_on_by)}; taking it down is "
                            "an outage, not a canary")
        elif host.quorum_group and host.quorum_size - 1 < MIN_QUORUM:
            rejected.append(f"{name}: one of {host.quorum_size} members of quorum group "
                            f"{host.quorum_group!r}; taking it leaves fewer than {MIN_QUORUM}")
        else:
            return CanaryChoice(host=name)
    return CanaryChoice(reason="no host in this stage could serve as a canary: " + "; ".join(rejected)
                        if rejected else "the stage names no target that could serve as a canary")


def stageable(capability: str, *, strategy: str = "", stateful: bool = False,
              pod_disruption_budget: str = "", rollout_method: str = "") -> str:
    """Whether this change can be rolled out a stage at a time, and why not when it cannot.

    The three capabilities need different things, and the wrong answer for any of them is the same:
    applying the whole thing and calling it gradual.

    * **Ansible** groups hosts and can walk them. Anything else is not a staged Ansible rollout.
    * **OpenTofu** applies a saved plan as a unit. `-target` selects a subset of the graph for the
      operator's convenience; it does not validate the rest of the plan against the new state, so a
      rollout built from it decides nothing about whether the full apply would have worked.
    * **Kubernetes** depends on the workload. A `StatefulSet` with a read-write-once volume has an
      identity that a second pod cannot stand in for, and a pod disruption budget with `minAvailable` at
      or near the replica count leaves no room for a canary at all. There is no universal canary for an
      arbitrary resource, and claiming one is how a rollout ends up deleting data.
    """
    if capability == "tofu.apply":
        return (f"an OpenTofu plan is not stageable: {strategy or 'the plan'} applies the saved plan as a "
                "unit, and -target does not make it gradual - it only decides less")
    if capability == "ansible.apply":
        if strategy != "host_groups":
            return f"an Ansible rollout advances host groups; {strategy or 'no strategy'} is not one"
        return ""
    if capability == "k8s.apply":
        if stateful:
            return "the workload is stateful, so a second pod is not a stand-in for the first"
        if pod_disruption_budget:
            return (f"pod disruption budget {pod_disruption_budget!r} governs availability during the "
                    "rollout, and a canary would have to satisfy it; the budget is not something this "
                    "rollout can read, so the canary is not something it can promise")
        if rollout_method not in ("rolling", "blue_green", "canary"):
            return f"unknown rollout method {rollout_method!r}; refusing to guess one"
        return ""
    return f"no rollout strategy is defined for capability {capability!r}"


@dataclass
class Rollout:
    """A rollout in progress, and everything needed to argue with it later.

    `stages_digest` covers the stage list, the plan it is bound to and the preconditions, so a rollout
    whose stages were edited mid-flight is a *different* rollout - and `assert_unchanged` compares the
    stages about to be run against the stored digest rather than against the stored record, so editing
    the record and the digest together still fails.
    """

    change_id: str
    plan_id: str
    plan_hash: str
    stages: tuple[Stage, ...]
    canary: str = ""
    created: float = 0.0
    states: list[str] = field(default_factory=list)
    id: str = ""

    def __post_init__(self) -> None:
        if not self.stages:
            raise OpsError("a rollout with no stages is not a rollout")
        if not self.states:
            self.states = [StageState.PENDING.value] * len(self.stages)
        if len(self.states) != len(self.stages):
            raise OpsError("the stored stage states do not match the stages they belong to")
        if not self.id:
            self.id = new_id("ro")

    @property
    def stages_digest(self) -> str:
        return digest({"stages": [stage.to_dict() for stage in self.stages], "plan_id": self.plan_id,
                       "plan_hash": self.plan_hash, "change_id": self.change_id})

    @property
    def current(self) -> int:
        """The index of the first stage that has not been promoted. There is no "skip ahead"."""
        for index, state in enumerate(self.states):
            if state != StageState.PROMOTED.value:
                return index
        return len(self.stages) - 1

    @property
    def complete(self) -> bool:
        return all(state == StageState.PROMOTED.value for state in self.states)

    def state_of(self, index: int) -> StageState:
        return StageState(self.states[index])

    def assert_unchanged(self, stages: tuple[Stage, ...], plan_id: str, plan_hash: str) -> None:
        """Refuse to run a rollout whose shape has moved under it.

        Compared against the arguments, not against the stored digest: a record edited together with its
        own digest would pass a check that reads the record.
        """
        walked = digest({"stages": [stage.to_dict() for stage in stages], "plan_id": plan_id,
                         "plan_hash": plan_hash, "change_id": self.change_id})
        if walked != self.stages_digest:
            raise OpsError(
                f"the stages, plan or preconditions changed since this rollout was created "
                f"({self.stages_digest[:12]} != {walked[:12]}): a rollout that can be widened while it "
                "runs is not a staged rollout, and widening it needs a new one")

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "change_id": self.change_id, "plan_id": self.plan_id,
                "plan_hash": self.plan_hash, "stages": [stage.to_dict() for stage in self.stages],
                "canary": self.canary, "created": round(self.created or now(), 3), "states": list(self.states),
                "stages_digest": self.stages_digest}

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> Rollout:
        rollout = cls(change_id=document["change_id"], plan_id=document["plan_id"],
                      plan_hash=document.get("plan_hash", ""),
                      stages=tuple(Stage.from_dict(item) for item in document.get("stages", ())),
                      canary=document.get("canary", ""), created=float(document.get("created", 0.0) or 0.0),
                      states=list(document.get("states", ())), id=document.get("id", ""))
        # The stored digest is re-derived, never trusted: a record whose stages were edited without its
        # digest is exactly the record `assert_unchanged` exists to catch, and reading the digest off it
        # would have made the check agree with the tampering.
        if document.get("stages_digest") and document["stages_digest"] != rollout.stages_digest:
            raise OpsError(f"rollout {rollout.id} is corrupt: its stages do not match its own digest")
        return rollout


def gate(stage: Stage, report: Any, *, postflight_outcome: str = "") -> tuple[bool, Stop, str]:
    """Whether this stage earned the next one, and why not when it did not.

    `report` is a `VerificationReport`; it is typed loosely for the same reason `postflight` is - naming
    it here would import the module that imports this one.

    Promotion needs three independent things, and any one of them missing is a stop:

    1. the stage's own checks ran, for this stage, and passed;
    2. they watched for at least as long as the stage asked to be observed;
    3. the postflight did not say the goal was missed.

    A report that never ran comes back `NOT_RUN`, and a check that could not reach its target comes back
    `UNKNOWN`. Both stop the rollout, because a stage nobody measured is not a stage that worked.
    """
    if report is None:
        return False, Stop.CHECK_UNKNOWN, f"stage {stage.label or stage.targets[0]!r} produced no report"
    if report.status is CheckStatus.FAIL:
        return False, Stop.CHECK_FAILED, f"the stage's checks reported FAIL: {getattr(report, 'reason', '')}"
    if report.status is not CheckStatus.PASS:
        return False, Stop.CHECK_UNKNOWN, (
            f"the stage's checks reported {report.status.value}, which is not a pass")
    if float(getattr(report, "observation_s", 0.0) or 0.0) < stage.observation_s:
        return False, Stop.CHECK_UNKNOWN, (
            f"the stage asked to be observed for {stage.observation_s:.0f}s and was observed for "
            f"{float(getattr(report, 'observation_s', 0.0) or 0.0):.0f}s")
    if postflight_outcome in ("not_met", "unclear"):
        return False, Stop.POSTFLIGHT_NOT_MET, (
            f"the postflight said the goal was {postflight_outcome} after this stage, so the next one does "
            "not start")
    return True, Stop.NONE, "the stage's checks passed and the postflight did not contradict them"


__all__ = ["CanaryChoice", "Host", "Rollout", "Stage", "StageState", "Stop", "gate", "select_canary",
           "stageable", "MIN_QUORUM"]
