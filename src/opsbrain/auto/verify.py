"""Deterministic verification of the state a change actually produced.

A green apply is a claim about the *intent* of a command, not a fact about a host. The unit may still be
running the old drop-in, the workload may still be on the previous revision, and the file on the box may
never have been the file in the repo. This module re-derives the state from the target itself and answers
with one of four statuses, never with a boolean:

* `PASS` - the objective and the control invariants were observed on the target;
* `FAIL` - they were observed to be untrue. This is the only answer that may block, and it is a real
  answer, not a guess;
* `UNKNOWN` - the target could not be reached, the data was incomplete, the revision could not be bound to
  the change, or the observation window was too short to claim a settled system. `UNKNOWN` is never a
  pass: `VerifyConfig.unknown_is_not_pass` exists so that a check which cannot be evaluated cannot
  authorise anything, and the Verifier downgrades a premature `PASS` to `UNKNOWN` rather than trust it;
* `NOT_RUN` - a required check never executed, because no target was named or because it would have
  changed state without the plan having declared it. Nothing was observed, so nothing may be concluded.

Two rules carry most of the weight:

* **The boundary of a check is part of its result.** Every result says what it `proves` and, just as
  important, what it `does_not_prove`. One `200` says nothing about the endpoints that were not asked,
  about the logs, or about a crash five minutes after the window closed. A check that cannot state its
  boundary is a check whose verdict will be over-read.
* **Verification observes, it does not repair.** A check that would have to *start* something to answer
  (`systemd:unit-start`) carries `state_changing=True` and is refused unless the change plan declared it
  and `VerifyConfig.allow_state_changing_checks` allows it. The read-only check is a different check, so
  "is it running?" can never quietly become "make it running".

Results are bound to the change that produced them: the report carries the `change_id`, and every result
carries the target, the capture time, the revision that was effective at capture time and the evidence
ids behind it. A check that cannot confirm which change it belongs to answers `UNKNOWN`.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..result import Result
from ..util import OpsError, clip, now
from .config import AutoConfig, VerifyConfig

if TYPE_CHECKING:  # `core` imports this package; keep the edge one-directional
    from ..core import Core

_SSH_TIMEOUT = 20.0
_HTTP_TIMEOUT = 10.0
_START_TIMEOUT = 90.0

#: A leading `-` turns the name into an option for systemctl rather than a unit name, and the character
#: class deliberately excludes it even though the rest of a unit name is more permissive than it looks.
_UNIT = re.compile(r"^(?![-])([A-Za-z0-9@_.:-]{1,120})$")
_ABS_PATH = re.compile(r"^/[A-Za-z0-9._/@:+-]{1,240}$")
_PURE_NUMBER = re.compile(r"^(100|[1-9]?[0-9])$")
_DIGEST = re.compile(r"\b([0-9a-f]{64})\b")
_NOT_FOUND = re.compile(r"\bNotFound\b")

#: The `systemctl show` view the systemd checks reason about. The effective state and the effective
#: configuration are read from the same capture on purpose: "active" and "running the drop-in we installed"
#: are two halves of one fact, and a check that reads only the first half can be satisfied by a stale unit.
_UNIT_PROPERTIES = "ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,ExecMainStartTimestamp"

_K8S_REVISION_ANNOTATION = "deployment.kubernetes.io/revision"

#: A target's `kind` decides which profile can look at it. An unmapped kind is matched by no check, so it
#: shows up in the report as a NOT_RUN gap rather than as an unexamined pass.
KIND_PROFILES = {
    "unit": "systemd",
    "http": "http",
    "k8s": "k8s",
    "storage": "storage",
    "repo": "drift",
}


class CheckStatus(StrEnum):
    """Four answers, deliberately not a boolean: `not yet known` and `never looked` are not success."""

    PASS = "PASS"  # noqa: S105 - a status label, not a credential
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_RUN = "NOT_RUN"


@dataclass(frozen=True)
class Target:
    """One thing to look at, plus the expectation the plan attached to it.

    `expected` carries what the plan promised (the drop-in path, a free-space floor, the live path of a
    file) and `expected_revision` what it claims is now in effect. Without the expectation a check can
    only measure, and a measurement is not a verdict.
    """

    kind: str
    name: str
    host: str = ""
    expected: tuple[tuple[str, str], ...] = ()
    expected_revision: str | None = None

    @property
    def label(self) -> str:
        """How the target is named in every record: the host is part of what was verified."""
        return f"{self.host}/{self.name}" if self.host else self.name

    def expect(self, key: str) -> str | None:
        return dict(self.expected).get(key)


def unit_target(host: str, unit: str, *, drop_in: str | None = None,
                expected_revision: str | None = None) -> Target:
    """A systemd unit on a host, optionally with the drop-in the plan said it installed."""
    return Target("unit", unit, host, (("drop_in", drop_in),) if drop_in else (), expected_revision)


def http_target(name: str, url: str, *, expected_status: int | None = None) -> Target:
    """A URL the plan promised would answer."""
    expected: tuple[tuple[str, str], ...] = (("url", url),)
    if expected_status is not None:
        expected += (("status", str(expected_status)),)
    return Target("http", name, "", expected)


def k8s_target(name: str, *, namespace: str = "default", kind: str = "deployments",
               expected_revision: str | None = None, expected_replicas: int | None = None) -> Target:
    """A workload whose rollout and revision the change is judged on.

    `expected_replicas` is the count the plan asked for. A scale change that reached the count the
    cluster was already at has not demonstrated anything, and only the plan knows the difference.
    """
    expectations: tuple[tuple[str, str], ...] = (("namespace", namespace), ("kind", kind))
    if expected_replicas is not None:
        expectations += (("replicas", str(expected_replicas)),)
    return Target("k8s", name, "", expectations, expected_revision)


def storage_target(path: str, *, host: str = "", min_free_pct: int | None = None) -> Target:
    """A filesystem, with the free-space floor the plan assumed before touching it."""
    return Target("storage", path, host, (("min_free_pct", str(min_free_pct)),) if min_free_pct is not None
                  else ())


def repo_target(repo_path: str, live_path: str, *, host: str) -> Target:
    """A file in the repo and the path it is expected to occupy on `host`."""
    return Target("repo", repo_path, host, (("path", live_path),))


@dataclass(frozen=True)
class CheckResult:
    """One outcome, carrying everything a later reader needs to not take it on trust.

    `revision` is what makes the observation attributable: the k8s revision, the moment a unit's current
    configuration took over, the digest of the file on disk. `observation_s` is how long the check watched
    before claiming anything, because "it is up" and "it has been up since the change" are different claims.
    """

    check: str
    profile: str
    target: str
    status: CheckStatus
    captured: float
    detail: str
    revision: str | None = None
    evidence_refs: tuple[str, ...] = ()
    state_changing: bool = False
    observation_s: float = 0.0
    proves: str = ""
    does_not_prove: str = ""
    reason: str = ""

    @property
    def is_pass(self) -> bool:
        """The only value a decision engine may act on. `UNKNOWN` and `NOT_RUN` are both False."""
        return self.status is CheckStatus.PASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check, "profile": self.profile, "target": self.target, "status": self.status.value,
            "captured": round(self.captured, 3), "revision": self.revision, "detail": self.detail,
            "evidence_refs": list(self.evidence_refs), "state_changing": self.state_changing,
            "observation_s": self.observation_s, "proves": self.proves, "does_not_prove": self.does_not_prove,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class VerificationReport:
    """The answer for one change: many outcomes, one status, and the change they belong to."""

    change_id: str
    status: CheckStatus
    results: tuple[CheckResult, ...]
    captured: float
    evidence_refs: tuple[str, ...] = ()
    observation_s: float = 0.0

    @property
    def is_pass(self) -> bool:
        return self.status is CheckStatus.PASS

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> VerificationReport:
        """Rebuild a report from either shape this class emits.

        `to_dict` names the change `change_id`; `brief` names it `change`, because `brief` is written for a
        human reading a tool response. `verify_change` and `verify_plan` return `brief`, so reading it back
        through the `to_dict` parser alone silently lost the identity and the decision engine then refused
        a perfectly good report as naming no change at all. Both spellings are accepted.
        """
        change_id = str(document.get("change_id") or document.get("change") or "")
        return cls(change_id=change_id,
                   status=CheckStatus(str(document.get("status", CheckStatus.NOT_RUN.value))),
                   results=tuple(CheckResult(**{**row, "status": CheckStatus(str(row["status"])),
                                                "evidence_refs": tuple(row.get("evidence_refs", ())),
                                                "revision": row.get("revision")})
                                 for row in document.get("results", ())),
                   captured=float(document.get("captured", 0.0)),
                   evidence_refs=tuple(document.get("evidence_refs", ())),
                   observation_s=float(document.get("observation_s", 0.0)))

    def by_status(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for result in self.results:
            counts[result.status.value] = counts.get(result.status.value, 0) + 1
        return counts

    def with_status(self, status: CheckStatus) -> tuple[CheckResult, ...]:
        return tuple(result for result in self.results if result.status is status)

    def boundary(self) -> dict[str, list[str]]:
        """What this verification as a whole may be cited for, and what it may not.

        A reader who sees only the report still learns the limits: the union of the per-check boundaries is
        the boundary of the set, and the set is never wider than its weakest member.
        """
        return {"proves": _unique(result.proves for result in self.results),
                "does_not_prove": _unique(result.does_not_prove for result in self.results)}

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_id": self.change_id, "status": self.status.value, "is_pass": self.is_pass,
            "captured": round(self.captured, 3), "observation_s": self.observation_s,
            "evidence_refs": list(self.evidence_refs), "by_status": self.by_status(),
            "results": [result.to_dict() for result in self.results], **self.boundary(),
        }

    def brief(self) -> dict[str, Any]:
        """Small answer for a tool response: the status and the results that are not passes."""
        out: dict[str, Any] = {
            "change": self.change_id, "status": self.status.value, "is_pass": self.is_pass,
            "checks": len(self.results), "by_status": self.by_status(),
            # How long this was watched, which is a fact about the evidence and not a detail of it: the
            # rollout gate compares it against what each stage asked to be observed for, and a client
            # driving a rollout through the tool surface has nothing else to compare. Dropping it here
            # made every stage read as "observed for 0s" and refuse, and a caller that supplied the
            # number itself would be the only way through.
            "observation_s": round(self.observation_s, 1),
        }
        outstanding = [*self.with_status(CheckStatus.FAIL), *self.with_status(CheckStatus.UNKNOWN),
                       *self.with_status(CheckStatus.NOT_RUN)]
        if outstanding:
            out["outstanding"] = [{"check": result.check, "status": result.status.value,
                                   "detail": result.detail, "reason": result.reason}
                                  for result in outstanding[:10]]
        out["does_not_prove"] = self.boundary()["does_not_prove"][:4]
        return out


@dataclass(frozen=True)
class VerifyContext:
    """What a check is handed: the target surface, the bounds, and the change it is verifying.

    Deliberately narrow - a check can read the host, ask for an artifact and nothing else. It gets no way
    to open a review, spend a budget or start a change, so a check cannot widen its own remit.
    """

    core: Core
    verify: VerifyConfig
    change_id: str
    window_s: float
    evidence_refs: tuple[str, ...] = ()
    clock: Callable[[], float] = now
    #: When the change was observed applied, or None when the caller did not say. Present so the window
    #: can be recomputed per check instead of frozen at the start of the run.
    applied_at: float | None = None

    def window(self) -> float:
        """How long ago the change was applied, as of *now*.

        A verification is a sequence of remote commands; the last one may run much later than the first,
        and every check has to be judged against the settling time it actually waited.
        """
        if self.applied_at is None:
            return self.window_s
        return max(0.0, self.clock() - self.applied_at)

    def keep(self, kind: str, title: str, text: str) -> tuple[str, ...]:
        """The raw capture behind a verdict, so a reader can re-derive it instead of trusting the summary."""
        try:
            return (self.core.artifacts.save(kind, title, text).id,)
        except OSError:
            return ()  # a full disk must not crash a verification; the parsed values in `detail` still stand


CheckFn = Callable[[VerifyContext, Target], CheckResult]


@dataclass(frozen=True)
class Check:
    """A registered typed check: what it is called, which profile it belongs to, and how it answers.

    `state_changing` is a declaration, not a warning: a check that starts, restarts or otherwise acts is
    named as such and the Verifier refuses to run it unless the change plan asked for it by name.
    `settles` marks a property that needs time before it means anything - a just-restarted unit, a
    just-synced endpoint, a rollout that is still converging.
    """

    name: str
    profile: str
    run: CheckFn
    state_changing: bool = False
    settles: bool = False
    #: The check can only answer "is this the state the change produced" if the plan said what revision it
    #: was aiming at. Without it the check is measuring whatever happens to be there, and `_unbound` used to
    #: call that acceptable.
    requires_revision: bool = False
    why: str = ""


#: Workload kinds `k8s:rollout` knows how to read. A Deployment scaled to zero omits its optional status
#: counters, which this check handles; other kinds are refused rather than guessed at.
#: Only resource types `kubectl get` accepts here. `apps/v1` is a group/version prefix and `deployment.apps`
#: is not a type at all; both were being handed to kubectl as if they were, which is a typo that reads as
#: a resource rather than an error.
SUPPORTED_KINDS = frozenset({"deployment", "deployments"})

#: Every check OpsBrain knows, by its policy-facing name (`profile:check`). A policy names these strings,
#: so a typo is a refusal rather than a silently skipped requirement.
REGISTRY: dict[str, Check] = {}


def register(check: Check) -> Check:
    """Register a typed check. Re-registering a name replaces it, which is how a deployment overrides a
    check without editing the Verifier."""
    REGISTRY[check.name] = check
    return check


# ------------------------------------------------------------------------------------------------- helpers
def config_path(core: Core) -> Path:
    """Where the auto pipeline keeps its records, derived from the Core it was handed."""
    return Path(getattr(core.config, "data_path", ".")) / "auto"


def _redacted(result: Result) -> Result:
    """Strip everything from a kubectl document except the fields this check reads."""
    try:
        document = json.loads(result.out)
    except ValueError:
        return result
    if not isinstance(document, dict):
        return result
    reduced = {
        "metadata": {"name": (document.get("metadata") or {}).get("name"),
                     "generation": (document.get("metadata") or {}).get("generation"),
                     "annotations": (document.get("metadata") or {}).get("annotations") or {}},
        "spec": {"replicas": (document.get("spec") or {}).get("replicas")},
        "status": {key: (document.get("status") or {}).get(key)
                   for key in ("generation", "observedGeneration", "replicas", "updatedReplicas",
                               "readyReplicas", "availableReplicas")},
    }
    return Result(result.rc, json.dumps(reduced), result.timed_out)


def _registered(name: str) -> Check:
    """The registry entry a check reports under, so a result is traceable to the exact rule that made it."""
    return REGISTRY[name]


def _unique(values: Iterable[str]) -> list[str]:
    seen: dict[str, None] = {}
    for value in values:
        if value:
            seen.setdefault(value, None)
    return list(seen)


def _run(context: VerifyContext, target: Target, argv: Sequence[str], *, timeout: float = _SSH_TIMEOUT) -> Result:
    """Run a read-only command, on the target's host when it has one and locally otherwise.

    Every part is `shlex.quote`d for the remote path: the argv a check builds is never interpolated into
    a shell string, so a unit or path can never become an operator.
    """
    if target.host:
        return context.core.exec.run_ssh(target.host, " ".join(shlex.quote(part) for part in argv),
                                        timeout=timeout)
    return context.core.exec.run_local(list(argv), timeout=timeout)


def _fault(result: Result) -> str:
    """Why a capture may not be believed, or "" when it may.

    Only transport-level answers count here: a timeout, a lost connection and a missing tool mean we never
    reached the state, which is an UNKNOWN. A command that ran and reported a problem is left to the check
    to interpret, because `is-active` exiting 3 is a failed unit and not a failed connection.
    """
    if result.timed_out:
        return "timed out: the capture did not finish before the observation window closed"
    if result.rc == 255:
        return f"connection lost: {clip(result.out.strip() or 'ssh exited 255', 120)}"
    if result.rc == 127:
        return f"no such tool on the target: {clip(result.out.strip() or 'command not found', 120)}"
    return ""


def _properties(text: str) -> dict[str, str]:
    """`systemctl show --property=A,B` as a dict. An unparseable line is simply absent, which the callers
    read as incomplete data rather than silently defaulting."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip():
            out[key.strip()] = value.strip()
    return out


def _counters(fields: Mapping[str, Any], names: Sequence[str]) -> dict[str, int] | None:
    """The rollout counters, or None when any of them is absent.

    A workload status without `readyReplicas` is partial data, not a rollout of zero replicas. The two must
    not collapse, so the caller gets an UNKNOWN instead of a verdict built on a default.
    """
    out: dict[str, int] = {}
    for name in names:
        value = fields.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        out[name] = int(value)
    return out


def _unbound(target: Target, revision: str | None, check: Check | None = None) -> str:
    """Why a result cannot be attributed to the change, or "" when it can.

    A revision is what makes a check *about this change*. If the plan declared one and the capture does
    not carry it - or carries a different one - the check is looking at some other state of the world, and
    an unattributable observation is not a pass.
    """
    if check is not None and check.requires_revision and not target.expected_revision:
        return (f"the plan named no expected_revision for {target.label}: without one there is nothing to "
                "compare the target against, so this is a measurement rather than a verdict")
    if not target.expected_revision:
        return ""
    if revision is None:
        return f"unknown revision: the plan applied {target.expected_revision!r}, the target reports none"
    if revision != target.expected_revision:
        return (f"revision mismatch: the plan applied {target.expected_revision!r}, "
                f"the target reports {revision!r}")
    return ""


def _unit(target: Target) -> str:
    """The unit name, validated before it is put on a command line."""
    if not _UNIT.fullmatch(target.name):
        raise OpsError(f"invalid unit name: {target.name!r}")
    return target.name


def _outcome(context: VerifyContext, check: Check, target: Target, status: CheckStatus, detail: str, *,
             proves: str, does_not_prove: str, revision: str | None = None, evidence: tuple[str, ...] = (),
             reason: str = "") -> CheckResult:
    """One result with everything the record must carry, including the boundary of what was established."""
    return CheckResult(check=check.name, profile=check.profile, target=target.label, status=status,
                       captured=context.clock(), detail=clip(detail, 300), revision=revision,
                       evidence_refs=evidence, state_changing=check.state_changing,
                       observation_s=context.window(), proves=proves, does_not_prove=does_not_prove,
                       reason=reason)


def _unknown(context: VerifyContext, check: Check, target: Target, reason: str, *,
             revision: str | None = None, evidence: tuple[str, ...] = (), proves: str = "",
             does_not_prove: str = "") -> CheckResult:
    """Something that could not be concluded. The boundary is still stated: what a check would have looked
    at does not depend on whether it managed to look."""
    return _outcome(context, check, target, CheckStatus.UNKNOWN, reason,
                    proves=proves or f"nothing about {target.label}: the check could not be evaluated",
                    does_not_prove=does_not_prove or f"the state of {target.label}",
                    revision=revision, evidence=evidence, reason=reason)


def _not_run(context: VerifyContext, check: Check, target: Target, detail: str) -> CheckResult:
    return _outcome(context, check, target, CheckStatus.NOT_RUN, detail, proves="nothing: the check never ran",
                    does_not_prove=f"the state of {target.label}: an unrun check observes nothing", reason=detail)


def _save(context: VerifyContext, check: Check, target: Target, text: str) -> tuple[str, ...]:
    """Keep the raw capture that a verdict was derived from, so the verdict stays auditable."""
    return context.keep("verify", f"{check.name} {target.label}", text)


# ------------------------------------------------------------------------------------------------- systemd
def systemd_unit_active(context: VerifyContext, target: Target) -> CheckResult:
    """Is the unit running the *effective* configuration, not merely loaded?

    `systemctl is-active` answers "is the unit active", which a stale or missing drop-in can satisfy: a unit
    that was started an hour before the change is still active. What the change promised is that the unit
    runs the configuration just installed, so this reads the manager's own view - ActiveState, the drop-ins
    in effect, and the timestamp at which this configuration took over. That timestamp is the result's
    revision: the thing the next verification, and the next change, is compared against.

    Read-only by construction: nothing here starts or restarts anything.
    """
    check = _registered("systemd:unit-active")
    unit = _unit(target)
    result = _run(context, target, ["systemctl", "show", unit, "--no-pager", f"--property={_UNIT_PROPERTIES}"])
    fault = _fault(result)
    if fault:
        return _unknown(context, check, target, fault, evidence=_save(context, check, target, result.out))
    properties = _properties(result.out)
    state = properties.get("ActiveState")
    if state is None:
        return _unknown(context, check, target,
                        f"incomplete data: systemctl returned no ActiveState for {unit}",
                        evidence=_save(context, check, target, result.out))
    revision = properties.get("ExecMainStartTimestamp") or None
    if state not in ("active", "reloading"):
        # A unit that is not running fails whatever the plan claimed, and a failure needs no attribution.
        # Downgrading it to UNKNOWN here would let a broken unit report as "could not tell", which reads
        # as an absence of information rather than the bad news it is.
        return _outcome(context, check, target, CheckStatus.FAIL,
                        f"{target.label}: {unit} is {state}/{properties.get('SubState', '?')}, not active",
                        revision=revision, proves=f"that {unit} on {target.host} is {state}",
                        does_not_prove="why it is down, or whether the change caused it",
                        evidence=_save(context, check, target, result.out))
    unbound = _unbound(target, revision, check)
    if unbound:
        return _unknown(context, check, target, unbound, revision=revision,
                        evidence=_save(context, check, target, result.out))
    where = f"{target.label}: {unit} is {state}/{properties.get('SubState', '?')}"
    boundary = {
        "proves": f"that {unit} on {target.host} reached ActiveState={state} with the drop-in chain "
                  f"in effect since {revision or 'an unrecorded moment'}",
        "does_not_prove": "that the service works: an active unit can crash on its first request, and this "
                          "check neither exercises it nor reads a log",
    }
    if state != "active":
        return _outcome(context, check, target, CheckStatus.FAIL, where, revision=revision,
                        evidence=_save(context, check, target, result.out), **boundary)
    return _outcome(context, check, target, CheckStatus.PASS, where, revision=revision,
                    evidence=_save(context, check, target, result.out), **boundary)


def systemd_drop_in(context: VerifyContext, target: Target) -> CheckResult:
    """Is the drop-in the plan installed actually in the unit's effective drop-in chain?

    This is where "the apply returned 0" stops being enough. A drop-in written into the wrong directory is
    a file that exists, is readable, may even be correct - and is not part of the unit at all, because
    systemd only reads `<unit>.service.d/` next to the unit. The effective chain (`DropInPaths`) is the only
    answer to "is the configuration we intended in force", so the check reads that and nothing else.

    Without a declared drop-in there is nothing to compare against, and the answer is UNKNOWN rather than a
    reassuring PASS: a check that cannot say what it expected has verified nothing.
    """
    check = _registered("systemd:drop-in")
    wanted = target.expect("drop_in")
    if not wanted:
        return _unknown(context, check, target,
                        f"the change plan names no drop-in for {target.label}, so there is nothing to "
                        f"compare the effective configuration against")
    unit = _unit(target)
    result = _run(context, target, ["systemctl", "show", unit, "--no-pager", f"--property={_UNIT_PROPERTIES}"])
    fault = _fault(result)
    if fault:
        return _unknown(context, check, target, fault, evidence=_save(context, check, target, result.out))
    properties = _properties(result.out)
    raw = properties.get("DropInPaths")
    if raw is None:
        return _unknown(context, check, target, f"incomplete data: systemctl returned no DropInPaths for {unit}",
                        evidence=_save(context, check, target, result.out))
    # The same revision the running unit reports: a drop-in that is loaded but not yet taken over is a
    # different fact from one that is in force, and an unattributable one is not a pass.
    revision = properties.get("ExecMainStartTimestamp") or None
    unbound = _unbound(target, revision)
    if unbound:
        return _unknown(context, check, target, unbound, revision=revision,
                        evidence=_save(context, check, target, result.out))
    effective = raw.split()
    if wanted not in effective:
        return _outcome(context, check, target, CheckStatus.FAIL,
                        f"{target.label}: {wanted} is not in the effective drop-in chain of {unit} "
                        f"(in effect: {', '.join(effective) or 'nothing'})",
                        revision=revision, evidence=_save(context, check, target, result.out),
                        proves=f"which drop-ins systemd actually loads for {unit} on {target.host}",
                        does_not_prove="that the intended drop-in exists on disk: a file in the wrong directory "
                                       "is present, correct and still not part of the unit")
    return _outcome(context, check, target, CheckStatus.PASS,
                    f"{target.label}: {wanted} is in the effective drop-in chain of {unit}",
                    revision=revision, evidence=_save(context, check, target, result.out),
                    proves=f"that systemd loads {wanted} for {unit} on {target.host}, so the intended "
                           f"configuration is part of the unit",
                    does_not_prove="the contents of the drop-in and whether the unit has restarted onto it: "
                                   "the drop-in can be loaded while the running process still uses the old one")


def systemd_unit_start(context: VerifyContext, target: Target) -> CheckResult:
    """Start the unit, then report what it actually did. Declared in advance, not disguised.

    Starting a service is an action, not an observation, which is why this is a separate entry from
    `systemd:unit-active` and carries `state_changing=True`: the Verifier refuses to run it unless the plan
    named it and the config allows state-changing checks. A plan that forgot to declare the start gets a
    NOT_RUN, not a pass it did not earn.
    """
    check = _registered("systemd:unit-start")
    unit = _unit(target)
    started = _run(context, target, ["systemctl", "start", unit], timeout=_START_TIMEOUT)
    fault = _fault(started)
    if fault:
        return _unknown(context, check, target, fault, evidence=_save(context, check, target, started.out))
    if started.rc != 0:
        return _outcome(context, check, target, CheckStatus.FAIL,
                        f"{target.label}: `systemctl start {unit}` exited {started.rc}: "
                        f"{clip(started.out.strip(), 120)}",
                        evidence=_save(context, check, target, started.out),
                        proves=f"that starting {unit} on {target.host} was attempted and failed",
                        does_not_prove="whether the unit is running: a refused start says nothing about the "
                                       "state that is already there")
    observed = systemd_unit_active(context, target)
    return replace(observed, check=check.name, state_changing=True,
                   detail=f"started {unit}: {observed.detail}",
                   proves=f"{observed.proves}; and that `systemctl start {unit}` exited 0")


# ---------------------------------------------------------------------------------------------------- http
def http_reachable(context: VerifyContext, target: Target) -> CheckResult:
    """Does the endpoint answer - and what is that worth?

    Availability is a narrow, real property, and the temptation is to let it stand in for "nothing broke".
    So the result is explicit about its two edges: it covers one URL at one instant inside one window, and
    it says nothing about the endpoints nobody asked, the logs, or a failure that arrives after the window
    closes. A transport error (status 0) is UNKNOWN rather than FAIL - a refused connection and a filtered
    port look identical from here, and reporting a down service on that evidence would be a guess.
    """
    check = _registered("http:reachable")
    requested = target.expect("url") or target.name
    url = context.core.config.observe.http_checks.get(requested)
    if url is None and requested in context.core.config.observe.http_checks.values():
        url = requested
    if url is None:
        # `http.check` will happily GET any string. Verification must not turn into a way to probe hosts
        # the operator never listed, so an unconfigured endpoint is refused rather than contacted.
        return _unknown(context, check, target,
                        f"{requested!r} is not one of the configured observe.http_checks: verification does "
                        f"not contact endpoints nobody declared ({sorted(context.core.config.observe.http_checks)})")
    status, elapsed_ms = context.core.http.check(url, timeout=_HTTP_TIMEOUT)
    window = context.window()
    if status == 0:
        return _unknown(context, check, target,
                        f"no answer from {url} after {elapsed_ms}ms: a refused connection, a filtered port "
                        f"and a DNS failure are indistinguishable from here")
    if not 200 <= status < 400:
        return _outcome(context, check, target, CheckStatus.FAIL, f"{target.label}: {url} answered HTTP {status}",
                        proves=f"that {url} answered HTTP {status} after {elapsed_ms}ms",
                        does_not_prove="why it failed and what depends on it: the probe sees a status code "
                                       "and nothing of the body, the logs or the upstream")
    unbound = _unbound(target, None)
    if unbound:
        return _unknown(context, check, target, unbound)
    expected = target.expect("status")
    if expected is not None and expected != str(status):
        return _outcome(context, check, target, CheckStatus.FAIL,
                        f"{target.label}: {url} answered HTTP {status}, the plan expected {expected}",
                        proves=f"that {url} answered HTTP {status}, which is not the {expected} the plan required",
                        does_not_prove="whether the service is broken: an unexpected status may be a proxy, a "
                                       "redirect policy or a stale expectation in the plan")
    return _outcome(context, check, target, CheckStatus.PASS,
                    f"{target.label}: {url} answered HTTP {status} in {elapsed_ms}ms, observed {window:g}s "
                    f"after the change",
                    proves=f"that {url} answered HTTP {status} within {elapsed_ms}ms, observed {window:g}s "
                           f"after the change was applied",
                    does_not_prove="the absence of regressions: not the other endpoints, not the logs, and "
                                   "not any failure that appears after the observation window closes")


# ----------------------------------------------------------------------------------------------------- k8s
def k8s_rollout(context: VerifyContext, target: Target) -> CheckResult:
    """Has the workload finished the rollout the change asked for, and at which revision?

    Two things have to hold at once: the controller has observed the new generation (so the live spec is the
    new spec) and every replica of that generation is ready. Either half missing is partial data, not a
    rollout of zero - hence `_counters`, and an UNKNOWN rather than a verdict built on a default. The
    revision annotation is the result's revision: without it the answer cannot be attributed to the change.
    """
    check = _registered("k8s:rollout")
    k8s = context.core.config.k8s
    where = target.expect("namespace") or "default"
    if k8s is None:
        return _unknown(context, check, target, "k8s is not configured: the rollout cannot be observed")
    argv = [k8s.kubectl, "--request-timeout=30s"]
    if k8s.kubeconfig:
        argv += ["--kubeconfig", str(Path(k8s.kubeconfig).expanduser())]
    if k8s.context:
        argv += ["--context", k8s.context]
    kind = (target.expect("kind") or "deployment").strip().lower()
    if kind not in SUPPORTED_KINDS:
        # The kind goes straight into argv. An unrestricted value is an argument injection, and a
        # misspelling is silently the wrong resource type rather than an error.
        return _unknown(context, check, target,
                        f"unsupported workload kind {kind!r}: this check understands "
                        f"{sorted(SUPPORTED_KINDS)}")
    argv += ["get", kind, target.name, "-n", where, "-o", "json"]
    result = _run(context, target, argv, timeout=_SSH_TIMEOUT)
    fault = _fault(result)
    if fault:
        return _unknown(context, check, target, fault, evidence=_save(context, check, target, result.out))
    if result.rc != 0:
        if _NOT_FOUND.search(result.out):
            return _unknown(context, check, target,
                            f"unknown target: {where}/{target.name} does not exist in the cluster",
                            evidence=_save(context, check, target, result.out))
        return _unknown(context, check, target, f"kubectl exited {result.rc}: {clip(result.out.strip(), 120)}",
                        evidence=_save(context, check, target, result.out))
    try:
        document: dict[str, Any] = json.loads(result.out)
    except ValueError as exc:
        return _unknown(context, check, target, f"incomplete data: kubectl returned no usable JSON ({exc})",
                        evidence=_save(context, check, target, result.out))
    # A Deployment manifest carries inline environment values, and those are routinely API keys and
    # passwords. The document is reduced to the status and spec counters this check actually reads before
    # it is stored, so a verification artifact never becomes a place secrets accumulate.
    result = _redacted(result)
    metadata: dict[str, Any] = document.get("metadata") or {}
    status: dict[str, Any] = document.get("status") or {}
    spec: dict[str, Any] = document.get("spec") or {}
    annotations: dict[str, Any] = metadata.get("annotations") or {}
    raw_revision = annotations.get(_K8S_REVISION_ANNOTATION)
    revision = str(raw_revision) if raw_revision is not None else None
    # `spec.replicas` is the *current* spec, which for a scale change is what the cluster already has -
    # so comparing against it would report the state the change just produced as the state it was aiming
    # at. When the plan states the count it wants, that is the only figure this check judges against.
    wanted_from_plan = target.expect("replicas")
    desired = {"replicas": int(wanted_from_plan)} if wanted_from_plan and wanted_from_plan.isdigit() \
        else _counters({**metadata, **spec}, ("replicas",))
    counters = _counters({**metadata, **status},
                         ("generation", "observedGeneration", "replicas", "updatedReplicas", "readyReplicas"))
    if counters is None or desired is None:
        return _unknown(context, check, target,
                        f"incomplete data: {where}/{target.name} is missing one of "
                        f"generation, observedGeneration, replicas, updatedReplicas, readyReplicas, "
                        f"spec.replicas",
                        revision=revision, evidence=_save(context, check, target, result.out))
    # Omitted zero-valued optional fields are zeroes, not missing data: a Deployment scaled to zero has no
    # `status.replicas` key, and reading that as "incomplete" would make the healthy case unreportable.
    wanted = desired["replicas"]
    observed = counters["observedGeneration"] == counters["generation"]
    # Ready against the *desired* count, not against `status.replicas`: while a rollout scales up the
    # controller already reports the new generation with `replicas == updatedReplicas` before the extra
    # pods are ready, and comparing only against `status.replicas` calls a half-finished rollout complete.
    complete = (counters["updatedReplicas"] == wanted and counters["readyReplicas"] == wanted
                and counters["replicas"] == wanted)
    label = f"{where}/{target.name}"
    detail = (f"{label}: {counters['readyReplicas']}/{wanted} ready, "
              f"{counters['updatedReplicas']} updated, observedGeneration "
              f"{counters['observedGeneration']}/{counters['generation']}, revision {revision or 'unrecorded'}")
    boundary = {
        "proves": f"the rollout state of {label} at revision {revision or 'unrecorded'}: every replica of "
                  f"generation {counters['generation']} is ready",
        "does_not_prove": "that the workload serves correctly: a completed rollout is a scheduling fact, "
                          "not a request, a health check or a data-path check",
    }
    if not (observed and complete):
        # A rollout that has not converged is bad news whether or not we can attribute it, and turning that
        # into UNKNOWN would read as "we could not tell" rather than "it is not done".
        return _outcome(context, check, target, CheckStatus.FAIL, detail, revision=revision,
                        evidence=_save(context, check, target, result.out), **boundary)
    # The revision is only consulted for a *pass*: a completed rollout is only the change's result if it
    # is the revision the plan applied.
    unbound = _unbound(target, revision, check)
    if unbound:
        return _unknown(context, check, target, unbound, revision=revision,
                        evidence=_save(context, check, target, result.out))
    return _outcome(context, check, target, CheckStatus.PASS, detail, revision=revision,
                    evidence=_save(context, check, target, result.out), **boundary)


# ------------------------------------------------------------------------------------------------- storage
def storage_capacity(context: VerifyContext, target: Target) -> CheckResult:
    """Does the filesystem still have the headroom the plan assumed before it started?

    A free-space number without a declared floor is a measurement, not a verdict, so a plan that named no
    threshold gets UNKNOWN rather than a PASS on whatever the disk happens to say. Columns that will not
    parse are partial data: an unreadable `df` says the state could not be established, not that the disk
    is fine.
    """
    check = _registered("storage:capacity")
    floor = target.expect("min_free_pct")
    path = target.name
    if floor is None or not _PURE_NUMBER.fullmatch(floor):
        return _unknown(context, check, target,
                        f"the plan declares no free-space floor for {path}: a measurement without an "
                        f"objective is not a verdict")
    if not _ABS_PATH.fullmatch(path):
        return _unknown(context, check, target, f"invalid path: {path!r}")
    result = _run(context, target, ["df", "-Pk", path])
    fault = _fault(result)
    if fault:
        return _unknown(context, check, target, fault, evidence=_save(context, check, target, result.out))
    if result.rc != 0:
        return _unknown(context, check, target,
                        f"cannot read the filesystem state of {path}: {clip(result.out.strip(), 120)}",
                        evidence=_save(context, check, target, result.out))
    lines = [line for line in result.out.splitlines() if line.strip()]
    columns = lines[-1].split() if lines else []
    if len(columns) < 5:
        return _unknown(context, check, target,
                        f"incomplete data: `df` returned {len(columns)} columns for {path}",
                        evidence=_save(context, check, target, result.out))
    try:
        total, available = int(columns[1]), int(columns[3])
    except ValueError:
        return _unknown(context, check, target, f"incomplete data: non-numeric `df` row {clip(columns[-1], 80)}",
                        evidence=_save(context, check, target, result.out))
    if total <= 0:
        return _unknown(context, check, target, f"cannot compute free space on {path}: total={total}")
    free_pct = available * 100.0 / total
    detail = f"{target.label}: {free_pct:.1f}% free on {columns[0]} ({available // 1024} MiB of {total // 1024})"
    boundary = {
        "proves": f"how much of {columns[0]} was free at capture time",
        "does_not_prove": "the trend: one sample cannot say whether the change is what filled the disk, or "
                          "whether it will be full again in an hour",
    }
    if free_pct < int(floor):
        evidence = _save(context, check, target, result.out)
        return _outcome(context, check, target, CheckStatus.FAIL,
                        f"{detail}, the plan required at least {floor}%", evidence=evidence, **boundary)
    evidence = _save(context, check, target, result.out)
    return _outcome(context, check, target, CheckStatus.PASS, f"{detail}, the plan required at least {floor}%",
                    evidence=evidence, **boundary)


# --------------------------------------------------------------------------------------------------- drift
def drift_repo_live(context: VerifyContext, target: Target) -> CheckResult:
    """Is the file on the host the file in the repo?

    Code vs live is a comparison, so both sides have to exist: a missing repo copy or an unreadable live one
    is UNKNOWN, not "no drift". The live digest is the result's revision, which is what lets a later change
    tell "the file changed since then" from "the file was always different".
    """
    check = _registered("drift:repo-live")
    path = target.name
    live = target.expect("path")
    if not target.host:
        return _unknown(context, check, target, f"drift needs a live host: {path} compared with itself proves "
                                               f"nothing")
    if live is None or not _ABS_PATH.fullmatch(live):
        return _unknown(context, check, target, f"the plan names no usable live path for {path}")
    try:
        root = context.core.repo.resolve()
        candidate = (root / path).resolve()
        if not candidate.is_relative_to(root):
            return _unknown(context, check, target,
                            f"{path!r} resolves outside the repository: verification reads the repository, "
                            "it does not read the filesystem")
        wanted = hashlib.sha256(candidate.read_bytes()).hexdigest()
    except OSError as exc:
        return _unknown(context, check, target, f"cannot read the repo copy of {path}: "
                                               f"{exc.strerror or exc.__class__.__name__}")
    result = _run(context, target, ["sha256sum", live])
    fault = _fault(result)
    if fault:
        return _unknown(context, check, target, fault, evidence=_save(context, check, target, result.out))
    match = _DIGEST.search(result.out)
    if result.rc != 0 or match is None:
        return _unknown(context, check, target, f"incomplete data: no digest for {live} on {target.host} "
                                               f"({clip(result.out.strip(), 80)})",
                        evidence=_save(context, check, target, result.out))
    got = match.group(1)
    unbound = _unbound(target, got)
    if unbound:
        return _unknown(context, check, target, unbound, revision=got,
                        evidence=_save(context, check, target, result.out))
    if got != wanted:
        return _outcome(context, check, target, CheckStatus.FAIL,
                        f"{target.label}: {live} ({got[:12]}) differs from the repo copy of {path} "
                        f"({wanted[:12]})", revision=got, evidence=_save(context, check, target, result.out),
                        proves=f"that the bytes of {live} on {target.host} are not the bytes of {path} in the repo",
                        does_not_prove="which side is right, or whether anything else on the host drifted: "
                                       "one file compared is one file compared")
    return _outcome(context, check, target, CheckStatus.PASS,
                    f"{target.label}: {live} matches the repo copy of {path} ({got[:12]})", revision=got,
                    evidence=_save(context, check, target, result.out),
                    proves=f"that {live} on {target.host} is byte-identical to {path} in the repo",
                    does_not_prove="anything about the other resources the change touched: an unchanged file "
                                   "is one fact, not a clean host")


# ------------------------------------------------------------------------------------------------ registry
register(Check("systemd:unit-active", "systemd", systemd_unit_active, settles=True, requires_revision=True,
               why="the unit is running the effective configuration, not merely active since before the change"))
register(Check("systemd:drop-in", "systemd", systemd_drop_in, requires_revision=True,
               why="the drop-in the plan installed is in the unit's effective drop-in chain"))
register(Check("systemd:unit-start", "systemd", systemd_unit_start, state_changing=True, settles=True,
               why="starting the unit is an action, so it runs only when the plan declared it"))
register(Check("http:reachable", "http", http_reachable, settles=True,
               why="the endpoint answers inside the observation window, and only that"))
register(Check("k8s:rollout", "k8s", k8s_rollout, settles=True, requires_revision=True,
               why="the workload finished the rollout the change asked for, at the expected revision"))
register(Check("storage:capacity", "storage", storage_capacity,
               why="the filesystem still has the headroom the plan assumed"))
register(Check("drift:repo-live", "drift", drift_repo_live,
               why="the file on the host is the file in the repo"))


# ------------------------------------------------------------------------------------------------ overall
def overall_status(results: Iterable[CheckResult], *, unknown_is_not_pass: bool = True) -> CheckStatus:
    """The one rule that turns many outcomes into the answer a decision engine is allowed to read.

    A FAIL dominates, because a known false is more informative than anything unknown. Then an UNKNOWN,
    while `unknown_is_not_pass` holds - which it may not be switched off from. Then a NOT_RUN: a required
    check that never executed concludes nothing, so the run concludes nothing either. Only a set in which
    every check passed is a PASS, and an empty set is not a set in which every check passed - which is why
    "nothing ran" is NOT_RUN and never a pass. Should the flag ever be false, an UNKNOWN would stop
    blocking and the run would be reported as NOT_RUN, still never as a pass.
    """
    rows = tuple(results)
    if not rows:
        return CheckStatus.NOT_RUN
    if any(row.status is CheckStatus.FAIL for row in rows):
        return CheckStatus.FAIL
    if unknown_is_not_pass and any(row.status is CheckStatus.UNKNOWN for row in rows):
        return CheckStatus.UNKNOWN
    if any(row.status in (CheckStatus.UNKNOWN, CheckStatus.NOT_RUN) for row in rows):
        return CheckStatus.NOT_RUN
    return CheckStatus.PASS


def _settle(check: Check, config: VerifyConfig, result: CheckResult) -> CheckResult:
    """A property that needs settling time may not be claimed before the window has passed.

    Applied centrally rather than inside each check, because a check that has to remember to be careful is
    a check that will eventually forget. A FAIL is left alone - something already went wrong, and waiting
    cannot make it less true.
    """
    if not check.settles or not config.require_observation or result.status is not CheckStatus.PASS:
        return result
    if result.observation_s >= config.observation_s:
        return result
    reason = (f"observation window too short: {result.observation_s:g}s of {config.observation_s}s since the "
              f"change was applied")
    return replace(result, status=CheckStatus.UNKNOWN, reason=reason,
                   detail=f"{result.detail} - {reason}, so a settled system is not claimed")


class Verifier:
    """Runs the selected checks against the selected targets and reports one status for one change.

    The Verifier owns the two rules no individual check may forget:

    * **the observation window** - a check that claims a property needing settling time may not return PASS
      before `VerifyConfig.observation_s` has elapsed since the change was applied;
    * **the overall status** - see `overall_status`: any FAIL makes the change FAIL, any UNKNOWN makes it
      UNKNOWN, any NOT_RUN means nothing was concluded, and only an all-PASS set is a PASS.

    A state-changing check runs only when the config allows it *and* the plan named it in `declared`. That
    is the whole point of the flag: a plan must declare the action it expects, and a check that starts a
    service cannot be smuggled in under the name of one that reads.
    """

    def __init__(self, auto: AutoConfig, core: Core, *, clock: Callable[[], float] = now,
                 root: Path | None = None) -> None:
        self.auto = auto
        self.core = core
        self.clock = clock
        #: Where preflight records live, so a state-changing declaration can be checked against the
        #: change that actually recorded it rather than against the caller's word.
        self.root = root if root is not None else config_path(core)

    def available(self) -> tuple[str, ...]:
        """The checks the config enables. A profile name that matches no registered check yields nothing,
        which reaches the report as NOT_RUN rather than as an unexamined pass."""
        enabled = set(self.auto.verify.profiles)
        return tuple(sorted(name for name, check in REGISTRY.items() if check.profile in enabled))

    def describe(self) -> list[dict[str, Any]]:
        """What is enabled, each check's own statement of what it is for, and whether it acts. A tool
        surface offers this, so nothing has to be guessed from a check's name."""
        return [{"check": name, "profile": REGISTRY[name].profile, "state_changing": REGISTRY[name].state_changing,
                 "settles": REGISTRY[name].settles, "why": REGISTRY[name].why} for name in self.available()]

    def select(self, names: Sequence[str] = (), declared: Sequence[str] = ()) -> tuple[Check, ...]:  # noqa: C901
        """Resolve `["systemd:unit-active", "http"]` into concrete checks; an empty list means every enabled
        check. A bare profile name expands to all of its checks.

        An unknown name is an error, not a skip: a typo in a policy row must not drop a required check and
        let the rest of the set pass.
        """
        available = self.available()
        # A broad request must not sweep in an action. Asking for the profile `systemd` is not an
        # authorisation to run `systemd:unit-start`, so profile expansion skips state-changing checks the
        # change did not declare. Naming one explicitly is still allowed - `verify` is what decides, and
        # refusing to select it here would hide the difference from the report.
        permitted = frozenset(declared)

        def may_expand(key: str) -> bool:
            return not REGISTRY[key].state_changing or key in permitted

        if not names:
            chosen = [REGISTRY[name] for name in available if may_expand(name)]
        else:
            chosen = []
            for name in names:
                if ":" in name:
                    if name not in available:
                        raise OpsError(f"unknown verification check: {name!r} (enabled: {', '.join(available)})")
                    chosen.append(REGISTRY[name])
                    continue
                expanded = [REGISTRY[key] for key in available
                            if REGISTRY[key].profile == name and may_expand(key)]
                if not expanded:
                    raise OpsError(f"unknown verification profile: {name!r}")
                chosen.extend(expanded)
        if len(chosen) > self.auto.verify.max_checks:
            raise OpsError(f"{len(chosen)} checks selected, the configured limit is {self.auto.verify.max_checks}")
        # Deduplicated: asking for a profile and one of its members is the same request written twice, and
        # running a state-changing check twice is a second action nobody planned.
        return tuple({check.name: check for check in reversed(chosen)}.values())[::-1]

    def verify(self, change_id: str, targets: Sequence[Target], *, checks: Sequence[str] = (),
               applied_at: float | None = None, evidence_refs: Sequence[str] = (),
               declared: Sequence[str] = ()) -> VerificationReport:
        """Verify one applied change.

        `targets` says what to look at, `checks` what to demand (`()` means every enabled check),
        `applied_at` is when the change was observed applied - the start of the observation window - and
        `declared` names the state-changing checks the plan authorised in advance.
        """
        if not change_id.strip():
            raise OpsError("verification must name the change it verifies: an unattributable report proves "
                           "nothing")
        unknown = sorted({target.kind for target in targets if target.kind not in KIND_PROFILES})
        if unknown:
            # Silently skipping an unrecognised kind is how "everything passed" gets reported for a run
            # that checked half of what it was given. It is reported, and the report is not a pass.
            raise OpsError(
                f"no verification profile recognises target kind(s) {unknown}; known kinds are "
                f"{sorted(KIND_PROFILES)}: a target that is skipped is a check that never ran")
        selected = self.select(checks, declared)
        # Recomputed for every check. A verification that takes two minutes must not keep reporting the
        # window it started with: a check running at the end waited longer than one that ran first, and
        # settling is measured from when the change was applied.
        context = VerifyContext(core=self.core, verify=self.auto.verify, change_id=change_id, window_s=0.0,
                                evidence_refs=tuple(evidence_refs), clock=self.clock,
                                applied_at=applied_at)
        results: list[CheckResult] = []
        for check in selected:
            matched = [target for target in targets if KIND_PROFILES.get(target.kind) == check.profile]
            if not matched:
                results.append(_not_run(context, check, Target("", "-"),
                                        f"no {check.profile} target was named by the change plan"))
                continue
            for target in matched:
                if check.state_changing and not self._permitted(check, declared, change_id):
                    results.append(_not_run(context, check, target, self._undeclared(check)))
                    continue
                results.append(self._one(check, context, target))
        return VerificationReport(change_id=change_id, status=overall_status(results), results=tuple(results),
                                  captured=self.clock(), evidence_refs=context.evidence_refs,
                                  observation_s=context.window())

    def _permitted(self, check: Check, declared: Sequence[str], change_id: str = "") -> bool:
        """A state-changing check runs only when the operator allows it *and* the change authorises it.

        `declared` arrives from the caller, so on its own it is a name in a list. It is cross-checked
        against the plan the change actually recorded: an authorisation the stored change does not carry
        is not an authorisation, however well it was spelled.
        """
        if not self.auto.verify.allow_state_changing_checks or check.name not in declared:
            return False
        return self._plan_declares(change_id, check)

    def _plan_declares(self, change_id: str, check: Check) -> bool:
        """Whether the *stored* change authorised this check. A missing plan authorises nothing.

        Returning "no plan, so allow" is the dangerous direction: the record being absent is exactly what
        an unauthorised caller controls, and it would hand out the one action that can change a host.
        """
        try:
            document = json.loads(
                (self.root / "preflight" / f"pf-{change_id[:16]}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        declared = document.get("declared_checks")
        if not isinstance(declared, list):
            return False
        return check.name in declared

    def _undeclared(self, check: Check) -> str:
        if not self.auto.verify.allow_state_changing_checks:
            return (f"{check.name} changes state and auto.verify.allow_state_changing_checks is false: "
                    f"verification is not allowed to act")
        return (f"{check.name} changes state and the stored change does not declare it: an action that was "
                f"not planned is not run by the thing that checks the plan")

    def _one(self, check: Check, context: VerifyContext, target: Target) -> CheckResult:
        """Run one check and enforce the window rule on its answer.

        `OpsError` is the declared failure mode (an unknown host, a malformed unit name) and becomes an
        UNKNOWN. Anything else is a bug in the check and is left to fail loudly rather than being reported
        as a state of the world.
        """
        try:
            result = check.run(context, target)
        except OpsError as exc:
            return _unknown(context, check, target, f"the check could not be evaluated: {exc}")
        return _settle(check, self.auto.verify, result)
