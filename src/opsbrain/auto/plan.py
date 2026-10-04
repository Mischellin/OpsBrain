"""The change plan: what is proposed, on the strength of which evidence, and how it would be undone.

A plan is the object a reviewer is asked to judge and the object an approval is later bound to. Two
properties matter more than the field list:

* **It says what it does not know.** `unverified_claims` and `unknowns` are fields, not prose, so a plan
  cannot quietly present an unconfirmed belief as a premise. A plan that claims to know everything is
  usually a plan that has not looked.
* **Rollback is part of the plan, not an afterthought.** A change with no applicable rollback must say so
  with `irreversible = true` and a reason, because "we forgot to write the rollback" and "this genuinely
  cannot be undone" are different risks and a reviewer must be able to tell them apart.

The plan never touches infrastructure. Building, validating and rendering it are pure functions; applying it
happens later, through a change id, and only after a decision nobody may forge from this file.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ..changes import digest
from ..util import OpsError, now

CONTRACT_VERSION = "1.0"


def _floor_ms(moment: float) -> float:
    """Whole milliseconds, always downwards.

    `round()` maps 1 to 1 but 1.0004 to 1.0, so the same instant supplied as an int and as a float would
    hash differently and a plan would appear altered by nothing at all.
    """
    return math.floor(moment * 1000) / 1000

MAX_TEXT = 4_000
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./@-]{0,127}$")


class PlanError(OpsError):
    """The plan is internally inconsistent and must not be submitted for review."""


class Reversibility(StrEnum):
    ROLLBACK = "rollback"  # a concrete, applicable undo is named
    COMPENSATE = "compensate"  # no undo of the same action, but a compensating one is named
    IRREVERSIBLE = "irreversible"  # nothing undoes this; the reason is mandatory


class Risk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ProposedChange:
    """One concrete edit. `how` must be specific enough that a reviewer can disagree with it.

    "restart logrotate" is not a proposal; "drop `logrotate.service.d/custom.conf` into
    `/etc/systemd/system/logrotate.service.d/`" is. The distinction is the whole point of the field.
    """

    capability: str
    target: str
    how: str
    reversible: Reversibility = Reversibility.ROLLBACK
    undo: str = ""
    irreversible_reason: str = ""
    state_changing: bool = True
    #: The verification profile this step acts on, e.g. `systemd`. It is what maps a plan's declaration
    #: onto the verifier's own check names; a step that names none authorises nothing.
    profile: str = ""
    #: The verification check this step authorises, by name (`systemd:unit-start`). A profile is a class of
    #: checks; only this names one, so a step never sweeps in an action by matching vocabulary.
    declared_check: str = ""

    def __post_init__(self) -> None:
        if not self.capability or not self.target:
            raise PlanError("a proposed change needs a capability and a target")
        if not self.how.strip():
            raise PlanError(f"change {self.capability}:{self.target} has no `how`")
        if len(self.how) > MAX_TEXT:
            raise PlanError(f"change {self.capability}:{self.target}: `how` is too long to review")
        if self.reversible is Reversibility.IRREVERSIBLE:
            if not self.irreversible_reason.strip():
                raise PlanError(
                    f"change {self.capability}:{self.target} is marked irreversible without a reason; "
                    "a reviewer cannot price a risk that has not been described")
        elif not self.undo.strip() and self.state_changing:
            raise PlanError(
                f"change {self.capability}:{self.target} claims to be reversible but names no undo")
        # `state_changing=False` means the step observes rather than acts, so demanding an undo for it
        # asks for a rollback of something that was never going to happen.

    def to_dict(self) -> dict[str, Any]:
        return {"capability": self.capability, "target": self.target, "how": self.how,
                "reversible": self.reversible.value, "undo": self.undo, "profile": self.profile,
                "irreversible_reason": self.irreversible_reason, "state_changing": self.state_changing}

    @staticmethod
    def from_dict(data: Any) -> ProposedChange:
        if not isinstance(data, dict):
            raise PlanError("a proposed change must be an object")
        reversible = data.get("reversible", Reversibility.ROLLBACK)
        if not isinstance(reversible, str) or reversible not in set(Reversibility):
            raise PlanError(f"unknown reversibility: {reversible!r}")
        return ProposedChange(
            capability=str(data.get("capability", "")), target=str(data.get("target", "")),
            how=str(data.get("how", "")), reversible=Reversibility(reversible),
            undo=str(data.get("undo", "") or ""), irreversible_reason=str(data.get("irreversible_reason", "") or ""),
            state_changing=bool(data.get("state_changing", True)),
            profile=str(data.get("profile", "") or ""),
            declared_check=str(data.get("declared_check", "") or ""))


@dataclass(frozen=True)
class ChangePlan:
    """The immutable proposal. Frozen so the thing a reviewer judged is the thing that gets approved.

    `arguments_hash` and `plan_hash` are computed from the content, which is what makes an approval
    verifiable later: if any of this changes, the hashes change, and an approval bound to the old hashes
    stops applying.
    """

    id: str
    objective: str
    diagnosis: str
    changes: tuple[ProposedChange, ...]
    created: float
    #: Content-addressed, and stored rather than recomputed on demand: an approval is bound to these, and
    #: a plan that re-derived them could change under it.
    arguments_hash: str = ""
    plan_hash: str = ""
    evidence_refs: tuple[str, ...] = ()
    evidence_bundle: str = ""
    inventory_hash: str = ""
    targets: tuple[str, ...] = ()
    preconditions: tuple[str, ...] = ()
    post_checks: tuple[str, ...] = ()
    rollback: str = ""
    reversibility: Reversibility = Reversibility.ROLLBACK
    blast_radius: tuple[str, ...] = ()
    alternatives_rejected: tuple[str, ...] = ()
    unverified_claims: tuple[str, ...] = ()
    unknowns: tuple[str, ...] = ()
    versions: Mapping[str, str] = field(default_factory=dict)
    risk: Risk = Risk.MEDIUM
    profile: str = "general"
    contract_version: str = CONTRACT_VERSION

    # -- construction ------------------------------------------------------------------------------
    @staticmethod
    def build(*, objective: str, diagnosis: str, changes: Sequence[ProposedChange],
              evidence_refs: Sequence[str] = (), evidence_bundle: str = "", inventory_hash: str = "",
              targets: Sequence[str] = (), preconditions: Sequence[str] = (), post_checks: Sequence[str] = (),
              rollback: str = "", reversibility: Reversibility | None = None, blast_radius: Sequence[str] = (),
              alternatives_rejected: Sequence[str] = (), unverified_claims: Sequence[str] = (),
              unknowns: Sequence[str] = (), versions: Mapping[str, str] | None = None, risk: Risk = Risk.MEDIUM,
              profile: str = "general", created: float | None = None) -> ChangePlan:
        if not objective.strip():
            raise PlanError("a plan needs an objective")
        if not diagnosis.strip():
            raise PlanError("a plan needs a diagnosis: what is wrong, and how that was established")
        if not changes:
            raise PlanError("a plan with no changes is not a plan")
        # The author's order is the execution order. Sorting by target made "stop the unit, replace its
        # config, start it again" into an arbitrary permutation, and a plan that is applied in a different
        # order than it was reviewed is a different plan.
        ordered = tuple(changes)
        derived = _worst_reversibility(ordered)
        if reversibility is not None and reversibility is not derived:
            # Accepting a *safer* label than the changes support is how an irreversible edit gets filed
            # as reversible. The worst of the declared changes is the only value that may stand.
            raise PlanError(
                f"plan declares {reversibility.value} but its changes are {derived.value}: the reversibility "
                "of a plan follows from what it does, not from what it is called")
        resolved = derived
        if resolved is not Reversibility.IRREVERSIBLE and not rollback.strip():
            raise PlanError(f"a {resolved.value} plan must name its rollback")
        plan = ChangePlan(
            id="", objective=objective.strip(), diagnosis=diagnosis.strip(), changes=ordered,
            created=_floor_ms(now() if created is None else created),
            evidence_refs=tuple(sorted(set(evidence_refs))), evidence_bundle=evidence_bundle,
            inventory_hash=inventory_hash,
            # A plan that forgot to say where it acts must not end up judged against an empty scope.
            targets=tuple(sorted(set(targets) | {change.target for change in ordered if change.target})),
            preconditions=tuple(preconditions), post_checks=tuple(post_checks), rollback=rollback.strip(),
            reversibility=resolved, blast_radius=tuple(sorted(set(blast_radius))),
            alternatives_rejected=tuple(alternatives_rejected), unverified_claims=tuple(unverified_claims),
            unknowns=tuple(unknowns), versions=dict(sorted((versions or {}).items())), risk=risk, profile=profile)
        return ChangePlan(**{**plan.__dict__, "id": f"pl-{plan.compute_arguments_hash()[:16]}",
                             "arguments_hash": plan.compute_arguments_hash(),
                             "plan_hash": plan.compute_plan_hash()})

    # -- the two hashes ----------------------------------------------------------------------------
    def as_digest_source(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "objective": self.objective,
            "diagnosis": self.diagnosis,
            "changes": [change.to_dict() for change in self.changes],
            "evidence_refs": list(self.evidence_refs),
            "evidence_bundle": self.evidence_bundle,
            "inventory_hash": self.inventory_hash,
            "targets": list(self.targets),
            "preconditions": list(self.preconditions),
            "post_checks": list(self.post_checks),
            "rollback": self.rollback,
            "reversibility": self.reversibility.value,
            "blast_radius": list(self.blast_radius),
            "alternatives_rejected": list(self.alternatives_rejected),
            "unverified_claims": list(self.unverified_claims),
            "unknowns": list(self.unknowns),
            "versions": dict(self.versions),
            "risk": self.risk.value,
            "profile": self.profile,
            "created": round(self.created, 3),
        }

    def compute_arguments_hash(self) -> str:
        """What would be executed, and against what: the inputs an approval must be bound to."""
        return digest({
            "changes": [change.to_dict() for change in self.changes],
            "targets": list(self.targets),
            "evidence_refs": list(self.evidence_refs),
            "inventory_hash": self.inventory_hash,
        })

    def compute_plan_hash(self) -> str:
        """The whole proposal, including the reasoning: change one word of the diagnosis and this moves."""
        return digest(self.as_digest_source())

    # -- self-assessment ---------------------------------------------------------------------------
    @property
    def irreversible(self) -> bool:
        return self.reversibility is Reversibility.IRREVERSIBLE

    def incomplete(self) -> tuple[str, ...]:
        """Gaps a reviewer should refuse the plan for, derived from the plan itself.

        Kept separate from the reviewer's opinion on purpose: these are structural, checkable without a
        model, and they are the findings a reviewer would otherwise have to notice by reading.
        """
        gaps: list[str] = []
        if not self.evidence_refs and not self.evidence_bundle:
            gaps.append("no evidence: the diagnosis is not tied to anything anyone can re-read")
        if not self.versions:
            gaps.append("no component versions: a plan against an unknown version cannot be reviewed")
        if not self.post_checks:
            gaps.append("no post-check: nothing would establish that the change worked")
        if self.irreversible and not any(change.irreversible_reason.strip() for change in self.changes):
            gaps.append("marked irreversible: every irreversible change must state why")
        return tuple(gaps)

    def blast(self) -> tuple[str, ...]:
        """Everything this touches, declared or derived. Never empty for a non-empty plan."""
        derived = {change.target for change in self.changes if change.target}
        return tuple(sorted(set(self.blast_radius) | derived))

    def to_dict(self) -> dict[str, Any]:
        return {**self.as_digest_source(), "id": self.id, "arguments_hash": self.arguments_hash,
                "plan_hash": self.plan_hash, "blast": list(self.blast())}

    @staticmethod
    def from_dict(data: Any) -> ChangePlan:
        if not isinstance(data, dict):
            raise PlanError("a plan must be a JSON object")
        if data.get("contract_version", CONTRACT_VERSION) != CONTRACT_VERSION:
            raise PlanError(f"plan contract version mismatch: {data.get('contract_version')!r}")
        risk = data.get("risk", Risk.MEDIUM)
        if not isinstance(risk, str) or risk not in set(Risk):
            raise PlanError(f"unknown risk: {risk!r}")
        reversibility = data.get("reversibility", Reversibility.ROLLBACK)
        if not isinstance(reversibility, str) or reversibility not in set(Reversibility):
            raise PlanError(f"unknown reversibility: {reversibility!r}")
        plan = ChangePlan(
            id=str(data.get("id", "")), arguments_hash=str(data.get("arguments_hash", "")),
            plan_hash=str(data.get("plan_hash", "")), objective=str(data.get("objective", "")),
            diagnosis=str(data.get("diagnosis", "")),
            changes=tuple(ProposedChange.from_dict(item) for item in data.get("changes", [])),
            created=float(data.get("created", 0.0)),
            evidence_refs=tuple(data.get("evidence_refs", [])), evidence_bundle=str(data.get("evidence_bundle", "")),
            inventory_hash=str(data.get("inventory_hash", "")), targets=tuple(data.get("targets", [])),
            preconditions=tuple(data.get("preconditions", [])), post_checks=tuple(data.get("post_checks", [])),
            rollback=str(data.get("rollback", "")), reversibility=Reversibility(reversibility),
            blast_radius=tuple(data.get("blast_radius", [])),
            alternatives_rejected=tuple(data.get("alternatives_rejected", [])),
            unverified_claims=tuple(data.get("unverified_claims", [])), unknowns=tuple(data.get("unknowns", [])),
            versions=dict(data.get("versions", {})), risk=Risk(risk), profile=str(data.get("profile", "general")))
        for change in plan.changes:
            ProposedChange.from_dict(change.to_dict())  # re-apply the per-change invariants
        if plan.reversibility is not _worst_reversibility(plan.changes):
            raise PlanError(
                f"plan is filed as {plan.reversibility.value} but its changes are "
                f"{_worst_reversibility(plan.changes).value}")
        if plan.reversibility is not Reversibility.IRREVERSIBLE and not plan.rollback.strip():
            raise PlanError(f"a {plan.reversibility.value} plan must name its rollback")
        if plan.id and plan.id != f"pl-{plan.compute_arguments_hash()[:16]}":
            raise PlanError("plan id does not match its arguments hash: the record was altered")
        if plan.plan_hash and plan.plan_hash != plan.compute_plan_hash():
            # `arguments_hash` covers the commands, not the argument for them. Rewriting the diagnosis
            # therefore leaves the id untouched, and a plan whose reasoning was swapped would still be
            # accepted under the id that vouched for the original reasoning.
            raise PlanError("plan hash does not match its contents: the record was altered")
        return plan

    # -- presentation ------------------------------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        return {
            "plan": self.id,
            "objective": self.objective,
            "risk": self.risk.value,
            "profile": self.profile,
            "reversibility": self.reversibility.value,
            "irreversible": self.irreversible,
            "targets": list(self.targets),
            "blast": list(self.blast()),
            "changes": len(self.changes),
            "evidence_refs": list(self.evidence_refs),
            "evidence_bundle": self.evidence_bundle,
            "post_checks": list(self.post_checks),
            "preconditions": list(self.preconditions),
            "unverified_claims": list(self.unverified_claims),
            "unknowns": list(self.unknowns),
            "incomplete": list(self.incomplete()),
            "arguments_hash": self.arguments_hash,
            "plan_hash": self.plan_hash,
        }

    def render_for_reviewer(self) -> str:
        """The plan as the reviewer reads it: complete, including the parts that look bad.

        The `unverified_claims` and `unknowns` sections are not decoration. A reviewer handed only the
        confident parts of a plan will approve the confident parts; the doubts are the point.
        """
        lines = [
            f"CHANGE PLAN {self.id}  (contract {self.contract_version})",
            f"objective: {self.objective}",
            f"risk: {self.risk.value}   profile: {self.profile}   reversibility: {self.reversibility.value}",
            f"targets: {', '.join(self.targets) or '(undeclared)'}",
            f"blast radius: {', '.join(self.blast())}",
            f"versions: {dict(self.versions) or '(none recorded)'}",
            f"evidence: bundle={self.evidence_bundle or '(none)'} refs={list(self.evidence_refs) or '(none)'}",
            f"inventory_hash: {self.inventory_hash or '(none)'}",
            "",
            "DIAGNOSIS:",
            f"  {self.diagnosis}",
            "",
            "PROPOSED CHANGES:",
        ]
        for index, change in enumerate(self.changes, 1):
            lines += [
                f"  {index}. {change.capability}:{change.target}"
                f"{'  [changes state]' if change.state_changing else '  [read-only]'}",
                f"     how:       {change.how}",
                f"     reversible:{change.reversible.value}"
                + (f" — {change.irreversible_reason}" if change.irreversible_reason else ""),
            ]
            if change.undo:
                lines.append(f"     undo:      {change.undo}")
        lines += ["", "PRECONDITIONS:"]
        lines += [f"  - {item}" for item in self.preconditions] or ["  (none stated)"]
        lines += ["", "POST-CHECKS (these must test the original problem, not the command's exit code):"]
        lines += [f"  - {item}" for item in self.post_checks] or ["  (none stated — nothing would prove success)"]
        lines += ["", f"ROLLBACK: {self.rollback or '(none — this plan is irreversible)'}"]
        lines += ["", "ALTERNATIVES CONSIDERED AND REJECTED:"]
        lines += [f"  - {item}" for item in self.alternatives_rejected] or ["  (none recorded)"]
        lines += ["", "UNVERIFIED CLAIMS (the plan asserts these; nobody has confirmed them):"]
        lines += [f"  - {item}" for item in self.unverified_claims] or ["  (none declared)"]
        lines += ["", "UNKNOWNS (nobody established these either way):"]
        lines += [f"  - {item}" for item in self.unknowns] or ["  (none declared)"]
        gaps = self.incomplete()
        lines += ["", "STRUCTURAL GAPS ALREADY KNOWN BEFORE ANY REVIEW:"]
        lines += [f"  - {gap}" for gap in gaps] or ["  (none)"]
        lines += [
            "",
            "Judge whether the diagnosis follows from the evidence, whether reasonable alternatives were "
            "excluded, whether the semantics of every path and setting are right, whether the scope is "
            "minimal, and whether each post-check would actually establish the original problem. "
            "A successful command that does not inspect the target state is not a post-check. "
            "Return NEEDS_EVIDENCE with concrete read-only requests if the plan cannot be judged yet; "
            "name any request that would change the host, because that is not read-only.",
        ]
        return "\n".join(lines)


def _worst_reversibility(changes: Sequence[ProposedChange]) -> Reversibility:
    order = [Reversibility.IRREVERSIBLE, Reversibility.COMPENSATE, Reversibility.ROLLBACK]
    for candidate in order:
        if any(change.reversible is candidate for change in changes):
            return candidate
    return Reversibility.ROLLBACK
