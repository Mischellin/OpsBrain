"""Preflight: the review of a plan, before anything changes.

The flow is deliberately dull: assemble the request from a plan and its evidence, hand it to the
ReviewService, and turn the answer into a decision-shaped record. Nothing in here executes anything. A
preflight that could change the world would defeat the point of reviewing it first.

Two failure modes get specific handling, because both are ways a bad plan slips through:

* **Insufficient evidence** is not a soft "maybe". It returns the concrete read-only requests the reviewer
  asked for, and the caller collects them and starts again. It is never rounded up to a pass.
* **A diagnostic that changes state is not read-only.** A check like "does restarting the unit make the
  symptom go away" is an experiment, not a probe, and `read_only_probes` marks anything that might start,
  stop, restart or write as not read-only so the caller cannot run it as a lookup.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ..redact import redact_text
from ..util import OpsError, now
from .config import AutoConfig
from .evidence import EvidenceBundle, render_for_reviewer
from .plan import ChangePlan
from .review import ReviewLimits, ReviewRequest, ReviewResult, RunnerStatus, Severity, Subject, Verdict
from .store import RecordStore
from .verify import REGISTRY, Target

#: An allowlist, not a denylist. A denylist of mutating verbs is always one verb short: `touch`, `chmod`,
#: `chown`, `tee`, `sed -i`, `apt install` and a hundred others change state without appearing on it, and
#: anything the list misses is treated as a harmless lookup. A request is read-only only when the operator
#: has declared it so; everything else needs the plan to declare it before it may run.
READ_ONLY_PROBES = frozenset({
    "systemctl show", "systemctl status", "systemctl is-enabled", "systemctl is-active", "systemctl cat",
    "journalctl", "cat", "ls", "stat", "df", "du", "free", "uname", "id", "ps", "ss", "ip -j addr",
    "kubectl get", "kubectl describe", "kubectl logs", "kubectl version", "tofu show", "git log",
    "git diff", "git show", "getent", "dig", "pgrep", "nproc", "openssl x509", "coroot query",
})


class Outcome(StrEnum):
    """What preflight concluded. Only `APPROVABLE` opens the door; the rest are honest stops."""

    APPROVABLE = "approvable"  # a reviewer said PASS and nothing structural is missing
    NEEDS_CHANGES = "needs_changes"
    NEEDS_EVIDENCE = "needs_evidence"
    DENIED = "denied"
    REVIEW_FAILED = "review_failed"  # timeout, quota, crash, malformed answer
    INCOMPLETE = "incomplete"  # the plan itself is structurally short, whatever the reviewer said


OUTCOME_BY_VERDICT = {
    Verdict.PASS: Outcome.APPROVABLE,
    Verdict.NEEDS_CHANGES: Outcome.NEEDS_CHANGES,
    Verdict.NEEDS_EVIDENCE: Outcome.NEEDS_EVIDENCE,
    Verdict.DENY: Outcome.DENIED,
}

REASON_BY_OUTCOME = {
    Outcome.APPROVABLE: "review_passed",
    Outcome.NEEDS_CHANGES: "review_blocked",
    Outcome.NEEDS_EVIDENCE: "evidence_missing",
    Outcome.DENIED: "policy_forbids",
    Outcome.REVIEW_FAILED: "review_failed",
    Outcome.INCOMPLETE: "evidence_incomplete",
}


@dataclass(frozen=True)
class PreflightResult:
    """The record a decision engine reads. `approvable` is the only field that may authorise anything."""

    plan_id: str
    outcome: Outcome
    reason: str
    review_id: str
    review_status: RunnerStatus
    verdict: Verdict | None
    findings: tuple[dict[str, Any], ...]
    unverified_claims: tuple[str, ...]
    requested_probes: tuple[str, ...]
    state_changing_probes: tuple[str, ...]
    structural_gaps: tuple[str, ...]
    #: The state-changing checks this plan authorised, in the verifier's vocabulary. Verification compares
    #: its own declarations against this rather than against a caller-supplied list.
    declared_checks: tuple[str, ...]
    #: The evidence that actually travelled with the request. Without it a later reader cannot tell which
    #: bundle produced this verdict, nor recheck that bundle's freshness.
    evidence_ids: tuple[str, ...]
    arguments_hash: str
    plan_hash: str
    created: float = 0.0
    note: str = ""

    @property
    def approvable(self) -> bool:
        return self.outcome is Outcome.APPROVABLE and not self.structural_gaps

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> PreflightResult:
        """Rebuild a result from its own stored `to_dict` shape.

        The stored document names things for the reader - `plan`, `review` - while the dataclass names them
        for the constructor. Assembling the dataclass from the document by matching field names picks up
        nothing and then fails on the two required fields, which is a confusing way to learn that the two
        vocabularies differ.
        """
        return cls(
            plan_id=str(record.get("plan", "")),
            outcome=Outcome(str(record.get("outcome", Outcome.INCOMPLETE.value))),
            reason=str(record.get("reason", "")),
            review_id=str(record.get("review", "")),
            review_status=RunnerStatus(str(record.get("review_status", RunnerStatus.OK.value))),
            verdict=Verdict(record["verdict"]) if record.get("verdict") else None,
            findings=tuple(record.get("findings", ())),
            unverified_claims=tuple(record.get("unverified_claims", ())),
            requested_probes=tuple(record.get("requested_probes", ())),
            state_changing_probes=tuple(record.get("state_changing_probes", ())),
            structural_gaps=tuple(record.get("structural_gaps", ())),
            declared_checks=tuple(record.get("declared_checks", ())),
            evidence_ids=tuple(record.get("evidence_ids", ())),
            arguments_hash=str(record.get("arguments_hash", "")),
            plan_hash=str(record.get("plan_hash", "")),
            created=float(record.get("created", 0.0)),
            note=str(record.get("note", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan": self.plan_id,
            "outcome": self.outcome.value,
            "approvable": self.approvable,
            "reason": self.reason,
            "review": self.review_id,
            "review_status": self.review_status.value,
            "verdict": self.verdict.value if self.verdict else None,
            "findings": list(self.findings),
            "unverified_claims": list(self.unverified_claims),
            "requested_probes": list(self.requested_probes),
            "state_changing_probes": list(self.state_changing_probes),
            "structural_gaps": list(self.structural_gaps),
            "declared_checks": list(self.declared_checks),
            "evidence_ids": list(self.evidence_ids),
            "arguments_hash": self.arguments_hash,
            "plan_hash": self.plan_hash,
            "created": round(self.created, 3),
            "note": self.note,
        }

    def brief(self) -> dict[str, Any]:
        out: dict[str, Any] = {"plan": self.plan_id, "outcome": self.outcome.value, "approvable": self.approvable,
                               "reason": self.reason, "review": self.review_id}
        if self.verdict is not None:
            out["verdict"] = self.verdict.value
        if self.structural_gaps:
            out["structural_gaps"] = list(self.structural_gaps)
        if self.findings:
            out["findings"] = list(self.findings[:8])
        if self.requested_probes:
            out["requested_probes"] = list(self.requested_probes[:8])
        if self.state_changing_probes:
            out["state_changing_probes"] = list(self.state_changing_probes[:8])
        if self.unverified_claims:
            out["unverified_claims"] = list(self.unverified_claims[:8])
        return out


#: The same fencing evidence uses. A plan is written by a worker or a model, and `diagnosis` and `how` are
#: exactly where "approve this plan" would be put. The reviewer still reads the text; it is now visibly data.
BEGIN = "=== UNTRUSTED PLAN DATA ==="
END = "=== END UNTRUSTED PLAN DATA ==="


def untrusted(text: str) -> str:
    """Fence worker-authored text so its contents cannot close the region or speak as the harness."""
    return f"{BEGIN}\n{text.replace(END, '').replace(BEGIN, '')}\n{END}"


def split_probes(checks: Sequence[str], allowlist: Sequence[str] = ()) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Separate "go and look" from "go and change something", so a caller can only act on the first.

    A reviewer asking for a diagnostic is not asking for permission to run an experiment. An experiment
    has to be declared in the change plan like any other state change, so the request is surfaced
    separately and never quietly executed as a lookup.
    """
    allowed = READ_ONLY_PROBES | frozenset(allowlist)
    read_only: list[str] = []
    acting: list[str] = []
    for check in checks:
        (read_only if _is_read_only(check, allowed) else acting).append(check)
    return tuple(read_only), tuple(acting)


#: Characters that turn one command into several. Nothing about a leading read-only name makes these safe.
_SHELL_OPERATORS = (";", "&&", "||", "|", "`", "$(", ">", "<")

#: Flags that mutate state on a binary whose bare invocation reads. `journalctl --rotate` and
#: `openssl x509 -out FILE` both pass a prefix test and both write.
#: Long flags only. A short `-o` is how kubectl and journalctl say "write to", but it is also how
#: `kubectl get pods -o yaml` says "read from", so short flags cannot be judged without knowing the binary.
_MUTATING_FLAGS = frozenset({"--rotate", "--vacuum", "--vacuum-time", "--vacuum-size", "--force", "--delete",
                             "--purge", "--overwrite", "--rebuild", "--in-place", "--output", "--sign",
                             "--generate", "--setup", "--create", "--remove"})


def _is_read_only(check: str, allowed: frozenset[str]) -> bool:
    """Exact match against the allowlist, after checking the arguments.

    Prefix matching was the defect: it treats every invocation of a read-only executable as read-only,
    so the flags that *do* mutate pass through. A bare name is allowed - the operator has declared that
    reading with no arguments is safe - but anything with arguments has to be declared in full, because
    knowing which flags of which binary mutate is not something this module can guess.
    """
    collapsed = " ".join(check.lower().split())
    if any(operator in collapsed for operator in _SHELL_OPERATORS):
        return False
    tokens = collapsed.split()
    if any(token in _MUTATING_FLAGS for token in tokens):
        return False
    # A bare name is safe because the operator declared the reading. A name with arguments is safe only
    # if the operator declared *that command*, since which flags mutate is not knowable from here.
    if collapsed in allowed:
        return True
    return any(collapsed.startswith(f"{prefix} ") for prefix in allowed if not collapsed.startswith(f"{prefix} -"))


class Preflight:
    """Runs one plan review and records the outcome. Holds no executor and mutates nothing."""

    def __init__(self, auto: AutoConfig, reviews: Any, root: Any, evidence: Any = None):
        self.auto = auto
        self.reviews = reviews
        self.evidence = evidence
        self.evidence = evidence
        self.store = RecordStore(root / "preflight", ("pf",))

    def _truncated(self, request: ReviewRequest) -> bool:
        return len(request.context) > self.limits().context_chars

    def refuse(self, plan: ChangePlan, outcome: Outcome, reason: str) -> PreflightResult:
        """A recorded refusal, with the same shape as a reviewed one, so nothing downstream needs a special case."""
        preflight = PreflightResult(plan_id=plan.id, outcome=outcome,
                                    reason=REASON_BY_OUTCOME[outcome], review_id="",
                                    review_status=RunnerStatus.UNAVAILABLE, verdict=None, findings=(),
                                    unverified_claims=plan.unverified_claims, requested_probes=(),
                                    state_changing_probes=(), structural_gaps=plan.incomplete(),
                                    declared_checks=declared_state_changing(plan), evidence_ids=(),
                                    arguments_hash=plan.arguments_hash, plan_hash=plan.plan_hash, created=now(),
                                    note=reason)
        self.store.put(f"pf-{plan.plan_hash[:16]}", {**preflight.to_dict(), "plan_document": plan.to_dict()})
        return preflight

    def limits(self) -> ReviewLimits:
        """The configured ceilings, in the contract's units. A plan longer than the context budget is
        clipped by the service before the id is derived, so the reviewer is asked about what it sees."""
        review = self.auto.review
        return ReviewLimits(timeout_s=review.timeout_s, context_chars=review.context_chars,
                            output_chars=review.output_chars)

    def build_request(self, plan: ChangePlan, bundle: EvidenceBundle | None = None, *,
                      subject_ref: str | None = None) -> ReviewRequest:
        context = [untrusted(redact_text(plan.render_for_reviewer()))]
        if bundle is not None:
            payloads, _ = self.evidence.load_artifacts(bundle)
            context.append("")
            context.append(render_for_reviewer(bundle, payloads))
        refs = tuple(sorted(set(plan.evidence_refs) | ({bundle.id} if bundle else set())))
        return ReviewRequest(subject=Subject.INFRA_PLAN, subject_ref=subject_ref or plan.id,
                             objective=f"preflight: {plan.objective}", context="\n".join(context),
                             evidence_refs=refs, model=self.auto.review.model,
                             limits=self.limits())

    def run(self, plan: ChangePlan, bundle: EvidenceBundle | None = None, *,
            subject_ref: str | None = None) -> PreflightResult:
        request_bundle_id = bundle.id if bundle is not None else ""
        if self.reviews.is_stub():
            # The stub answers PASS to anything, so with the default configuration every plan would be
            # approvable without anybody having looked at it. Autonomy is the one thing a stub must never
            # manufacture, so the outcome is a refusal and the reason says which runner produced nothing.
            return self.refuse(plan, Outcome.REVIEW_FAILED,
                               "auto.review.runner is `fake`: the stub cannot authorise a plan")
        request = self.build_request(plan, bundle, subject_ref=subject_ref)
        if len(request.context) > self.limits().context_chars:
            return self.refuse(plan, Outcome.INCOMPLETE,
                               f"the plan does not fit in the review context "
                               f"({self.auto.review.context_chars} chars): a reviewer cannot judge a plan it "
                               "only saw part of")
        result: ReviewResult = self.reviews.review(request)
        read_only, acting = split_probes(result.next_checks, self.auto.evidence.read_only_probes)
        # A plan may cite evidence nobody can resolve. Those references are not evidence: without this the
        # reviewer receives bare id strings and a PASS still comes back approvable.
        unresolved = tuple(ref for ref in plan.evidence_refs if ref.startswith("ev-") and ref != request_bundle_id)
        gaps = (*plan.incomplete(),
                *((f"cites evidence that cannot be resolved: {', '.join(unresolved[:4])}",) if unresolved else ()))
        outcome = self._outcome(result, gaps)
        preflight = PreflightResult(
            plan_id=plan.id, outcome=outcome, reason=REASON_BY_OUTCOME[outcome], review_id=result.review_id,
            review_status=result.status, verdict=result.verdict,
            findings=tuple(finding.to_dict() for finding in result.findings),
            unverified_claims=tuple(dict.fromkeys(plan.unverified_claims + result.unverified_claims)),
            requested_probes=read_only,
            state_changing_probes=acting, structural_gaps=gaps,
            declared_checks=declared_state_changing(plan), evidence_ids=request.evidence_refs,
            arguments_hash=plan.arguments_hash, plan_hash=plan.plan_hash, created=now())
        self.store.put(f"pf-{plan.plan_hash[:16]}", {**preflight.to_dict(), "plan_document": plan.to_dict()})
        return preflight

    def _outcome(self, result: ReviewResult, gaps: Sequence[str]) -> Outcome:
        """A structurally short plan is not approvable whatever the reviewer answered.

        The reviewer's PASS is about the plan it read. If the plan is missing the evidence it claims, the
        pass is about a fiction, so the structural gap wins - the reviewer is not the only gate.
        """
        if result.status is not RunnerStatus.OK or result.verdict is None:
            return Outcome.REVIEW_FAILED
        if gaps:
            return Outcome.INCOMPLETE
        if result.is_pass:
            return Outcome.APPROVABLE
        if result.verdict is Verdict.PASS:
            # A PASS that carries a BLOCKER is a self-contradicting answer. `is_pass` already refused it;
            # mapping the verdict alone would let the contradiction through and open the door anyway.
            return Outcome.NEEDS_CHANGES
        return OUTCOME_BY_VERDICT.get(result.verdict, Outcome.NEEDS_CHANGES)

    def get(self, plan_hash: str) -> dict[str, Any]:
        return self.store.get(f"pf-{plan_hash[:16]}")

    def get_by_plan(self, plan_id: str) -> dict[str, Any]:
        """The stored record for a plan id, including the plan itself so it can be re-read verbatim."""
        for row in self.store.list(10_000):
            if row.get("plan") == plan_id:
                if "plan_document" not in row:
                    raise OpsError(f"preflight record for {plan_id} does not carry its plan")
                return row
        raise OpsError(f"no preflight record for plan {plan_id}")

    def list(self, limit: int = 20) -> list[dict[str, Any]]:
        return [{key: row[key] for key in ("plan", "plan_hash", "arguments_hash", "outcome", "approvable",
                                           "reason", "verdict", "created") if key in row}
                for row in self.store.list(limit)]


def declared_state_changing(plan: ChangePlan) -> tuple[str, ...]:
    """The names a plan authorises to act, so the verifier can compare them with what it will run.

    Verification is allowed to start something only if the plan said so *in advance*. This is the one place
    that extracts that declaration, so a plan cannot quietly grow a permitted action after review.

    The two vocabularies differ: a plan step says `ansible.apply` on a profile, the verifier runs a check
    named `systemd:unit-start`. Emitting the plan's own strings compares against a set that can never
    contain the check being run, and every state-changing check is refused forever.
    """
    # Only what the plan *names*. Mapping a profile to all of its state-changing checks would let a plan
    # that says `systemd: apply a config change` authorise `systemd:unit-start` as a side effect of the
    # vocabulary matching, which is not the same thing as declaring it.
    return tuple(sorted({change.declared_check for change in plan.changes
                         if change.state_changing and change.declared_check}))


def unmatched_declarations(plan: ChangePlan) -> tuple[str, ...]:
    """State-changing steps that name no check, so they authorise nothing and are reported.

    A profile on its own is a class of checks, not a declaration: `systemd` says what the step touches,
    `systemd:unit-start` says what it is allowed to do. Only the second is an authorisation.
    """
    known = set(declared_state_changing(plan))
    return tuple(sorted({f"{change.capability}:{change.target}" for change in plan.changes
                         if change.state_changing and change.declared_check not in known} - known))


#: `ChangePlan.targets` is a set of host or workload names; which kind each one is comes from the step
#: that names it. A name that appears only in an untyped step stays untyped and is reported, not guessed.
def unverifiable_steps(plan: ChangePlan) -> tuple[str, ...]:
    """Steps that name a profile but not the parts a `Target` needs, so nothing can be checked about them."""
    from .verify import REGISTRY

    profiles = {REGISTRY[name].profile for name in REGISTRY if REGISTRY[name].state_changing}
    return tuple(sorted({f"{change.capability}:{change.target}" for change in plan.changes
                         if change.profile in profiles and not change.resource}))


def verification_targets(plan: ChangePlan) -> tuple[Target, ...]:
    """The targets verification is asked about, derived from the plan's own steps.

    Each step declares a profile - the same field the state-changing declaration is mapped through - so
    the target set comes from what the plan says rather than from a default. A step whose profile names
    no registered check produces no target, and `unverified_targets` says so: a plan that says "fix the
    logs" has not said what should be checked afterwards, and inventing the target would let verification
    pass against something nobody planned for.
    """
    from .verify import Target as VTarget
    from .verify import http_target, repo_target, unit_target

    profiles = {REGISTRY[name].profile for name in REGISTRY if REGISTRY[name].state_changing}
    targets: list[Target] = []
    for change in plan.changes:
        if change.profile not in profiles or not change.resource:
            # A `Target` needs a host, a resource and an expectation, and none of them can be recovered
            # from one label: `target="web-1"` is a hostname, not a unit, a drop-in path and a revision.
            # Filling a label into all three produces a check that inspects a unit named after a host and
            # compares its start timestamp against a plan id, which nothing applied can ever satisfy.
            continue
        if change.profile == "systemd":
            targets.append(unit_target(change.host or change.target, change.resource,
                                       drop_in=change.expectation or None,
                                       expected_revision=change.expected_revision or None))
        elif change.profile == "http":
            targets.append(http_target(change.target, change.expectation or change.target))
        elif change.profile == "drift":
            targets.append(repo_target(change.target, change.expectation, host=change.host))
        else:
            targets.append(VTarget(change.profile, change.resource, change.host,
                                   (("expectation", change.expectation),) if change.expectation else (),
                                   change.expected_revision or None))
    return tuple(targets)


def unverified_targets(plan: ChangePlan) -> tuple[str, ...]:
    """Steps whose profile names no verification check, so nothing will be checked about them."""

    profiles = {REGISTRY[name].profile for name in REGISTRY if REGISTRY[name].state_changing}
    return tuple(sorted({f"{change.capability}:{change.target}" for change in plan.changes
                         if change.profile in profiles and not change.resource}))


def blocking_findings(result: ReviewResult) -> tuple[dict[str, Any], ...]:
    return tuple(finding.to_dict() for finding in result.findings
                 if finding.severity in (Severity.BLOCKER, Severity.MAJOR))
