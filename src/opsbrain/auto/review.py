"""The versioned review contract shared with DevBrain (DevBrain#30).

Two rules shape the whole module:

* **Only a PASS is ever a permission.** A crash, a timeout, a quota error, malformed JSON or a truncated
  answer all resolve to a non-OK `RunnerStatus`, and `ReviewResult.is_pass` is False for every one of them.
  There is no code path that turns "the reviewer did not answer" into "go ahead".
* **The reviewer observes, it never acts.** A `Reviewer` receives redacted text and returns a verdict. It
  is handed no executor, no credentials and no way to reach a target, so it cannot approve itself, read a
  secret, or change a host.

The wire format is JSON with an explicit `contract_version`, so a reviewer built against a different
version is rejected instead of being guessed at.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from ..changes import digest
from ..util import OpsError, new_id, now

#: Bumped whenever the JSON shape below changes incompatibly. A reviewer answering a different
#: version is a contract error, not a review.
CONTRACT_VERSION = "1.0"

#: Bumped when the wording of a rubric changes, so a verdict stays attributable to the rules that made it.
RUBRIC_VERSION = "opsbrain-rubric-1"

MAX_CONTEXT_CHARS = 200_000
MAX_OUTPUT_CHARS = 64_000
MAX_FINDINGS = 50


class Subject(StrEnum):
    """What is being reviewed. OpsBrain uses three of the four contract subjects."""

    CODE_CHANGE = "CODE_CHANGE"
    INFRA_PLAN = "INFRA_PLAN"
    INFRA_RESULT = "INFRA_RESULT"
    SECURITY_AUDIT = "SECURITY_AUDIT"


class Verdict(StrEnum):
    PASS = "PASS"  # noqa: S105 - a verdict label, not a credential
    NEEDS_CHANGES = "NEEDS_CHANGES"
    NEEDS_EVIDENCE = "NEEDS_EVIDENCE"
    DENY = "DENY"


class RunnerStatus(StrEnum):
    """Outcome of the attempt, orthogonal to the verdict. Only OK carries a meaningful verdict."""

    OK = "OK"
    TIMEOUT = "TIMEOUT"
    QUOTA_EXHAUSTED = "QUOTA_EXHAUSTED"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    INVALID_RESPONSE = "INVALID_RESPONSE"
    RUNNER_ERROR = "RUNNER_ERROR"
    UNAVAILABLE = "UNAVAILABLE"


class Severity(StrEnum):
    BLOCKER = "BLOCKER"
    MAJOR = "MAJOR"
    MINOR = "MINOR"
    INFO = "INFO"


#: Statuses that mean the reviewer never produced a usable opinion. None of them may pass.
FAILED_STATUSES = frozenset({
    RunnerStatus.TIMEOUT, RunnerStatus.QUOTA_EXHAUSTED, RunnerStatus.BUDGET_EXCEEDED,
    RunnerStatus.INVALID_RESPONSE, RunnerStatus.RUNNER_ERROR, RunnerStatus.UNAVAILABLE,
})


class ContractError(OpsError):
    """The answer does not satisfy the contract: wrong version, missing field, wrong type."""


@dataclass(frozen=True)
class Finding:
    """One problem. `evidence_refs` points at bundle entries, never at raw secrets."""

    severity: Severity
    summary: str
    evidence_refs: tuple[str, ...] = ()
    required_property: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {key: (list(value) if isinstance(value, tuple) else value) for key, value in asdict(self).items()}

    @staticmethod
    def from_dict(data: Any) -> Finding:
        if not isinstance(data, dict):
            raise ContractError("finding must be an object")
        severity = data.get("severity")
        if not isinstance(severity, str) or severity not in set(Severity):
            raise ContractError(f"finding.severity must be one of {[s.value for s in Severity]}, got {severity!r}")
        summary = data.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            raise ContractError("finding.summary must be a non-empty string")
        refs = data.get("evidence_refs", [])
        if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
            raise ContractError("finding.evidence_refs must be a list of strings")
        required = data.get("required_property")
        if required is not None and not isinstance(required, str):
            raise ContractError("finding.required_property must be a string or null")
        return Finding(Severity(severity), summary.strip(), tuple(refs), required)


@dataclass(frozen=True)
class ReviewLimits:
    """Ceilings handed to the runner. The runner enforces them; the service re-checks the result."""

    timeout_s: float = 300.0
    context_chars: int = 60_000
    output_chars: int = 8_000

    def clipped_context(self, context: str) -> str:
        return context if len(context) <= self.context_chars else context[: self.context_chars]


@dataclass(frozen=True)
class ReviewUsage:
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    calls: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ReviewRequest:
    """Everything the reviewer is allowed to see. Redaction happens before this object exists."""

    subject: Subject
    subject_ref: str
    objective: str
    contract_version: str = CONTRACT_VERSION
    rubric_version: str = RUBRIC_VERSION
    model: str = ""
    context: str = ""
    evidence_refs: tuple[str, ...] = ()
    limits: ReviewLimits = field(default_factory=ReviewLimits)
    review_id: str = ""

    def with_id(self) -> ReviewRequest:
        """Always re-derive the id from the content.

        A caller-supplied `review_id` is ignored rather than trusted. Honouring it would let a request for
        subject B present the id of subject A and be answered from A's stored PASS, without the reviewer
        ever being asked about B.
        """
        return ReviewRequest(**{**asdict_shallow(self), "review_id": self.stable_id()})

    def stable_id(self) -> str:
        """Deterministic id: re-delivering the same request must not create a second review.

        Derived from the content, not from a random value, so a retry after a timeout reuses the id and
        the store deduplicates instead of double-charging the budget.
        """
        # The effective context is what the reviewer actually saw, and the limits decide what that is:
        # hashing the raw context would let a redelivery under a wider limit reuse a verdict that was
        # produced for a clipped one, silently skipping whatever the wider window would have added.
        fingerprint = digest({
            "contract": self.contract_version,
            "rubric": self.rubric_version,
            "subject": self.subject.value,
            "subject_ref": self.subject_ref,
            "objective": self.objective,
            "evidence": sorted(self.evidence_refs),
            "model": self.model,
            "limits": {"timeout_s": self.limits.timeout_s,
                       "context_chars": self.limits.context_chars,
                       "output_chars": self.limits.output_chars},
            "context_hash": hashlib.sha256(self.limits.clipped_context(self.context).encode()).hexdigest(),
        })
        return f"rv-{fingerprint[:16]}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "review_id": self.review_id,
            "subject": self.subject.value,
            "subject_ref": self.subject_ref,
            "objective": self.objective,
            "rubric_version": self.rubric_version,
            "model": self.model,
            "context": self.limits.clipped_context(self.context),
            "evidence_refs": list(self.evidence_refs),
            "limits": {"timeout_s": self.limits.timeout_s,
                       "context_chars": self.limits.context_chars,
                       "output_chars": self.limits.output_chars},
        }


def asdict_shallow(request: ReviewRequest) -> dict[str, Any]:
    return {key: getattr(request, key) for key in request.__dataclass_fields__}


@dataclass(frozen=True)
class ReviewResult:
    review_id: str
    subject: Subject
    subject_ref: str
    status: RunnerStatus
    verdict: Verdict | None = None
    contract_version: str = CONTRACT_VERSION
    rubric_version: str = RUBRIC_VERSION
    model: str = ""
    findings: tuple[Finding, ...] = ()
    unverified_claims: tuple[str, ...] = ()
    next_checks: tuple[str, ...] = ()
    usage: ReviewUsage = field(default_factory=ReviewUsage)
    created: float = field(default_factory=now)
    note: str = ""

    @property
    def is_pass(self) -> bool:
        """The only truth that may authorise anything. A BLOCKER finding vetoes an otherwise PASS."""
        return (self.status is RunnerStatus.OK and self.verdict is Verdict.PASS
                and not any(finding.severity is Severity.BLOCKER for finding in self.findings))

    @property
    def blockers(self) -> tuple[Finding, ...]:
        return tuple(finding for finding in self.findings if finding.severity is Severity.BLOCKER)

    def to_dict(self) -> dict[str, Any]:
        return {
            "review_id": self.review_id,
            "contract_version": self.contract_version,
            "subject": self.subject.value,
            "subject_ref": self.subject_ref,
            "status": self.status.value,
            "verdict": self.verdict.value if self.verdict else None,
            "rubric_version": self.rubric_version,
            "model": self.model,
            "findings": [finding.to_dict() for finding in self.findings],
            "unverified_claims": list(self.unverified_claims),
            "next_checks": list(self.next_checks),
            "usage": self.usage.to_dict(),
            "created": round(self.created, 3),
            "note": self.note,
        }

    def brief(self) -> dict[str, Any]:
        """Small answer for a tool response: verdict, counts, the findings worth acting on."""
        out: dict[str, Any] = {"review": self.review_id, "subject": self.subject.value, "status": self.status.value}
        if self.verdict is not None:
            out["verdict"] = self.verdict.value
        out["is_pass"] = self.is_pass
        blocking = [finding for finding in self.findings if finding.severity in (Severity.BLOCKER, Severity.MAJOR)]
        if blocking:
            out["findings"] = [{"severity": finding.severity.value, "summary": finding.summary,
                                "evidence": list(finding.evidence_refs), "required": finding.required_property}
                               for finding in blocking[:8]]
        if self.unverified_claims:
            out["unverified_claims"] = list(self.unverified_claims[:8])
        if self.next_checks:
            out["next_checks"] = list(self.next_checks[:8])
        if self.note:
            out["note"] = self.note
        return out

    @staticmethod
    def failure(request: ReviewRequest, status: RunnerStatus, note: str,
                usage: ReviewUsage | None = None) -> ReviewResult:
        """A review that did not happen. Verdict stays None so no caller can mistake it for a decision."""
        if status is RunnerStatus.OK:
            raise ValueError("a failure needs a non-OK status")
        return ReviewResult(review_id=request.review_id or new_id("rv"), subject=request.subject,
                            subject_ref=request.subject_ref, status=status, rubric_version=request.rubric_version,
                            model=request.model, usage=usage or ReviewUsage(model=request.model), note=note)


def parse_review_response(request: ReviewRequest, payload: str) -> ReviewResult:
    """Strict parse of a runner's answer, after pulling the contract document out of any event stream.

    Anything unexpected - a wrong contract version, a missing verdict, a stray prefix, an empty body -
    becomes `INVALID_RESPONSE` with no verdict. It never degrades into a pass.
    """
    from .runners import extract_review_payload  # local import: runners imports this module

    text = extract_review_payload(payload).strip()
    if not text:
        return ReviewResult.failure(request, RunnerStatus.INVALID_RESPONSE, "empty response")
    try:
        document = json.loads(text)
    except ValueError as exc:
        return ReviewResult.failure(request, RunnerStatus.INVALID_RESPONSE, f"invalid JSON: {exc}")
    return build_result(request, document)


def build_result(request: ReviewRequest, document: Any) -> ReviewResult:
    if not isinstance(document, dict):
        return ReviewResult.failure(request, RunnerStatus.INVALID_RESPONSE, "response must be a JSON object")
    version = document.get("contract_version")
    if not isinstance(version, str) or not version:
        return ReviewResult.failure(request, RunnerStatus.INVALID_RESPONSE,
                                    "contract_version is required: a response that does not state which "
                                    "wire format it speaks has not demonstrated compatibility")
    if version != CONTRACT_VERSION:
        return ReviewResult.failure(request, RunnerStatus.INVALID_RESPONSE,
                                    f"contract version mismatch: got {version!r}, expected {CONTRACT_VERSION!r}")
    status = document.get("status", RunnerStatus.OK.value)
    if not isinstance(status, str) or status not in set(RunnerStatus):
        return ReviewResult.failure(request, RunnerStatus.INVALID_RESPONSE, f"unknown status {status!r}")
    parsed_status = RunnerStatus(status)
    if parsed_status in FAILED_STATUSES:
        # The runner told us it failed. Keep its note, drop any verdict it may have optimistically sent.
        return ReviewResult.failure(request, parsed_status, str(document.get("note", ""))[:200])
    raw_verdict = document.get("verdict")
    if not isinstance(raw_verdict, str) or raw_verdict not in set(Verdict):
        return ReviewResult.failure(request, RunnerStatus.INVALID_RESPONSE,
                                    f"missing or unknown verdict {raw_verdict!r}")
    raw_findings = document.get("findings", [])
    if not isinstance(raw_findings, list):
        return ReviewResult.failure(request, RunnerStatus.INVALID_RESPONSE, "findings must be a list")
    if len(raw_findings) > MAX_FINDINGS:
        return ReviewResult.failure(request, RunnerStatus.INVALID_RESPONSE, f"too many findings: {len(raw_findings)}")
    try:
        findings = tuple(Finding.from_dict(item) for item in raw_findings)
    except ContractError as exc:
        return ReviewResult.failure(request, RunnerStatus.INVALID_RESPONSE, str(exc))
    try:
        claims = _string_tuple(document.get("unverified_claims", []), "unverified_claims")
        checks = _string_tuple(document.get("next_checks", []), "next_checks")
    except ContractError as exc:
        return ReviewResult.failure(request, RunnerStatus.INVALID_RESPONSE, str(exc))
    usage = _usage(document)
    if isinstance(usage, str):
        return ReviewResult.failure(request, RunnerStatus.INVALID_RESPONSE, usage)
    input_tokens, output_tokens = usage
    return ReviewResult(
        review_id=request.review_id, subject=request.subject, subject_ref=request.subject_ref,
        status=parsed_status, verdict=Verdict(raw_verdict), contract_version=CONTRACT_VERSION,
        rubric_version=document.get("rubric_version") or request.rubric_version,
        model=str(document.get("model") or request.model), findings=findings,
        unverified_claims=claims, next_checks=checks,
        usage=ReviewUsage(model=str(document.get("model") or request.model),
                          input_tokens=input_tokens, output_tokens=output_tokens, calls=1),
    )


#: No single answer may claim more than this. A reviewer reporting absurd usage is reporting a bug, and
#: the budget must not be charged - or credited - on the strength of it.
MAX_REPORTED_TOKENS = 10_000_000


def _usage(document: dict[str, Any]) -> tuple[int, int] | str:
    """Validated (input, output) token counts, or the reason the answer is unusable.

    Usage arrives from the same untrusted JSON as the verdict, and it is what the monetary budget is
    computed from, so an unchecked `int()` here is both a crash (`"unknown"`) and a hole (a negative count
    that *reduces* recorded spend). Both directions have to be closed.
    """
    counts: list[int] = []
    for name in ("input_tokens", "output_tokens"):
        value = document.get(name, 0)
        if value is None:
            counts.append(0)
            continue
        if isinstance(value, bool) or not isinstance(value, int):
            return f"{name} must be an integer, got {type(value).__name__}"
        if value < 0:
            return f"{name} must not be negative, got {value}"
        if value > MAX_REPORTED_TOKENS:
            return f"{name} is implausibly large: {value}"
        counts.append(value)
    return counts[0], counts[1]


def _string_tuple(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ContractError(f"{name} must be a list of strings")
    return tuple(value)


def required_checks(result: ReviewResult) -> tuple[str, ...]:
    """Read-only diagnostics the reviewer asks for. Safe to execute without a change plan."""
    return tuple(check for check in result.next_checks if check.strip())


def review_summary(results: Iterable[ReviewResult]) -> dict[str, Any]:
    rows = list(results)
    statuses: dict[str, int] = {}
    for result in rows:
        statuses[result.status.value] = statuses.get(result.status.value, 0) + 1
    return {
        "reviews": len(rows),
        "passed": sum(1 for result in rows if result.is_pass),
        "by_status": statuses,
        "tokens_in": sum(result.usage.input_tokens for result in rows),
        "tokens_out": sum(result.usage.output_tokens for result in rows),
    }


def response_document(verdict: Verdict, findings: Sequence[Finding] = (), *, unverified: Sequence[str] = (),
                      next_checks: Sequence[str] = (), model: str = "", input_tokens: int = 0,
                      output_tokens: int = 0) -> dict[str, Any]:
    """The shape a reviewer (or the fake one in tests) must answer with."""
    return {
        "contract_version": CONTRACT_VERSION,
        "status": RunnerStatus.OK.value,
        "verdict": verdict.value,
        "rubric_version": RUBRIC_VERSION,
        "model": model,
        "findings": [finding.to_dict() for finding in findings],
        "unverified_claims": list(unverified),
        "next_checks": list(next_checks),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    }


@runtime_checkable
class Reviewer(Protocol):
    """The only surface a review implementation has. It is handed text and returns text."""

    name: str

    def review(self, request: ReviewRequest) -> str:
        """Return the raw JSON answer. Raise `OpsError` for a runner-level failure."""
