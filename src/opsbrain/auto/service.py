"""ReviewService: the single way a review is obtained, recorded and accounted for.

Outside it, budgets do not exist and redelivery double-charges. Inside it:

* a request gets a deterministic id, so a retry after a timeout reuses the stored result instead of
  spawning a second review;
* model calls, wall time and spend are counted against the operator's limits *before* a call is made, so
  an exhausted budget fails fast with `BUDGET_EXCEEDED` rather than after the fact;
* every result is persisted with its subject, rubric version, model and usage, which is what makes a later
  decision auditable: the verdict can be traced back to the rules and evidence it was produced from.
"""

from __future__ import annotations

import threading
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..audit import AuditLog
from ..util import OpsError, new_id
from .config import AutoConfig
from .evidence import EvidenceBundle, EvidenceCollector, EvidenceStore, Observation, check_evidence, passed, reason_code
from .plan import ChangePlan
from .preflight import Outcome, Preflight, PreflightResult
from .review import (
    CONTRACT_VERSION,
    Reviewer,
    ReviewRequest,
    ReviewResult,
    RunnerStatus,
    Verdict,
    review_summary,
)
from .runners import CodexReviewer, FakeReviewer, RunnerSettings, probe_capabilities, run_review
from .store import RecordStore, atomic_claim, release_claim
from .verify import Target, VerificationReport, Verifier

if TYPE_CHECKING:  # `config` imports this package; keep the edge one-directional
    from ..config import Config

#: Aliases: the `list` method below shadows the builtin inside this class body, so annotations
#: that need a sequence name one instead of writing `list[...]` inline.
Records = list[dict[str, Any]]
Results = list[ReviewResult]

#: Rough USD per 1M tokens, used only to turn a token count into the operator's budget unit. Configurable
#: through `budget_usd`; when it is 0 no money limit is enforced at all.
USD_PER_MILLION_TOKENS = 2.50

#: How long a single-review claim may be held before a crashed holder is treated as gone.
TTL_S = 900.0


def _has_blocker(findings: Any) -> bool:
    return isinstance(findings, list) and any(
        isinstance(finding, dict) and finding.get("severity") == "BLOCKER" for finding in findings)


def _counter(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


class ReviewService:
    def __init__(self, config: AutoConfig, root: Path, *, reviewer: Reviewer | None = None,
                 reviewer_factory: Any = None):
        self.config = config
        self.root = root
        self.store = RecordStore(root / "reviews", ("rv",))
        self.reviews = config.review
        self._reviewer = reviewer
        self._factory = reviewer_factory
        self._lock = threading.Lock()
        self._calls = 0
        self._tokens_in = 0
        self._tokens_out = 0
        self._spend_usd = 0.0
        self._per_id: dict[str, threading.Lock] = {}
        self._recover_usage()

    def _recover_usage(self) -> None:
        """Rebuild the counters from the stored reviews.

        Without this a restart hands out a fresh `max_model_calls` and a fresh `budget_usd`, and a
        separately invoked `opsbrain autonomy status` reports zero for work the server already did. The
        ceilings are only ceilings if they survive a restart.
        """
        rows = self.store.list(1_000_000)
        calls = tokens_in = tokens_out = 0
        for document in rows:
            usage = document.get("usage")
            if not isinstance(usage, dict):
                continue
            if document.get("status") == RunnerStatus.OK.value or usage.get("calls"):
                calls += 1
            tokens_in += _counter(usage.get("input_tokens"))
            tokens_out += _counter(usage.get("output_tokens"))
        with self._lock:
            self._calls = calls
            self._tokens_in = tokens_in
            self._tokens_out = tokens_out
            self._spend_usd = (tokens_in + tokens_out) / 1_000_000 * USD_PER_MILLION_TOKENS

    def _is_stub(self) -> bool:
        """True only for the built-in stub. A test that injects its own fake is a test, and must keep working."""
        return type(self.reviewer()) is FakeReviewer

    def _id_lock(self, review_id: str) -> threading.Lock:
        """One lock per review id, so parallel redelivery of the same request does not review it twice."""
        with self._lock:
            return self._per_id.setdefault(review_id, threading.Lock())

    # -- accounting -------------------------------------------------------------------------------
    def usage(self) -> dict[str, Any]:
        with self._lock:
            return {"model_calls": self._calls, "input_tokens": self._tokens_in, "output_tokens": self._tokens_out,
                    "spend_usd": round(self._spend_usd, 4),
                    "max_model_calls": self.reviews.max_model_calls,
                    "budget_usd": self.reviews.budget_usd}

    def projected_cost(self, request: ReviewRequest) -> float:
        """What this request could possibly cost, from the limits rather than from what it later reports.

        A check that only asks whether spend has *already* reached the ceiling admits a call that then
        overshoots it arbitrarily, which makes `budget_usd` a suggestion instead of a ceiling. The worst
        case is bounded by what the operator allowed into the context plus the allowed output.
        """
        limit = self.reviews.context_chars / 4 + self.reviews.output_chars / 4
        return limit / 1_000_000 * USD_PER_MILLION_TOKENS

    def _reserve(self, request: ReviewRequest) -> None:
        """Counts a call before it happens, against both the call count and the projected spend.

        Reserving per attempt, not per request: `run_review` may invoke the reviewer up to
        `max_retries + 1` times, and a single reservation would let three paid calls pass one check.
        """
        with self._lock:
            if self._calls >= self.reviews.max_model_calls:
                raise BudgetExceeded(f"model call budget exhausted ({self.reviews.max_model_calls} calls)")
            if self.reviews.budget_usd:
                projected = self._spend_usd + self.projected_cost(request)
                if projected > self.reviews.budget_usd:
                    raise BudgetExceeded(
                        f"this call could cost up to ${self.projected_cost(request):.4f} and would take the "
                        f"total to ${projected:.4f}, over budget_usd=${self.reviews.budget_usd:.2f}")
            self._calls += 1

    def _charge(self, result: ReviewResult) -> None:
        with self._lock:
            self._tokens_in += result.usage.input_tokens
            self._tokens_out += result.usage.output_tokens
            tokens = result.usage.input_tokens + result.usage.output_tokens
            self._spend_usd += tokens / 1_000_000 * USD_PER_MILLION_TOKENS

    def reset_usage(self) -> None:
        with self._lock:
            self._calls, self._tokens_in, self._tokens_out, self._spend_usd = 0, 0, 0, 0.0

    # -- reviewer ---------------------------------------------------------------------------------
    def reviewer(self) -> Reviewer:
        if self._reviewer is not None:
            return self._reviewer
        if self._factory is not None:
            self._reviewer = self._factory(self.settings())
            return self._reviewer
        if self.reviews.runner == "fake":
            self._reviewer = FakeReviewer()
        else:
            self._reviewer = CodexReviewer(self.settings())
        return self._reviewer

    def settings(self) -> RunnerSettings:
        review = self.reviews
        return RunnerSettings(runner=review.runner, command=tuple(review.command), model=review.model,
                              auth=review.auth, timeout_s=review.timeout_s, max_parallel=review.max_parallel,
                              max_retries=review.max_retries, max_model_calls=review.max_model_calls,
                              budget_usd=review.budget_usd, snapshot_dir=review.snapshot_dir,
                              scratch_home=review.scratch_home, sandbox=tuple(review.sandbox), live=review.live)

    def capabilities(self) -> dict[str, Any]:
        return probe_capabilities(self.settings())

    # -- the one entry point ----------------------------------------------------------------------
    def review(self, request: ReviewRequest) -> ReviewResult:
        """Obtain, validate, record and return a review. Never raises for a runner failure."""
        if not self.config.enabled:
            # The master switch, enforced here as well as at the facade. This method is public, and a
            # pipeline that is "off" but still answers review requests has a gate that is a convention.
            raise OpsError("auto.enabled is false: the review pipeline is off")
        if self.reviews.runner == "fake" and self._is_stub():
            # The stub answers PASS to anything, and it is the documented default. With `auto.enabled:
            # true` and nothing else configured, it would otherwise manufacture a permission.
            return ReviewResult.failure(request, RunnerStatus.UNAVAILABLE,
                                        "auto.review.runner is `fake`: a stub cannot issue a permission, so "
                                        "configure a real runner before enabling autonomy")
        if request.contract_version != CONTRACT_VERSION:
            raise OpsError(f"review request built for contract {request.contract_version!r}, "
                           f"this build speaks {CONTRACT_VERSION!r}")
        # Clip first, then derive the id from what the reviewer would actually see. The other order lets a
        # redelivery under a wider limit reuse a verdict produced for a clipped context.
        clipped = request.limits.clipped_context(request.context)
        if clipped != request.context:
            request = ReviewRequest(**{**request.__dict__, "context": clipped})
        request = request.with_id()
        claim = self.root / "claims" / f"{request.review_id}.claim"
        # The lock covers the in-process race; the claim file covers two processes (a server and the CLI).
        # Either alone would still let a duplicate through.
        with self._id_lock(request.review_id):
            if atomic_claim(claim, f"pid-{id(self)}", TTL_S) is None:
                return ReviewResult.failure(request, RunnerStatus.RUNNER_ERROR,
                                           "another worker is already reviewing this request; "
                                           "re-issue once it finishes")
            try:
                return self._review_claimed(request, claim)
            finally:
                release_claim(claim, f"pid-{id(self)}")

    def _review_claimed(self, request: ReviewRequest, claim: Path) -> ReviewResult:
        if self.store.has(request.review_id):
            cached = self.store.get(request.review_id)
            if cached.get("status") == RunnerStatus.OK.value:
                return self._rebuild_cached(request, cached)
            return ReviewResult(review_id=request.review_id, subject=request.subject,
                                subject_ref=request.subject_ref, status=RunnerStatus(cached["status"]),
                                verdict=None, contract_version=cached.get("contract_version", CONTRACT_VERSION),
                                rubric_version=cached.get("rubric_version", request.rubric_version),
                                model=cached.get("model", request.model),
                                note=cached.get("note", "cached: the review never produced a verdict"))
        # `before_attempt` is the only reservation point: it fires once per invocation, so the first
        # attempt is charged exactly once and a retry has to pass the budget check too.
        result = run_review(self.reviewer(), request, retries=self.reviews.max_retries,
                            before_attempt=lambda: self._reserve(request))
        self._charge(result)
        self._record(request, result)
        return result

    def review_many(self, requests: Results) -> Results:
        """Run several reviews with the configured parallelism. A failure in one never hides another."""
        if not requests:
            return []
        workers = max(1, min(self.reviews.max_parallel, len(requests)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="opsbrain-review") as pool:
            return list(pool.map(self.review, requests))

    def _rebuild_cached(self, request: ReviewRequest, cached: dict[str, Any]) -> ReviewResult:
        """Rehydrate a stored verdict so a redelivery returns the same decision, not a weakened one."""
        from .review import Finding, build_result  # local import keeps the module graph flat

        document = {
            "contract_version": cached.get("contract_version", CONTRACT_VERSION),
            "status": cached.get("status", "OK"),
            "verdict": cached.get("verdict"),
            "rubric_version": cached.get("rubric_version", request.rubric_version),
            "model": cached.get("model", request.model),
            "findings": cached.get("findings", []),
            "unverified_claims": cached.get("unverified_claims", []),
            "next_checks": cached.get("next_checks", []),
            "input_tokens": cached.get("usage", {}).get("input_tokens", 0),
            "output_tokens": cached.get("usage", {}).get("output_tokens", 0),
        }
        result = build_result(request, document)
        # Findings are reconstructed from the stored documents, not dropped: a redelivery must not lose
        # the BLOCKER that made the first answer a refusal.
        if result.status is RunnerStatus.OK and cached.get("findings"):
            try:
                restored = tuple(Finding.from_dict(item) for item in cached["findings"])
            except OpsError:
                return ReviewResult.failure(request, RunnerStatus.INVALID_RESPONSE, "stored findings are unreadable")
            result = ReviewResult(**{**result.__dict__, "findings": restored})
        return result

    def _record(self, request: ReviewRequest, result: ReviewResult) -> None:
        document = result.to_dict()
        document["usage"] = result.usage.to_dict()
        self.store.put(result.review_id or new_id("rv"), document)

    def get(self, review_id: str) -> dict[str, Any]:
        return self.store.get(review_id)

    def list(self, limit: int = 20) -> Records:
        rows = self.store.list(limit)
        return [{**{key: row[key] for key in ("review_id", "subject", "subject_ref", "status", "verdict",
                                              "rubric_version", "model", "created") if key in row},
                 # `status=OK, verdict=PASS` is not the same as a pass: a BLOCKER finding vetoes it, and a
                 # listing that showed only the verdict would report a refusal as a permission.
                 "is_pass": row.get("status") == RunnerStatus.OK.value
                 and row.get("verdict") == Verdict.PASS.value
                 and not _has_blocker(row.get("findings"))}
                for row in rows]

    def summary(self, results: Results) -> dict[str, Any]:
        return {**review_summary(results), **self.usage()}


class BudgetExceeded(OpsError):
    """The configured call or spend ceiling would be crossed by this request."""


class AutoService:
    """Facade the rest of OpsBrain talks to. Owns the review service and, later, the pipeline stages."""

    def __init__(self, config: Config, *, reviewer: Reviewer | None = None, reviewer_factory: Any = None,
                 root: Path | None = None, collector: EvidenceCollector | None = None):
        self.audit = AuditLog(config.data_path / "audit.jsonl")
        self.config = config
        self.auto: AutoConfig = config.auto
        self.root = root or (config.data_path / "auto")
        self.reviews = ReviewService(self.auto, self.root, reviewer=reviewer, reviewer_factory=reviewer_factory)
        self.evidence = EvidenceStore(self.root / "evidence",
                                      max_artifact_bytes=self.auto.evidence.max_bundle_bytes)
        self._collector = collector
        self._preflight: Preflight | None = None
        self._verifier: Verifier | None = None
        #: Bound by `Core` right after construction. The Verifier needs a Core, and Core builds this
        #: service, so the link is made explicitly by the owner rather than passed in and defaulted.
        self.core: Any = None

    @property
    def enabled(self) -> bool:
        return self.auto.enabled

    @property
    def autonomous(self) -> bool:
        return self.enabled and self.auto.decision.autonomous

    def guard_enabled(self) -> None:
        if not self.enabled:
            raise OpsError("autonomous pipeline is disabled: set auto.enabled=true in the config")

    # -- evidence ---------------------------------------------------------------------------------
    def collector(self, *, allowed: Sequence[str], change_id: str = "") -> EvidenceCollector:
        """The collector is created with an explicit capability allowlist and nothing else.

        A collector without a list of permitted probes would let any capability the service can reach end
        up inside a bundle, so it is never defaulted: the caller has to say what may be collected.
        """
        if not allowed:
            raise OpsError("evidence collection needs an explicit list of allowed capabilities")
        if self._collector is None:
            return EvidenceCollector(self.evidence, self.auto.evidence, allowed=allowed, change_id=change_id)
        # An injected collector is a test double. Rebind it to this request rather than returning it as
        # configured earlier, so the per-call allowlist and change binding cannot be quietly bypassed.
        self._collector.allowed = frozenset(allowed)
        self._collector.change_id = change_id
        return self._collector

    def collect_evidence(self, objective: str, observations: Sequence[Observation], *, allowed: Sequence[str],
                         change_id: str = "", **fields: Any) -> dict[str, Any]:
        """Collect a bundle, persist it, and answer with its summary - never with payload text."""
        self.guard_enabled()
        bundle = self.collector(allowed=allowed, change_id=change_id).collect(objective, observations, **fields)
        saved = self.evidence.save(bundle)
        self.audit.record(event="evidence_collected", bundle=saved.id, change=change_id,
                          entries=len(saved.entries), digest=saved.digest)
        return saved.summary()

    def verify_evidence(self, bundle_id: str, *, now_s: float | None = None,
                        change_id: str | None = None) -> dict[str, Any]:
        """Re-derive every hash and re-test every policy. The first reason code is the one to log."""
        checks = self.evidence.verify(bundle_id, now_s=now_s, change_id=change_id)
        return {"bundle": bundle_id, "reason": reason_code(checks), "passed": passed(checks),
                "checks": [check.to_dict() for check in checks]}

    def evidence_list(self, limit: int = 20) -> Records:
        return self.evidence.list(limit)

    # -- preflight --------------------------------------------------------------------------------
    def preflight(self) -> Preflight:
        if self._preflight is None:
            self._preflight = Preflight(self.auto, self.reviews, self.root, self.evidence)
        return self._preflight

    def review_plan(self, plan: ChangePlan, *, evidence: str = "") -> dict[str, Any]:
        """Review a plan before anything changes, and answer with the outcome, not a boolean.

        `evidence` is a bundle id; when given, its redacted render travels with the plan so the reviewer
        judges the plan against the observations it claims to rest on rather than against its own summary.
        """
        self.guard_enabled()
        # The plan names its own evidence. Trusting only the caller's argument would let a plan that
        # declares a bundle be reviewed against a different one - or against none at all.
        bundle_id = evidence or plan.evidence_bundle
        bundle: EvidenceBundle | None = None
        if bundle_id:
            try:
                bundle = self.evidence.get(bundle_id)
            except OpsError as exc:
                # A plan that names a bundle nobody stored is not reviewable, and an exception here would
                # leave the caller with a stack trace instead of a decision.
                refused = self.preflight().refuse(plan, Outcome.INCOMPLETE,
                                                  f"the plan names evidence {bundle_id}, which cannot be read: {exc}")
                self.audit.record(event="preflight", plan=plan.id, outcome=refused.outcome.value,
                                  approvable=False, reason=refused.reason, review="")
                return refused.to_dict()
            # The expected change is the one the bundle itself recorded, or none at all when it is not
            # bound. Passing a prefix of the plan id compared "pl" against every entry and rejected each
            # one for belonging to something else.
            checks = check_evidence(bundle, self.evidence.load_artifacts(bundle)[0],
                                    change_id=bundle.change_id or None)
            if reason_code(checks) != "evidence_fresh":
                refused = self.preflight().refuse(plan, Outcome.INCOMPLETE,
                                                  f"the evidence bundle the plan names is {reason_code(checks)}: "
                                                  f"{next((c.detail for c in checks if not c.ok), 'unusable')}")
                self.audit.record(event="preflight", plan=plan.id, outcome=refused.outcome.value,
                                  approvable=False, reason=refused.reason, review="")
                return refused.to_dict()
        result: PreflightResult = self.preflight().run(plan, bundle)
        self.audit.record(event="preflight", plan=plan.id, outcome=result.outcome.value,
                          approvable=result.approvable, reason=result.reason, review=result.review_id)
        return result.to_dict()

    def preflight_list(self, limit: int = 20) -> Records:
        return self.preflight().list(limit)

    def plan_summary(self, document: dict[str, Any]) -> dict[str, Any]:
        return ChangePlan.from_dict(document).summary()

    # -- verification -----------------------------------------------------------------------------
    def verifier(self) -> Verifier:
        if self._verifier is None:
            if self.core is None:
                raise OpsError("verification needs a Core; build OpsBrain, not AutoService alone")
            self._verifier = Verifier(self.auto, self.core)
        return self._verifier

    def verification_checks(self) -> Records:
        """What verification can currently demand, with each check's own statement of its purpose."""
        return self.verifier().describe()

    def verify_change(self, change_id: str, targets: Sequence[Target], **kwargs: Any) -> dict[str, Any]:
        """Run the post-change checks for one change and answer with the report, not with a boolean."""
        self.guard_enabled()
        report: VerificationReport = self.verifier().verify(change_id, targets, **kwargs)
        self.audit.record(event="verified", change=change_id, status=report.status.value,
                          checks=len(report.results), observation_s=round(report.observation_s, 3))
        return report.brief()

    def verify_overview(self) -> dict[str, Any]:
        if self.core is None:
            return {"bound": False}
        verifier = self.verifier()
        return {
            "bound": True,
            "observation_s": self.auto.verify.observation_s,
            "require_observation": self.auto.verify.require_observation,
            "allow_state_changing_checks": self.auto.verify.allow_state_changing_checks,
            "available": list(verifier.available()),
        }

    def evidence_overview(self) -> dict[str, Any]:
        bundles = self.evidence.list(1000)
        return {"bundles": len(bundles), "fresh_window_s": self.auto.evidence.max_age_s,
                "max_bundle_bytes": self.auto.evidence.max_bundle_bytes,
                "require_inventory_hash": self.auto.evidence.require_inventory_hash,
                "require_target_identity": self.auto.evidence.require_target_identity,
                "recent": bundles[:5]}

    def overview(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "mode": self.auto.decision.mode,
            "autonomous": self.autonomous,
            "emergency_stop": self.auto.decision.emergency_stop,
            "policy_version": self.auto.decision.policy_version,
            "runner": self.auto.review.runner,
            "live": self.auto.review.live,
            "model": self.auto.review.model,
            "auth": self.auto.review.auth,
            "budget": self.reviews.usage(),
            "reviews": len(self.reviews.list(1000)),
            "evidence": self.evidence_overview(),
            "verify": self.verify_overview(),
            "preflights": len(self.preflight().list(1000)),
        }
