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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..util import OpsError, new_id
from .config import AutoConfig
from .ledger import BudgetLedger
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
        self.ledger = BudgetLedger(root / "budget.jsonl")
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
        """Rebuild the counters from the durable budget ledger.

        A restart must not hand out a fresh `max_model_calls` and a fresh `budget_usd`, and a separately
        invoked `opsbrain autonomy status` must report what the server actually spent. The ceilings are
        only ceilings if they survive a restart and if every reserved attempt is in the ledger - including
        the ones that went on to fail, since a failed attempt still cost money.
        """
        ledger = self.ledger
        with self._lock:
            self._calls = ledger.calls
            self._tokens_in = ledger.input_tokens
            self._tokens_out = ledger.output_tokens
            self._spend_usd = ledger.spend_usd

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
        """Admit one attempt, against a balance every process can see.

        Reserved per attempt, not per request: `run_review` may invoke the reviewer up to
        `max_retries + 1` times, and one reservation per request would let three paid calls pass a single
        check. The check and the record happen inside the ledger's lock, so a server and a CLI racing on
        the same data directory cannot both be admitted against the same money.
        """
        admitted, reason = self.ledger.admit(
            self.projected_cost(request), kind="reserve",
            max_calls=self.reviews.max_model_calls, max_spend=self.reviews.budget_usd)
        with self._lock:
            self._calls = self.ledger.calls
            self._spend_usd = self.ledger.spend_usd
        if not admitted:
            raise BudgetExceeded(reason)

    def _charge(self, result: ReviewResult) -> None:
        """Record what an admitted attempt actually cost, so the ceiling is measured against reality."""
        self.ledger.reconcile(0.0, kind="settle",
                              input_tokens=result.usage.input_tokens,
                              output_tokens=result.usage.output_tokens)
        with self._lock:
            self._tokens_in = self.ledger.input_tokens
            self._tokens_out = self.ledger.output_tokens

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
                              scratch_home=review.scratch_home, sandbox=tuple(review.sandbox),
                              api_key_env=review.api_key_env, live=review.live)

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
        # The lease has to outlive the whole retry window, or a redelivery arriving while the original
        # attempt is still running sees a stale claim, starts a second paid review, and deduplication
        # quietly stops deduplicating.
        ttl = self.reviews.timeout_s * (self.reviews.max_retries + 1) + 60.0
        claim = self.root / "claims" / f"{request.review_id}.claim"
        # The lock covers the in-process race; the claim file covers two processes (a server and the CLI).
        # Either alone would still let a duplicate through.
        with self._id_lock(request.review_id):
            if atomic_claim(claim, f"pid-{id(self)}", ttl) is None:
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
                 root: Path | None = None):
        self.config = config
        self.auto: AutoConfig = config.auto
        self.root = root or (config.data_path / "auto")
        self.reviews = ReviewService(self.auto, self.root, reviewer=reviewer, reviewer_factory=reviewer_factory)

    @property
    def enabled(self) -> bool:
        return self.auto.enabled

    @property
    def autonomous(self) -> bool:
        return self.enabled and self.auto.decision.autonomous

    def guard_enabled(self) -> None:
        if not self.enabled:
            raise OpsError("autonomous pipeline is disabled: set auto.enabled=true in the config")

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
        }
