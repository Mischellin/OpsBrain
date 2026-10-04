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

import contextlib
import json
import threading
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..audit import AuditLog
from ..util import OpsError, new_id, now
from .approval import ApprovalStore, binding_for
from .config import AutoConfig
from .decision import ApprovalEngine, Reason
from .evidence import EvidenceBundle, EvidenceCollector, EvidenceStore, Observation, check_evidence, passed, reason_code
from .ledger import BudgetLedger
from .plan import ChangePlan
from .preflight import Outcome, Preflight, PreflightResult, unverified_targets, verification_targets
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
        """Rebuild the counters from the stored reviews.

        Without this a restart hands out a fresh `max_model_calls` and a fresh `budget_usd`, and a
        separately invoked `opsbrain autonomy status` reports zero for work the server already did. The
        ceilings are only ceilings if they survive a restart.
        """
        ledger = self.ledger
        with self._lock:
            self._calls = ledger.calls
            self._tokens_in = ledger.input_tokens
            self._tokens_out = ledger.output_tokens
            self._spend_usd = ledger.spend_usd

    def is_stub(self) -> bool:
        """True only for the stub the *configuration* selected, not for one a caller injected.

        Both are `FakeReviewer` instances, and the difference is not the class but where it came from: the
        default runner is a stub nobody chose, while an injected reviewer - a test double or a real
        integration - is something a caller picked on purpose, and a guard must not overrule that on the
        basis of a config field the caller never touched.
        """
        return self._reviewer is None and self.reviews.runner == "fake"

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
        admitted, reason = self.ledger.admit(
            self.projected_cost(request), kind="reserve",
            max_calls=self.reviews.max_model_calls, max_spend=self.reviews.budget_usd)
        with self._lock:
            self._calls = self.ledger.calls
            self._spend_usd = self.ledger.spend_usd
        if not admitted:
            raise BudgetExceeded(reason)

    def _charge(self, result: ReviewResult) -> None:
        self.ledger.reconcile(0.0, kind="settle", input_tokens=result.usage.input_tokens,
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
        if self.is_stub():
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
        # attempt still runs sees a stale claim and starts a second paid review.
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
            # A runner failure is not an answer, so it is not a cached answer either. Returning it forever
            # meant the engine's `RETRY` / "retry the review" could not re-run the reviewer: the very next
            # call handed back the same TIMEOUT or QUOTA_EXHAUSTED until the repair budget ran out and the
            # change blocked. The spend is already charged and stays charged - what is retried is the
            # review, not the billing.
            self.store.discard(request.review_id)
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
        self._engine: ApprovalEngine | None = None
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
    def engine(self) -> ApprovalEngine:
        if self._engine is None:
            self._engine = ApprovalEngine(self.auto, ApprovalStore(self.root / "approvals"))
        return self._engine

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

    def verify_plan(self, plan_id: str) -> dict[str, Any]:
        """Verify a change from the targets its own plan declared.

        The change id is the plan's, never a caller's: a report that is not attributable to the change it
        describes proves nothing, and this is the one surface where that is cheap to get wrong.
        """
        self.guard_enabled()
        record = self.preflight().get_by_plan(plan_id)
        plan = ChangePlan.from_dict(record["plan_document"])
        targets = verification_targets(plan)
        if not targets:
            return {"plan": plan_id, "status": "not_verifiable",
                    "unverified_targets": list(unverified_targets(plan)),
                    "approvable": False,
                    "note": "the plan declares no target a registered check can be run against"}
        return self.verify_change(plan.id, targets, applied_at=plan.created,
                                 declared=record.get("declared_checks", ()))

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

    def decide_change(self, change_id: str, plan_id: str, *,
                      verification: dict[str, Any] | None = None) -> dict[str, Any]:
        """Ask the engine about one pending change, and issue the approval if it says yes.

        This is the step that makes the autonomous path reachable at all. Everything before it - the
        review, the preflight, the evidence - produces facts; without something that gathers them and asks
        the deterministic engine, the gate in front of the executor has nothing to accept and every
        operation goes to a human.

        Both ids are named explicitly. The change store and the preflight store key different things and
        do not link them, so guessing which plan a change belongs to would mean deciding about a document
        nobody named.

        Every `Inputs` field is gathered from stored state, not from the caller. A caller-supplied
        `policy_allows` or `review_verdict` would be the caller deciding on the engine's behalf, which is
        the one thing the engine exists to prevent. What the caller may add is the verification report,
        because the checks can only be run after something has been applied.
        """
        # Imported here, not at module scope: `config` imports this package, so a top-level import of
        # `Access` closes a cycle.
        from ..config import Access
        from .decision import Decision, Inputs

        self.guard_enabled()
        if self.core is None:
            raise OpsError("deciding needs a Core; build OpsBrain, not AutoService alone")
        change = self.core.changes.get(change_id)
        if change.state not in ("pending", "approved"):
            return self._decision_refused(change_id, plan_id,
                                          f"the change is {change.state}; a decision about work that has "
                                          f"already run, or was discarded, authorises nothing",
                                          review_id="")
        if change.expired:
            return self._decision_refused(change_id, plan_id, "the change has expired; plan again",
                                          review_id="")
        self._mark_workflow_start(change_id)
        change = self.core.changes.get(change_id)
        record = self.preflight().get_by_plan(plan_id)
        plan = ChangePlan.from_dict(record["plan_document"])
        # The outer record is selected by plan id, but a nested document that parses is not thereby the
        # same plan - and capability, target, arguments and profile are all read out of it. A stored PASS
        # for plan A would otherwise authorise a change described only by plan B.
        if plan.id != plan_id or (record.get("plan_hash") and plan.plan_hash != record["plan_hash"]):
            raise OpsError(
                f"the preflight record for {plan_id} carries a different plan (id={plan.id!r}): the stored "
                f"review says nothing about it")
        result = PreflightResult.from_record(record)
        # The review covers a concrete operation, not just a kind of edit. Comparing capability and target
        # alone left a reviewed `tofu.apply` for `proxmox` able to authorise a *different* saved plan
        # against the same stack, because the file it will run is named in the change's arguments and the
        # plan never mentioned it. A step now declares the arguments it runs, and all three must match.
        wanted = f"{change.capability}:{change.target}"
        candidates = [step for step in plan.changes
                      if f"{step.capability}:{step.target}" == wanted]
        if plan.changes and not candidates:
            proposed = sorted({f"{step.capability}:{step.target}" for step in plan.changes})
            return self._decision_refused(change_id, plan_id,
                                          f"the plan proposes {', '.join(proposed)} and not {wanted}",
                                          review_id=result.review_id)
        if candidates and not any(dict(step.arguments) == dict(change.args) for step in candidates):
            seen = "; ".join(f"{wanted} {dict(step.arguments)}" for step in candidates)
            return self._decision_refused(change_id, plan_id,
                                          f"the plan proposes {seen}, and the change runs "
                                          f"{wanted} {dict(change.args)}",
                                          review_id=result.review_id)
        if plan.targets and change.target not in plan.targets:
            return self._decision_refused(change_id, plan_id,
                                          f"the plan names {', '.join(plan.targets)} and not "
                                          f"{change.target!r}", review_id=result.review_id)
        profile = self._profile_for(plan)
        if profile is None and self.auto.profiles:
            return self._decision_refused(change_id, plan_id,
                                          f"the plan is filed under profile {plan.profile!r}, which the "
                                          f"configuration does not define", review_id=result.review_id)
        # The profile is what says this class of work may touch this target with this operation at all.
        # `target_in_scope=bool(change.target)` said only that a string was present, so every scope the
        # operator had written - `allow_autonomous`, `allowed_targets`, `allowed_capabilities` - was
        # configured, validated, shown in the overview, and never consulted.
        if profile is not None and not self.autonomous_for(change, profile):
            return self._decision_refused(change_id, plan_id, self._scope_reason(change, profile),
                                          review_id=result.review_id)
        # Resolved, not copied. `_evaluate` only checks that the tuple is non-empty, so a review record
        # that was deleted, corrupted or replaced after the preflight still produced a citation nobody
        # could open - an approval whose stated justification cannot be audited.
        # What the engine is told the review said. The preflight record is a *copy* made at review time,
        # so the stored record - which may since have become a failure or a denial - is the current fact.
        review_status = result.review_status.value
        review_verdict = result.verdict.value if result.verdict else ""
        review_ids: tuple[str, ...] = ()
        if result.review_id:
            resolved = self._review_state(result.review_id, plan_id)
            if resolved is None:
                return self._decision_refused(change_id, plan_id,
                                              f"review {result.review_id} cannot be resolved for this plan, "
                                              f"so nothing here has been judged", review_id="")
            if resolved != "passing":
                # A *failed* review is a legitimate outcome the engine has branches for - it is what RETRY
                # exists to answer. Refusing it here meant the workflow never returned RETRY for a reviewer
                # failure and the repair budget was never spent.
                live = self.reviews.store.get(result.review_id)
                review_status = str(live.get("status") or review_status)
                review_verdict = str(live.get("verdict") or "")
            review_ids = (result.review_id,)
        unmet = self._profile_gaps(plan, change, review_ids=review_ids)
        if unmet:
            return self._decision_refused(change_id, plan_id,
                                          f"profile {plan.profile!r} requires {unmet}, and this plan does "
                                          f"not state them", review_id=result.review_id)
        access = self.core.require(change.capability, change.target)
        if verification is not None:
            report = VerificationReport.from_dict(verification)
            # The report's identity is checked, not overwritten. It belongs to the change, while the
            # decision is about the plan, and forcing the id to the change here made every document
            # disagree with the plan it was gathered for. Forcing it would also let a PASS for one change
            # be read as proof about another.
            # `verify_plan` reports against the plan id, because that is what a caller names; the
            # executor's change is `c-*`. Both are the same object, so a report naming this plan is
            # accepted - while a report naming a *different* plan or a different change is still refused.
            expected = {change_id, plan_id}
            if report.change_id and report.change_id not in expected:
                return self._decision_refused(change_id, plan_id,
                                              f"the verification report is for {report.change_id}, which is "
                                              f"neither this change ({change_id}) nor this plan ({plan_id})",
                                              review_id=result.review_id)
        else:
            report = None
        # Evidence is re-read and re-checked here rather than trusted from the preflight record. That record
        # was written when the bundle was fresh; the decision happens later, and by then the bundle may have
        # aged past `evidence.max_age_s`, gone missing, or been tampered with. Treating a non-empty id tuple
        # as `evidence_fresh` made all three reach APPROVE.
        # What was reviewed is what the plan declared. `review_plan(plan, evidence=B)` lets a caller
        # supply a different bundle, and the preflight then records B - so the approval would be bound to
        # evidence the immutable reviewed plan never named. Both the declared bundle and the declared
        # references have to be what the review actually saw.
        declared = set(plan.evidence_refs) | ({plan.evidence_bundle} if plan.evidence_bundle else set())
        reviewed = set(result.evidence_ids)
        if declared and not reviewed.issubset(declared):
            return self._decision_refused(change_id, plan_id,
                                          f"the review saw {', '.join(sorted(reviewed))} but the plan "
                                          f"declares {', '.join(sorted(declared))}; an approval cannot rest "
                                          f"on evidence the reviewed plan did not name",
                                          review_id=result.review_id)
        evidence_ids, evidence_reason, evidence_remaining = self._evidence_state(
            result.evidence_ids, change_id)
        inputs = Inputs(
            mode=self.auto.decision.mode,
            preflight_outcome=result.outcome,
            preflight_reason=result.reason,
            preflight_approvable=result.approvable,
            evidence_reason=evidence_reason,
            evidence_ids=evidence_ids,
            review_verdict=review_verdict,
            review_status=review_status,
            policy_allows=access is not Access.DENY,
            target_in_scope=profile is None or self.autonomous_for(change, profile),
            destructive=bool(change.dangerous),
            verification=report,
            attempts=self._repair_count(change),
            policy_version=self.auto.decision.policy_version,
            # Counted from this workflow's own baseline, not from the service's lifetime totals. The
            # ledger is cumulative, so an unrelated earlier review against a stricter ceiling reported a
            # *new* workflow as exhausted before it had spent anything, and elapsed time measured from
            # change creation charged it for waiting.
            calls_used=self.reviews.ledger.calls - int(change.details.get("baseline_calls", 0)),
            spend_usd=self.reviews.ledger.spend_usd - float(change.details.get("baseline_spend", 0.0)),
            elapsed_s=now() - float(change.details.get("workflow_started") or change.created),
        )
        # The change record is the authority for what an approval covers, so it is what both the record
        # and the binding name. The plan's own `arguments_hash` travels in the record for audit; the two
        # vocabularies are different, and pretending they are one would let them silently disagree.
        from ..changes import digest as _digest

        arguments = _digest({key: value for key, value in sorted(change.args.items())}) if change.args else ""
        decision = self.engine().decide(inputs, plan_id, arguments, change_id=change_id,
                                        review_ids=review_ids)
        self.audit.record(event="decision", change=change_id, decision=decision.decision.value,
                          reason=decision.reason.value, plan=plan_id, review=result.review_id)
        out: dict[str, Any] = {"decision": decision.brief()}
        if decision.decision is Decision.RETRY:
            # Counted only after the decision, under the same lock as every other transition, so a crash
            # between deciding and counting cannot buy a free cycle - and so the count is durable. The
            # *returned* change is used for the reply: the object loaded before the increment reports one
            # less than the record now holds, so every answer was a cycle behind the durable counter.
            counted = self.core.changes.note_repair_cycle(change_id)
            out["decision"] = {**decision.brief(), "attempts": self._repair_count(counted),
                               "repair_cycles_remaining": max(
                                   0, self.auto.decision.max_repair_cycles - self._repair_count(counted))}
        if not decision.approvable:
            return out
        binding = binding_for(change, evidence_ids=result.evidence_ids,
                              policy_version=self.auto.decision.policy_version,
                              arguments_hash=arguments,
                              profile=plan.profile or self.auto.decision.default_profile,
                              profile_version=(self._profile_for(plan).version
                                               if self._profile_for(plan) else "1"),
                              evidence_expires_in_s=evidence_remaining)
        approval = self.engine().issue(plan_id, arguments, binding, record=decision)
        self.core.changes.attach_approval(change_id, approval)
        return {**out, "approval": approval, "next": f"apply change {change_id}; no human step is required"}

    def _review_state(self, review_id: str, plan_id: str) -> str | None:
        """`"passing"`, `"failed"`, or `None` when the record cannot be resolved for this plan.

        A `PASS` that has since become a `DENY`, or that has picked up a BLOCKER, is not a passing review.
        A record whose subject does not match this plan is not this plan's review. And a runner failure is
        neither of those: it is a real fact, and the one the engine's retry branches exist for.
        """
        try:
            stored = self.reviews.store.get(review_id)
        except OpsError:
            return None
        if str(stored.get("subject_ref", "")) != plan_id:
            return None
        if stored.get("status") != "OK":
            return "failed"
        if stored.get("verdict") == "DENY":
            return None
        if stored.get("verdict") != "PASS":
            return "failed"
        findings = stored.get("findings") or ()
        if any(str((finding or {}).get("severity", "")).upper() == "BLOCKER" for finding in findings):
            return None
        return "passing"

    def _mark_workflow_start(self, change_id: str) -> None:
        """Stamp the first attempt: what the ledger had already spent, and when this loop began.

        Both are baselines, not totals. Without them a change that waited an hour before its first retry
        was charged that hour, and any earlier review of anything counted against this decision's ceiling.
        """
        change = self.core.changes.get(change_id)
        if change.details.get("workflow_started"):
            return
        self.core.changes.note_workflow_start(
            change_id, calls=self.reviews.ledger.calls, spend=self.reviews.ledger.spend_usd, at=now())

    def _profile_gaps(self, plan: Any, change: Any, *,
                      review_ids: Sequence[str] = ()) -> str:
        """What this plan does not state that its profile requires, as one readable clause.

        `allowed_*` and `allow_autonomous` were the only fields enforced, so a profile could demand
        evidence, preconditions, verification or a second review and still see an APPROVE with none.
        """
        profile = self._profile_for(plan)
        if profile is None:
            return ""
        missing: list[str] = []
        for kind, required in (("evidence", profile.require_evidence),
                               ("a precondition", profile.require_preconditions),
                               ("a verification check", profile.require_verification)):
            missing += [f"{kind} {item!r}" for item in required if not self._plan_states(plan, item)]
        # The effective floor, which is the class's - the configured number can only be higher, because
        # the config layer refuses a profile that asks for less than its own classification is worth.
        needed = max(profile.extra_reviews, profile.min_reviews)
        if needed and len(review_ids) < needed:
            missing.append(f"{needed} reviews ({profile.classification} class, {len(review_ids)} ran)")
        if profile.irreversible and not any(step.irreversible_reason for step in plan.changes):
            missing.append("an irreversible_reason on its steps")
        return ", ".join(missing)

    @staticmethod
    def _plan_states(plan: Any, item: str) -> bool:
        """Whether the plan says the thing a profile names, matched by word rather than by id.

        A profile writes `host:reachable` and a plan writes `web-1 is reachable`; demanding an exact id
        match would make every requirement unsatisfiable, and demanding nothing is what let them through.
        The plan's own *statements* are searched, not its serialised form - `to_dict` carries field names
        for values never filled in, so "inventory" would be satisfied by an empty `inventory_hash` key.
        """
        parts: list[str] = [plan.objective, plan.diagnosis, plan.rollback, *plan.preconditions,
                            *plan.post_checks, *plan.alternatives_rejected, *plan.unverified_claims,
                            *plan.unknowns]
        for step in plan.changes:
            parts += [step.how, step.undo, step.irreversible_reason, step.expectation, step.resource]
        haystack = json.dumps(parts, ensure_ascii=False).casefold()
        needle = item.casefold()
        if needle in haystack:
            return True
        head = needle.split(":", 1)[0].strip()
        return len(head) >= 3 and head in haystack

    def _profile_for(self, plan: Any) -> Any:
        """The policy profile the plan is filed under, or None when the operator defined none."""
        for profile in self.auto.profiles:
            if profile.name == plan.profile:
                return profile
        return None

    def autonomous_for(self, change: Any, profile: Any) -> bool:
        """Whether this profile covers this operation, on this target, for autonomous execution.

        An empty `allowed_*` list means the operator did not restrict it. That is the only reading under
        which an empty list is permission without becoming a default that grants authority nobody chose.
        """
        if not profile.allow_autonomous:
            return False
        if profile.allowed_capabilities and change.capability not in profile.allowed_capabilities:
            return False
        return not (profile.allowed_targets and change.target not in profile.allowed_targets)

    def _scope_reason(self, change: Any, profile: Any) -> str:
        """Which of the three limits refused it, so the operator knows which one to change."""
        if not profile.allow_autonomous:
            return f"profile {profile.name!r} does not allow autonomous execution"
        if profile.allowed_capabilities and change.capability not in profile.allowed_capabilities:
            return (f"profile {profile.name!r} does not cover {change.capability}; it covers "
                    f"{', '.join(sorted(profile.allowed_capabilities))}")
        return (f"profile {profile.name!r} does not cover the target {change.target!r}; it covers "
                f"{', '.join(sorted(profile.allowed_targets))}")

    def _evidence_state(self, evidence_ids: Sequence[str],
                        change_id: str = "") -> tuple[tuple[str, ...], str, float]:
        """Re-read and re-check every bundle a decision rests on, and answer with what is true now.

        A preflight record remembers which evidence travelled with the review; it does not remember
        whether that evidence is still usable. A bundle can pass its freshness window, go missing, or be
        replaced, and all three left the id tuple intact - so a decision taken later would still have
        reported `evidence_fresh` off a reference that no longer resolved to anything.

        The bundles are also checked against `change_id`. Without it `check_evidence` falls back to the
        bundle's own id as the expected identity, so a bundle consistently bound to some other change
        passes every check and the approval records it as evidence for this one.

        Returns the references, the reason, and how much longer the *earliest* bundle stays fresh - the
        last of which caps the approval, so it cannot outlive its own evidence.
        """
        ids = tuple(evidence_ids)
        if not ids:
            return (), "evidence_missing", 0.0
        # The references are returned even when they fail. Dropping them would send the engine down its
        # "no evidence at all" branch, whose message names no bundle - and the operator's next step is to
        # look at that bundle.
        failing: list[str] = []
        code = "evidence_fresh"
        remaining = float("inf")
        for bundle_id in ids:
            try:
                bundle = self.evidence.get(bundle_id)
            except OpsError:
                failing.append(bundle_id)
                code = code if code != "evidence_fresh" else "evidence_missing"
                continue
            payloads, blocked = self.evidence.load_artifacts(bundle)
            checks = check_evidence(bundle, payloads, blocked=blocked, change_id=change_id or None)
            # Derived from the same two values `check_evidence` measures freshness with: the oldest
            # timestamp in the bundle and the limit stored *in that bundle*. Using `bundle.created` and
            # the currently configured window instead gave a longer answer whenever an observation
            # predated ingestion, or whenever the window was tightened after collection - so the approval
            # could be issued with seconds of freshness left and stay usable well after the evidence was
            # stale, because execution only re-reads the binding's expiry and the evidence ids.
            with contextlib.suppress(TypeError, ValueError):
                oldest = min([float(bundle.created),
                              *(float(entry.observed_at or entry.captured) for entry in bundle.entries)])
                remaining = min(remaining, max(0.0, oldest + float(bundle.limits.max_age_s) - time.time()))
            found = reason_code(checks)
            if found != "evidence_fresh":
                failing.append(bundle_id)
                code = found if code == "evidence_fresh" else code
        if not failing:
            return ids, "evidence_fresh", remaining
        return ids, f"{code} (unusable: {', '.join(failing)})", remaining

    def _repair_count(self, change: Any) -> int:
        """How many repair cycles this change has already had, from the record rather than from memory.

        Left at its default, `attempts` was always 0, so every review timeout and every `NEEDS_EVIDENCE`
        satisfied `attempts < max_repair_cycles` and returned RETRY indefinitely. The bound was enforced
        only in tests that passed the field by hand.
        """
        return int(change.details.get("repair_cycles", 0) or 0)

    def _decision_refused(self, change_id: str, plan_id: str, detail: str, *,
                          review_id: str = "") -> dict[str, Any]:
        """A refusal recorded as a decision, so the audit trail has the same shape either way."""
        self.audit.record(event="decision", change=change_id, decision="BLOCKED_AUTONOMOUSLY",
                          reason="plan_changed", plan=plan_id, review=review_id)
        return {"decision": {"decision": "BLOCKED_AUTONOMOUSLY", "reason": Reason.PLAN_CHANGED.value,
                            "detail": detail}}

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
