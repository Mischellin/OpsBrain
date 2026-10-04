"""The autonomous change pipeline: review, evidence, preflight, decision, rollout.

Nothing here replaces the two-step gate of `changes.py`. Manual approval keeps working; the autonomous
path is a second, policy-checked way to obtain an approval, and it is off unless `auto.enabled` is set.
"""

from __future__ import annotations

from .evidence import (  # noqa: F401
    Check,
    EvidenceBundle,
    EvidenceCollector,
    EvidenceEntry,
    EvidenceError,
    EvidenceStore,
    Observation,
    Provenance,
    Reason,
    check_evidence,
    metadata_only,
    passed,
    reason_code,
    render_for_reviewer,
)
from .review import (  # noqa: F401
    CONTRACT_VERSION,
    Finding,
    Reviewer,
    ReviewRequest,
    ReviewResult,
    RunnerStatus,
    Subject,
    Verdict,
)
from .service import AutoService  # noqa: F401

__all__ = [
    "CONTRACT_VERSION",
    "AutoService",
    "Check",
    "EvidenceBundle",
    "EvidenceCollector",
    "EvidenceEntry",
    "EvidenceError",
    "EvidenceStore",
    "Finding",
    "Observation",
    "Provenance",
    "Reason",
    "ReviewRequest",
    "ReviewResult",
    "Reviewer",
    "RunnerStatus",
    "Subject",
    "Verdict",
    "check_evidence",
    "metadata_only",
    "passed",
    "reason_code",
    "render_for_reviewer",
]
