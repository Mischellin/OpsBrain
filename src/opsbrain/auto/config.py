"""Configuration of the autonomous pipeline.

One `auto:` block in the operator's YAML. Everything defaults to *off*: no review, no autonomy, no spend
without a deliberate line in the config file. Models are `extra=forbid` like the rest of OpsBrain, so a
misspelt key fails loudly instead of silently leaving a gate open.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import Field, field_validator, model_validator

from ..models import Access, _Model

PROFILE_NAMES = ("general", "network", "firewall", "vpn", "reboot", "auth", "secrets", "storage",
                 "k8s-control-plane", "dns")

#: Reason codes the decision engine may emit. Stable strings: tests and audits match on them.
REASON_CODES = (
    "review_passed", "review_blocked", "review_failed", "review_missing", "evidence_fresh", "evidence_stale",
    "evidence_missing", "evidence_tampered", "policy_allows", "policy_forbids", "policy_unclassified",
    "target_not_in_scope", "destructive_requires_human", "verdict_disagreement", "budget_exhausted",
    "retries_exhausted", "unknown_target", "approval_stale", "lease_taken", "precondition_failed",
    "verification_failed", "verification_unknown", "autonomy_revoked", "emergency_stop",
)


class ReviewConfig(_Model):
    """How a review is obtained. A missing command means reviews are unavailable, not silently skipped."""

    runner: str = "fake"  # fake | codex
    command: list[str] = Field(default_factory=list)
    model: str = ""
    auth: str = "subscription"  # subscription | api
    timeout_s: float = Field(default=300.0, gt=0, le=3600)
    context_chars: int = Field(default=60_000, ge=1_000, le=200_000)
    output_chars: int = Field(default=8_000, ge=500, le=64_000)
    max_parallel: int = Field(default=2, ge=1, le=16)
    max_retries: int = Field(default=2, ge=0, le=5)
    max_model_calls: int = Field(default=40, ge=1, le=10_000)
    budget_usd: float = Field(default=0.0, ge=0, le=10_000)
    snapshot_dir: str = ""
    scratch_home: str = ""  # HOME handed to the reviewer: empty, never the operator's
    sandbox: list[str] = Field(default_factory=list)  # enforced wrapper: sandbox-exec / bwrap / firejail
    live: bool = False
    require_allow: bool = True  # `allow` policy rows may not be resolved by the model alone

    @field_validator("command", "sandbox")
    @classmethod
    def _argv(cls, value: list[str]) -> list[str]:
        if any(not part or "\x00" in part for part in value):
            raise ValueError(f"invalid argv: {value!r}")
        return value

    @field_validator("auth")
    @classmethod
    def _auth(cls, value: str) -> str:
        if value not in ("subscription", "api"):
            raise ValueError("auth must be `subscription` or `api`")
        return value

    @model_validator(mode="after")
    def _live_needs_command(self) -> ReviewConfig:
        if self.live and not self.command:
            raise ValueError("auto.review.live=true needs auto.review.command")
        if self.runner == "codex" and not self.command and self.live:
            raise ValueError("runner `codex` needs an explicit command")
        if self.live and not self.sandbox:
            # Without an enforced wrapper the reviewer inherits the operator's write access and HOME, which
            # contradicts the guarantee this module is built on. Refusing here beats a promise in a docstring.
            raise ValueError("auto.review.live=true needs auto.review.sandbox (sandbox-exec / bwrap / "
                             "firejail): a working directory does not confine a process")
        if self.sandbox and not self.live:
            raise ValueError("auto.review.sandbox only matters with auto.review.live=true")
        return self


class EvidenceConfig(_Model):
    """Freshness and completeness requirements for the evidence a change is judged on."""

    max_age_s: float = Field(default=900, gt=0, le=86_400)
    require_target_identity: bool = True
    require_inventory_hash: bool = True
    max_bundle_bytes: int = Field(default=1_000_000, ge=1024, le=100_000_000)


class DecisionConfig(_Model):
    """Bounds on the autonomous path. Zero tolerance on the ones that matter."""

    mode: str = "manual"  # manual | autonomous
    max_repair_cycles: int = Field(default=3, ge=0, le=20)
    max_model_calls: int = Field(default=40, ge=1, le=10_000)
    max_wall_s: float = Field(default=1800, ge=60, le=86_400)
    max_spend_usd: float = Field(default=0.0, ge=0, le=10_000)
    allow_destructive: bool = False  # autonomous execution of a destroying change stays off by default
    emergency_stop: bool = False  # one switch that blocks every autonomous decision
    policy_version: str = "v1"
    default_profile: str = "general"

    @field_validator("mode")
    @classmethod
    def _mode(cls, value: str) -> str:
        if value not in ("manual", "autonomous"):
            raise ValueError("mode must be `manual` or `autonomous`")
        return value

    @field_validator("default_profile")
    @classmethod
    def _profile(cls, value: str) -> str:
        if value not in PROFILE_NAMES:
            raise ValueError(f"default_profile must be one of {list(PROFILE_NAMES)}")
        return value

    @property
    def autonomous(self) -> bool:
        return self.mode == "autonomous" and not self.emergency_stop


class PolicyProfileConfig(_Model):
    """Per-profile requirements. `classification` is derived from config, never from a worker's claim."""

    name: str
    classification: str = "low"
    require_evidence: list[str] = Field(default_factory=list)
    require_preconditions: list[str] = Field(default_factory=list)
    require_verification: list[str] = Field(default_factory=list)
    allowed_targets: list[str] = Field(default_factory=list)
    allowed_capabilities: list[str] = Field(default_factory=list)
    recovery_actions: list[str] = Field(default_factory=list)
    extra_reviews: int = Field(default=0, ge=0, le=5)  # independent review sessions for risky classes
    irreversible: bool = False
    allow_autonomous: bool = True

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if value not in PROFILE_NAMES:
            raise ValueError(f"profile name must be one of {list(PROFILE_NAMES)}")
        return value

    @field_validator("classification")
    @classmethod
    def _class(cls, value: str) -> str:
        if value not in ("low", "medium", "high", "critical"):
            raise ValueError("classification must be low | medium | high | critical")
        return value


class VerifyConfig(_Model):
    """Bounds and defaults for the deterministic post-change checks.

    A check that cannot be evaluated returns UNKNOWN, never PASS. The defaults below encode that: an
    observation window is required before a check may claim the system is quiet.
    """

    observation_s: int = Field(default=30, ge=0, le=3600)
    require_observation: bool = True
    max_checks: int = Field(default=20, ge=1, le=200)
    unknown_is_not_pass: bool = True  # may not be turned off: an unknown target is not a success
    allow_state_changing_checks: bool = False  # a check that starts something must be in the plan
    profiles: list[str] = Field(default_factory=lambda: ["systemd", "http", "k8s", "storage", "drift"])


class AutoConfig(_Model):
    """The whole autonomous subsystem. Absent or disabled means every other setting is inert."""

    enabled: bool = False
    review: ReviewConfig = Field(default_factory=ReviewConfig)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)
    decision: DecisionConfig = Field(default_factory=DecisionConfig)
    verify: VerifyConfig = Field(default_factory=VerifyConfig)
    profiles: list[PolicyProfileConfig] = Field(default_factory=list)
    subject_reclassify: bool = True
    autonomy_token: str = ""  # presence required for autonomous mode; never read from the model

    @model_validator(mode="after")
    def _check(self) -> AutoConfig:
        names = [profile.name for profile in self.profiles]
        if len(names) != len(set(names)):
            raise ValueError(f"duplicate policy profile: {sorted(names)}")
        default = self.decision.default_profile
        if self.profiles and default not in names:
            raise ValueError(f"decision.default_profile {default!r} has no matching profile")
        if self.enabled and self.decision.autonomous and not self.autonomy_token:
            raise ValueError("autonomous mode needs auto.autonomy_token: autonomy is never implicit")
        return self

    def profile(self, name: str) -> PolicyProfileConfig | None:
        return next((profile for profile in self.profiles if profile.name == name), None)

    def as_digest_source(self) -> dict[str, Any]:
        """The parts of the policy an approval is bound to. Changing any of them makes approvals stale."""
        return {
            "enabled": self.enabled,
            "mode": self.decision.mode,
            "policy_version": self.decision.policy_version,
            "default_profile": self.decision.default_profile,
            "allow_destructive": self.decision.allow_destructive,
            "emergency_stop": self.decision.emergency_stop,
            "profiles": [profile.model_dump(mode="json") for profile in sorted(self.profiles, key=lambda p: p.name)],
            "review": {"model": self.review.model, "auth": self.review.auth, "runner": self.review.runner,
                       "timeout_s": self.review.timeout_s, "rubric_budget": self.review.max_model_calls},
            "evidence": {"max_age_s": self.evidence.max_age_s,
                         "require_inventory_hash": self.evidence.require_inventory_hash},
        }


_TOKEN = re.compile(r"^[A-Za-z0-9_-]{16,}$")


def valid_autonomy_token(token: str) -> bool:
    return bool(_TOKEN.fullmatch(token))


def access_from_profile(name: str, rows: dict[str, Access]) -> Access:
    """The `allow` / `confirm` / `deny` rows that also govern a profile's autonomous execution."""
    if name in rows:
        return rows[name]
    if f"profile:{name}" in rows:
        return rows[f"profile:{name}"]
    return Access.CONFIRM
