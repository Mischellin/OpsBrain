"""Shared value types: the strict pydantic base and the access levels.

Kept apart from `config.py` so the `auto` package can build its own configuration models from the same
base without importing the top-level config, which imports `auto` in turn.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class Access(StrEnum):
    ALLOW = "allow"
    CONFIRM = "confirm"
    DENY = "deny"


class _Model(BaseModel):
    """Every configuration model: no unknown keys, and frozen so nothing can rewrite the policy at runtime."""

    model_config = ConfigDict(extra="forbid", frozen=True)
