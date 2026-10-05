"""Policy: capability[:target] -> allow | confirm | deny.

Keyed on the capability name and the configured target only; never on command text or argument
content. A `deny` on any matching rule wins. Read capabilities default to `allow`, mutating ones to
`confirm`; an unknown capability is treated as mutating.
"""

from __future__ import annotations

from collections.abc import Mapping

from .config import Access

READ_CAPABILITIES = frozenset({
    "docs.read", "hosts.read", "tofu.plan", "tofu.state", "ansible.check", "k8s.read", "network.read",
    "observe.read", "drift.check"})
MUTATING_CAPABILITIES = frozenset({
    "hosts.restart", "tofu.apply", "tofu.unlock", "ansible.apply", "k8s.refresh", "k8s.sync", "k8s.restart"})


def _candidates(capability: str, target: str) -> list[str]:
    parts = capability.split(".")
    names = [capability] + [".".join(parts[:index]) + ".*" for index in range(len(parts) - 1, 0, -1)] + ["*"]
    out: list[str] = []
    for name in names:  # most specific first
        if target:
            out.append(f"{name}:{target}")
        out.append(name)
    return out


def decide(rules: Mapping[str, Access], capability: str, target: str = "") -> Access:
    matched = [rules[key] for key in _candidates(capability, target) if key in rules]
    if Access.DENY in matched:
        return Access.DENY
    if matched:
        return matched[0]
    return Access.ALLOW if capability in READ_CAPABILITIES else Access.CONFIRM
