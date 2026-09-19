"""Secret redaction applied to everything before it is written to an artifact or returned.

Best-effort defence in depth, not a guarantee: a secret with no recognisable shape passes through. The
primary guarantee is upstream (`/export hide-sensitive`, vault-encrypted files, no Secret reads, env files
that never leave the runner). Every pattern starts with a literal or uses bounded quantifiers.
"""

from __future__ import annotations

import re

MARK = "[REDACTED:{kind}]"

_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----.{0,20000}?"
                          r"-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----", re.DOTALL)
_VAULT = re.compile(r"\$ANSIBLE_VAULT;[0-9.]+;AES256[^\n]{0,80}\n(?:[ \t]*[0-9a-f]{20,}\n?){1,2000}")

_TOKENS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("gitlab_token", re.compile(r"\bgl(?:pat|rt|dt|cbt|ptt)-[A-Za-z0-9_-]{16,}")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("api_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    ("age_key", re.compile(r"\bAGE-SECRET-KEY-1[A-Z0-9]{50,}")),
    ("bearer", re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}")),
)
_URL_AUTH = re.compile(r"\b([a-z][a-z0-9+.-]{1,20}://[^\s:/@]{1,64}):([^\s@/]{1,256})@")
_SENSITIVE_KEY = (r"pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
                  r"preshared[_-]?key|credentials?|auth[_-]?key|client[_-]?secret|dsn")
_KEY_VALUE = re.compile(
    rf"(?i)((?:[A-Za-z0-9_.-]{{0,40}})(?:{_SENSITIVE_KEY})[A-Za-z0-9_.-]{{0,20}}[\"']?\s{{0,3}}[=:][ \t]{{0,40}})"
    r"(\"[^\"\n]{1,512}\"|'[^'\n]{1,512}'|[^\s,;\"']{1,512})")
# WireGuard keys are 32 bytes base64: 43 characters + "="
_WG_KEY = re.compile(r"(?i)\b(privatekey|presharedkey)\s{0,3}=\s{0,3}[A-Za-z0-9+/]{43}=")
_SAFE_VALUES = frozenset({"", "null", "none", "true", "false", "yes", "no", "(sensitive value)", "(sensitive)",
                          "<redacted>", "***", "\"\"", "''"})


def redact(text: str) -> tuple[str, int]:
    """Returns the redacted text and the number of redactions."""
    count = 0

    def sub(pattern: re.Pattern[str], replacement: str, source: str) -> str:
        nonlocal count
        result, found = pattern.subn(replacement, source)
        count += found
        return result

    text = sub(_PRIVATE_KEY, MARK.format(kind="private_key"), text)
    text = sub(_VAULT, MARK.format(kind="ansible_vault") + "\n", text)
    text = sub(_WG_KEY, r"\1 = " + MARK.format(kind="wireguard_key"), text)
    text = sub(_URL_AUTH, r"\1:" + MARK.format(kind="url_password") + "@", text)
    for kind, pattern in _TOKENS:
        text = sub(pattern, MARK.format(kind=kind), text)

    def key_value(match: re.Match[str]) -> str:
        nonlocal count
        value = match.group(2)
        if value.strip().lower() in _SAFE_VALUES or value.startswith("[REDACTED:"):
            return match.group(0)
        count += 1
        return match.group(1) + MARK.format(kind="value")

    return _KEY_VALUE.sub(key_value, text), count


def redact_text(text: str) -> str:
    return redact(text)[0]
