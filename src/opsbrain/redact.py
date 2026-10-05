"""Secret redaction applied to everything before it is written to an artifact or returned.

Best-effort defence in depth, not a guarantee: a secret with no recognisable shape passes through. The
primary guarantee is upstream (`/export hide-sensitive`, vault-encrypted files, no Secret reads, env files
that never leave the runner). Every pattern starts with a literal or uses bounded quantifiers.
"""

from __future__ import annotations

import re
from typing import Any

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
                  r"pre[_-]?shared[_-]?key|credentials?|auth[_-]?key|client[_-]?secret|dsn")
_KEY_VALUE = re.compile(
    rf"(?i)((?:[A-Za-z0-9_.-]{{0,40}})(?:{_SENSITIVE_KEY})[A-Za-z0-9_.-]{{0,20}}[\"']?\s{{0,3}}[=:][ \t]{{0,40}})"
    r"(\"[^\"\n]{1,512}\"|'[^'\n]{1,512}'|[^\s,;\"']{1,512})")
# WireGuard keys are 32 bytes base64: 43 characters + "="
_WG_KEY = re.compile(r"(?i)\b(privatekey|presharedkey)\s{0,3}=\s{0,3}[A-Za-z0-9+/]{43}=")
#: A value that is already a redaction marker, with or without the quotes the serialiser put round it.
#: The kinds `MARK` actually emits include underscores - `private_key`, `github_token`,
#: `ansible_vault` - so a character class of letters recognises almost none of our own output.
_ALREADY_REDACTED = re.compile(r'^(?:"\[REDACTED:[a-z_]+\]"|\[REDACTED:[a-z_]+\])$', re.IGNORECASE)
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
        if value.strip().lower() in _SAFE_VALUES or _ALREADY_REDACTED.match(value.strip()):
            # A marker that is already a marker, quoted or not, is left exactly as it is. Re-running the
            # redactor over stored text - an artifact read, a grep - used to rewrite
            # `"password":"[REDACTED:value]"` into a bare unquoted token, so the same corruption kept
            # happening downstream of the store even after the save path learned to skip it.
            return match.group(0)
        count += 1
        return match.group(1) + MARK.format(kind="value")

    return _KEY_VALUE.sub(key_value, text), count


def redact_text(text: str) -> str:
    return redact(text)[0]


#: A key name that *is itself* a password, however it is spelled. `pass` on its own is ambiguous - it is a
#: real password field in hand-written YAML, and it is also the tail of `is_pass`, `passed` and
#: `bypass`. Those are not credentials, and masking a boolean because its name contains a substring is
#: worse than useless: it turns `verify_evidence` into a string the client cannot read.
_PASSWORD_NAMES = (
    "pass", "passwd", "password", "passphrase", "passcode", "pass[-_]?code", "passkey", "pwd", "pass_word",
    "passwd_?hash", "pass[-_]?word",
    "x[-_]?pass", "(?:user|admin|root|db|ftp|ssh|smtp|mail|api|app|service)_pass(?:word|wd)?",
)
_PASSWORD_NAME = re.compile(r"(?i)^(?:" + "|".join(_PASSWORD_NAMES) + r")$")

#: The rest of the sensitive vocabulary matches on component boundaries: `auth_token`, `db.api_key` and
#: `client_secret` are credentials; `tokenizer`, `keynote` and `authorized` are not.
_SENSITIVE_NAME = re.compile(r"(?i)(?:^|[^a-z0-9])(?:" + _SENSITIVE_KEY + r")(?:[^a-z0-9]|$)")

#: ...and on a suffix, because a name can also arrive already squashed: an upstream payload that emits
#: `accesstoken` or `refreshtoken` carries the credential just as surely, and no separator will ever
#: appear in it to be found. Restricted to words that cannot be the tail of an ordinary term -
#: `tokenizer`, `keynote`, `secretary` and `authorized` do not end in any of these, which is the point.
_SENSITIVE_SUFFIX = re.compile(r"(?:token|secret|passphrase|password|passwd|passcode|pwd|credential)s?$|"
                               r"(?:apikey|privatekey|presharedkey|accesskey|secretkey|authkey|signingkey|"
                               r"encryptionkey|masterkey|passkey|passwordhash|passwdhash|pwdhash|dsn)s?$")

#: Keys that *look* sensitive and are not - but only while the value is the kind of value they promise.
#: `token` in a budget report is a count, not a credential, and masking it replaces a number with a string:
#: that silently breaks every client that reports usage, and hides exactly the field an operator is
#: watching. The exemption is therefore a property of the *value*, never of the name alone: `tokens` is
#: also what a credential collection is called, and `{"tokens": ["opaque-auth-token"]}` has to stay masked.
#: Listed explicitly rather than by narrowing the pattern, so a genuinely new secret-shaped key is
#: redacted by default.
_NUMERIC_KEYS = frozenset({
    "input_tokens", "output_tokens", "max_tokens", "total_tokens", "tokens", "token_budget",
    "tokens_used", "tokens_remaining", "max_model_calls", "model_calls", "spend_usd", "budget_usd",
})
#: Verification and review vocabulary. `passed` / `is_pass` are answers, not secrets, and redacting them
#: leaves a client unable to tell whether a check succeeded. A key that is *only* `pass` is not here - that
#: one is a password field, and `_PASSWORD_NAME` matches it whole. These carry a flag or a count.
_FLAG_KEYS = frozenset({"passed", "is_pass", "passes", "passing", "bypass", "bypassed", "password_changed"})


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _exempt(name: str, value: Any) -> bool:
    """Whether a key that looks sensitive is vouched for by the *type* of what it holds."""
    if name in _NUMERIC_KEYS:
        return _is_number(value)
    if name in _FLAG_KEYS:
        return isinstance(value, bool) or _is_number(value)
    return False


_NO_VALUE: Any = object()


#: `accessToken` -> `access_Token`. A run of capitals ends the word before it starts, except in the
#: `HTTPServer` shape, where the last capital belongs to the word that follows.
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _normalise_key(key: str) -> str:
    """Fold a key to `lower_snake` so camelCase and snake_case are judged by the same rule.

    Case-folding first and only then looking for separators destroyed the camel-case half: `accessToken`
    became `accesstoken` and matched nothing, so an opaque credential under that key came back untouched.
    Splitting on the case boundary first, then folding, keeps `accessToken` and `access_token` the same
    word while leaving `is_pass` and `isPass` the same non-word.
    """
    return _CAMEL.sub("_", str(key).strip()).replace("-", "_").replace(".", "_").casefold()


def _is_sensitive_key(key: str, value: Any = _NO_VALUE) -> bool:
    """Whether a key names a credential. A name is judged whole, not by whether it contains a fragment.

    With a `value`, a key from the telemetry vocabulary is cleared only when the value is a number (or, for
    the verification vocabulary, a flag). Asked about the name alone, those names are judged as the name
    they are and are not cleared.

    Substring matching is what made `is_pass` look like a password: the pattern's `pass` alternative
    matched the tail of an unrelated word. The password family is matched whole, and the rest only on
    component boundaries, so a new key has to be genuinely credential-shaped to be masked.
    """
    name = _normalise_key(key)
    if value is not _NO_VALUE and _exempt(name, value):
        return False
    if _PASSWORD_NAME.match(name):
        return True
    return bool(_SENSITIVE_NAME.search(name) or _SENSITIVE_SUFFIX.search(name))


def redact_obj(value: Any) -> Any:
    """Structure-aware variant for data that must stay valid JSON (the audit log): strings are redacted in
    place, values under a sensitive key are masked whole."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {key: (MARK.format(kind="value") if _is_sensitive_key(key, item) and item not in (None, "")
                      else redact_obj(item)) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [redact_obj(item) for item in value]
    return value
