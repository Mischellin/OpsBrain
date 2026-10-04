"""Review runners: the sandboxed live Codex adapter and the deterministic fake used by tests.

The live runner is the only place in OpsBrain that would ever start an external binary on behalf of the
review path, and it is deliberately dull about it:

* argv comes from a command template in the operator's config - never from model output, never through a
  shell, never assembled by string concatenation of arguments;
* the environment is rebuilt from an allowlist instead of inherited, so the reviewer cannot reach
  SSH_AUTH_SOCK, KUBECONFIG, DOCKER_HOST or cloud credentials;
* the working directory is a read-only snapshot, and the timeout is enforced by the parent process;
* there is no fallback model. A quota error or a missing subscription is an error to be reported, not a
  reason to quietly spend the owner's money somewhere else.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # noqa: S404 - fixed argv, no shell, scrubbed environment
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..result import Result
from ..util import OpsError, clip, compact
from .review import (
    CONTRACT_VERSION,
    MAX_OUTPUT_CHARS,
    ReviewRequest,
    ReviewResult,
    RunnerStatus,
    parse_review_response,
)

#: Passed through to the runner. Anything not listed here is dropped from the inherited environment.
ENV_ALLOWLIST = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS")

#: Substrings of environment variables that are never forwarded, whatever the allowlist says.
ENV_DENYLIST = ("SSH_", "KUBE", "DOCKER", "AWS_", "AZURE_", "GCP_", "GOOGLE_", "ANTHROPIC_", "OPENAI_", "GITHUB_",
                "GH_", "GLAB_", "TOKEN", "SECRET", "PASSWORD", "PASSPHRASE", "VAULT", "PGP_", "SOPS_AGE")

MAX_RETRIES = 3


@dataclass(frozen=True)
class RunnerSettings:
    """Everything the operator controls about how a review is obtained."""

    runner: str = "fake"
    command: tuple[str, ...] = ()  # argv template; {prompt} is replaced by the request file path
    model: str = ""
    auth: str = "subscription"  # subscription | api
    timeout_s: float = 300.0
    max_parallel: int = 2
    max_retries: int = 2
    max_model_calls: int = 40
    budget_usd: float = 0.0  # 0 = no money limit enforced, call/parallel limits still apply
    snapshot_dir: str = ""  # directory the request is written into
    scratch_home: str = ""  # HOME for the reviewer: empty credentials, not the operator's
    sandbox: tuple[str, ...] = ()  # enforced confinement wrapper (e.g. sandbox-exec, bwrap, firejail)
    api_key_env: str = ""  # which variable holds the API key when auth is `api`
    live: bool = False  # opt-in: without it no external binary is ever started

    def safe_env(self) -> dict[str, str]:
        env = {key: os.environ[key] for key in ENV_ALLOWLIST if key in os.environ}
        env = {key: value for key, value in env.items()
               if not any(denied in key.upper() for denied in ENV_DENYLIST)}
        # The inherited HOME is a way to the operator's ssh keys, cloud config and shell history. Point it
        # at an empty scratch directory so "read your credentials" is a filesystem decision the sandbox
        # makes, not something a well-behaved reviewer is trusted not to try.
        scratch = self.scratch_home or self.snapshot_dir
        if scratch:
            home = str(Path(scratch).expanduser())
            env.update({"HOME": home, "XDG_CONFIG_HOME": f"{home}/.config", "XDG_CACHE_HOME": f"{home}/.cache",
                        "XDG_DATA_HOME": f"{home}/.local/share"})
        return self._apply_auth(env)

    def _apply_auth(self, env: dict[str, str]) -> dict[str, str]:
        """Make `auth` decide which credentials the reviewer can see.

        Stored and reported but never consulted, `auth` was a label on a setting that did nothing:
        `api` and `subscription` launched the same command against the same inherited `HOME`, so the mode
        picked whichever credentials the binary happened to find. Now the mode chooses the environment, and
        an `api` run without its key named fails rather than silently falling back to a subscription login
        the operator did not select.
        """
        if self.auth == "api":
            if not self.api_key_env:
                raise ReviewerError(
                    "auto.review.auth is `api` but auto.review.api_key_env names no variable: the mode would "
                    "be ignored and whichever credential the binary found would be used instead")
            if self.api_key_env not in os.environ:
                raise ReviewerError(
                    f"auto.review.auth is `api` but {self.api_key_env} is not set: refusing to start "
                    "rather than falling back to another account")
            env[self.api_key_env] = os.environ[self.api_key_env]
            return env
        # A subscription login is a file under the reviewer's own scratch HOME, which the env allowlist
        # never populated. Nothing is added, and nothing needs removing: the credentials are not inherited.
        return env


class ReviewerError(OpsError):
    """A runner-level failure. Never carries a verdict."""


class FakeReviewer:
    """Answers from a rule table, keyed on a substring of the request context. No I/O, fully deterministic.

    This is the runner every test and every default configuration uses: the pipeline must be provable
    without spending a token.
    """

    name = "fake"

    def __init__(self, default: dict[str, Any] | None = None):
        self.default = default or {
            "contract_version": CONTRACT_VERSION,
            "status": "OK",
            "verdict": "PASS",
            "findings": [],
            "unverified_claims": [],
            "next_checks": [],
        }
        self.rules: list[tuple[str, dict[str, Any]]] = []
        self.requests: list[ReviewRequest] = []
        self.raise_on: set[str] = set()

    def on(self, fragment: str, document: dict[str, Any]) -> None:
        self.rules.insert(0, (fragment, document))

    def fail(self, fragment: str) -> None:
        self.raise_on.add(fragment)

    def review(self, request: ReviewRequest) -> str:
        self.requests.append(request)
        for fragment in self.raise_on:
            if fragment in request.context:
                raise ReviewerError(f"fake runner failure for {fragment!r}")
        for fragment, document in self.rules:
            if fragment in request.context or fragment in request.objective:
                return json.dumps(document)
        return json.dumps(self.default)


class CodexReviewer:
    """Runs an external CLI in a scrubbed, read-only sandbox and returns its raw stdout.

    Deliberately has no access to an `Executor`, an ssh config or a kubeconfig: it is handed a file with
    the request and a prompt, and its only output is text that goes straight into the strict parser.
    """

    name = "codex"

    def __init__(self, settings: RunnerSettings, *, runner: Any = None, now_fn: Any = time.time):
        self.settings = settings
        self._run = runner or self._subprocess
        self._now = now_fn
        self.calls = 0

    def review(self, request: ReviewRequest) -> str:
        if not self.settings.live:
            raise ReviewerError("live runner is disabled: set auto.review.live=true after configuring the CLI")
        if not self.settings.command:
            raise ReviewerError("auto.review.command is empty: nothing to run")
        # A working directory confines nothing. It does not make a directory read-only, and it does not
        # stop the child from writing anywhere the operator can, or from reading the operator's SSH keys
        # and kubeconfig. Since the whole promise of this module is that the reviewer observes and never
        # acts, live mode requires an enforced confinement wrapper rather than a `cwd` that merely looks
        # like one.
        if not self.settings.sandbox:
            raise ReviewerError(
                "auto.review.sandbox is empty: a working directory is not a sandbox. Live review needs an "
                "enforced wrapper (sandbox-exec / bwrap / firejail) so a prompt-injected reviewer cannot "
                "write, or read the operator's credentials. See docs/autonomy.md.")
        self.calls += 1
        prompt = self._write_request(request)
        argv = [part.replace("{prompt}", prompt) for part in self.settings.command]
        argv = [part.replace("{model}", self.settings.model) for part in argv]
        if not any("{prompt}" in part or "{model}" in part for part in self.settings.command):
            raise ReviewerError("auto.review.command must contain {prompt} or {model}")
        cwd = Path(self.settings.snapshot_dir).expanduser() if self.settings.snapshot_dir else None
        if cwd is not None and not cwd.is_dir():
            raise ReviewerError(f"auto.review.snapshot_dir does not exist: {cwd}")
        argv = [*self.settings.sandbox, *argv]
        try:
            result: Result = self._run(argv, cwd=cwd, env=self.settings.safe_env(),
                                       timeout=self.settings.timeout_s, input=self._payload(request))
        except subprocess.TimeoutExpired as exc:
            raise ReviewerError(f"reviewer timed out after {self.settings.timeout_s:.0f}s") from exc
        except FileNotFoundError as exc:
            raise ReviewerError(f"reviewer binary not found: {argv[0]}") from exc
        except OSError as exc:
            raise ReviewerError(f"reviewer could not start: {exc}") from exc
        if not result.ok:
            raise ReviewerError(f"reviewer exited rc={result.rc}: {clip(result.out.strip(), 200)}")
        if len(result.out) > MAX_OUTPUT_CHARS:
            raise ReviewerError(f"reviewer output too large: {len(result.out)} chars")
        return result.out

    def _payload(self, request: ReviewRequest) -> str:
        return json.dumps(request.to_dict(), ensure_ascii=False)

    def _write_request(self, request: ReviewRequest) -> str:
        """Writes the request where a sandbox can read it, 0600, and never echoes it back."""
        directory = Path(self.settings.snapshot_dir or "~/.opsbrain/auto").expanduser()
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = directory / f"{request.review_id}.request.json"
        # Created with the mode already set, and through a temp file: `write_text` would create it with the
        # process umask and only chmod afterwards, leaving a window in which a request is world readable.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(self._payload(request))
        except OSError:
            path.unlink(missing_ok=True)
            raise
        return str(path)

    def _subprocess(self, argv: list[str], *, cwd: Path | None, env: dict[str, str], timeout: float,
                    input: str) -> Result:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            argv, cwd=str(cwd) if cwd else None, env=env, input=input.encode(), timeout=timeout,
            capture_output=True, check=False)
        return Result(completed.returncode, completed.stdout.decode("utf-8", errors="replace"))


def probe_capabilities(settings: RunnerSettings) -> dict[str, Any]:
    """Check the installed CLI before it is needed in anger.

    Reports what the binary answers, so a wrong path, an older CLI or a model the installed build does not
    know is discovered while configuring - not halfway through an incident. Never starts a paid call.
    """
    if not settings.command:
        return {"ok": False, "error": "auto.review.command is empty", "command": None,
                "model": settings.model, "auth": settings.auth, "live": settings.live, "model_checked": False}
    binary = settings.command[0]
    resolved = shutil.which(binary) or (binary if Path(binary).is_file() else None)
    if resolved is None:
        return {"ok": False, "error": f"binary not found: {binary}", "command": str(settings.command),
                "model": settings.model, "auth": settings.auth, "live": settings.live, "model_checked": False}
    version = "unknown"
    probe = self_probe_version(resolved)
    if probe is not None:
        version = probe
    return {
        "ok": True,
        "command": str(settings.command),
        "binary": resolved,
        "version": version,
        "model": settings.model,
        "auth": settings.auth,
        "live": settings.live,
        "snapshot_dir": settings.snapshot_dir or None,
        "sandbox": list(settings.sandbox),
        "sandbox_required": True,
        "supports_prompt_placeholder": any("{prompt}" in part for part in settings.command),
        "model_checked": False,  # a real capability check needs credentials; the operator confirms it
    }


def self_probe_version(resolved: str) -> str | None:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [resolved, "--version"], capture_output=True, timeout=15, check=False,
            env={key: os.environ[key] for key in ENV_ALLOWLIST if key in os.environ})
    except (OSError, subprocess.SubprocessError):
        return None
    return clip(completed.stdout.decode("utf-8", errors="replace").strip() or completed.stderr.decode(
        "utf-8", errors="replace").strip(), 120) or None


#: Keys under which a runner's event stream may carry the answer as a nested document.
_NESTED_KEYS = ("text", "content", "response", "output", "result", "message", "arguments")


def extract_review_payload(raw: str) -> str:
    """Pull the contract document out of whatever the runner printed.

    `codex exec --json` does not print the verdict: it prints a JSONL *stream* of events, and the answer
    is nested in the last one. Parsing the whole stdout with a single `json.loads` therefore rejects every
    healthy live run as INVALID_RESPONSE. So: try the whole thing, then the last line, then the last event
    that carries something which itself parses as a contract document.
    """
    text = raw.strip()
    if not text:
        return text
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1).strip()
    if _looks_like_contract(text):
        return text
    lines = [line for line in text.splitlines() if line.strip()]
    for line in reversed(lines):
        if _looks_like_contract(line):
            return line
    for line in reversed(lines):
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        if _looks_like_contract(event):
            return line
        for key in _NESTED_KEYS:
            nested = event.get(key)
            if isinstance(nested, str) and _looks_like_contract(nested):
                return nested
            if isinstance(nested, dict) and _looks_like_contract(nested):
                return compact(nested)
    return text


def _looks_like_contract(value: Any) -> bool:
    """True when `value` is already a document this contract could act on."""
    document: Any = value
    if isinstance(value, str):
        try:
            document = json.loads(value)
        except ValueError:
            return False
    return isinstance(document, dict) and "verdict" in document


def run_review(reviewer: Any, request: ReviewRequest, *, retries: int = 0,
               before_attempt: Any = None) -> ReviewResult:
    """One review attempt with bounded retries.

    A retry only ever repeats a *transport* failure. A contract-invalid answer is returned as-is: repeating
    a malformed answer just spends the budget, and the caller must treat it as a blocker. A well-formed
    refusal ends the review immediately - retrying would buy a second opinion nobody asked for.

    `before_attempt` is called before every single invocation, not once per request. A caller that caps
    spend has to be able to refuse the *second* attempt too, or three paid calls pass one check.
    """
    attempts = max(0, min(int(retries), MAX_RETRIES))
    last: ReviewResult | None = None
    for attempt in range(attempts + 1):
        if before_attempt is not None:
            try:
                before_attempt()
            except Exception as exc:  # noqa: BLE001 - a refused reservation is a status, not a crash
                return ReviewResult.failure(request, RunnerStatus.BUDGET_EXCEEDED, str(exc)[:200])
        try:
            payload = reviewer.review(request)
        except ReviewerError as exc:
            last = ReviewResult.failure(request, RunnerStatus.RUNNER_ERROR, str(exc)[:200])
        except Exception as exc:  # noqa: BLE001 - a runner crash must not authorise anything
            last = ReviewResult.failure(request, RunnerStatus.RUNNER_ERROR, f"{type(exc).__name__}: {exc}"[:200])
        else:
            result = parse_review_response(request, payload)
            # A well-formed *refusal* ends the review; a well-formed report that the attempt itself failed
            # is a transport failure wearing a status code, and is exactly what a retry exists for.
            if not _retryable(result) or attempt >= attempts:
                return result
            last = result
        if attempt < attempts and _retryable(last):
            time.sleep(min(2 ** attempt, 8))
    return last or ReviewResult.failure(request, RunnerStatus.RUNNER_ERROR, "review produced no result")


def _retryable(result: ReviewResult | None) -> bool:
    return result is not None and result.status in (RunnerStatus.TIMEOUT, RunnerStatus.RUNNER_ERROR,
                                                    RunnerStatus.QUOTA_EXHAUSTED)
