# Autonomy

How a change gets reviewed and, eventually, approved without a human typing `yes` every time.

The starting point is [issues #3](https://github.com/Mischellin/OpsBrain/issues/3) and its eleven children.
[autonomy-goal.md](autonomy-goal.md) tracks what is done.

## The shape

```
Task -> diagnosis/evidence -> immutable plan -> deterministic preflight -> Codex review
      -> policy decision -> canary apply -> post-checks -> Codex postflight -> rollout -> VERIFIED
```

Manual approval still exists and still works. Autonomy is a *second* way to obtain an approval, and it is
switched off in a config file, not by a flag a model can set.

## The review contract

`auto/review.py` is the versioned JSON contract shared with DevBrain ([#30](https://github.com/Mischellin/DevBrain/issues/30)).
Three properties are enforced in code rather than documented:

1. **Only a `PASS` authorises anything.** A crash, a timeout, a quota error, malformed JSON, a truncated
   answer or a contract-version mismatch all resolve to a non-OK `RunnerStatus` with **no verdict at
   all**. There is no code path from "the reviewer failed" to "go ahead".
2. **A `BLOCKER` finding vetoes an otherwise passing verdict.** A reviewer cannot hand out a pass and
   quietly note a blocker in the same breath.
3. **The reviewer observes, it never acts.** `CodexReviewer` is handed text and returns text. It has no
   executor, no ssh config and no kubeconfig, and its environment is rebuilt from an allowlist so
   `SSH_AUTH_SOCK`, `KUBECONFIG`, `DOCKER_HOST` and cloud credentials are not present.

`ReviewRequest.review_id` is content-addressed, so a retry after a timeout reuses the stored verdict
instead of paying for a second review — and a redelivery keeps the `BLOCKER` that caused a refusal.

## Connecting a reviewer

```yaml
auto:
  enabled: true
  review:
    runner: codex
    command: ["codex", "exec", "--model", "{model}", "--json", "{prompt}"]
    model: <model id>
    auth: subscription        # or: api
    live: true
    snapshot_dir: ~/.opsbrain/auto
    max_model_calls: 40
    budget_usd: 2.00
```

`{prompt}` is replaced with a 0600 file holding the request; `{model}` with the model from **config**,
never from model output. The argv is a list — there is no shell and nothing is concatenated into a string.

### `sandbox` is mandatory, not advisory

A working directory confines nothing. It does not make a directory read-only, and it does not stop the
child process from writing anywhere the operator can — or from reading the operator's SSH keys and
kubeconfig. The whole promise of this module is that the reviewer observes and never acts, so `live: true`
without an enforced wrapper is refused by the config, not merely discouraged in a docstring. The wrapper
prefixes the command, so the reviewer really is inside it:

```yaml
auto:
  review:
    live: true
    sandbox:
      - sandbox-exec
      - -p
      - '(version-1)(deny default)(allow process*)(allow file-read* (subpath "/usr") (subpath "/var/lib/opsbrain"))(deny network*)'
    scratch_home: /var/lib/opsbrain/review-scratch   # an empty HOME, never yours
```

`bwrap --ro-bind / /` or `firejail` work as well. `HOME`, `XDG_CONFIG_HOME` and `XDG_CACHE_HOME` are
re-pointed at `scratch_home`, so "go read your credentials" becomes a filesystem decision the sandbox
makes rather than something a well-behaved reviewer is trusted not to try.

### Output that is not a single JSON document

`codex exec --json` prints a JSONL *stream* of events, not one verdict document. `parse_review_response`
therefore pulls the contract document out of whatever it was given: the whole payload if that is already
a document, otherwise the last line that is one, otherwise the last event carrying a nested document under
a known key. A stream whose final event refuses is never promoted to a pass.

Check the setup before you need it in anger:

```bash
opsbrain autonomy capabilities
```

It reports the resolved binary, its `--version` and whether the model was actually verified. It never
claims a model works without credentials: `model_checked` stays `false` until you confirm it yourself.
`opsbrain autonomy status` shows the switches, the mode and the spent budget.

## Budgets

Call and spend ceilings are checked **before** a call is made, so an exhausted budget fails with
`BUDGET_EXCEEDED` instead of being discovered afterwards. There is no fallback model: a quota error is
reported, not worked around by spending somewhere else.

Three details make the ceiling real rather than advisory:

- **The spend check projects the worst case** from the configured context and output limits, not from what
  the reviewer later claims it used. A call that could cross `budget_usd` is refused up front.
- **Every attempt is reserved separately.** `max_retries` means more than one invocation, so one
  reservation per *request* would let three paid calls pass a single check.
- **Usage is recovered from disk on start.** A restart does not hand out a fresh `max_model_calls`, and
  `opsbrain autonomy status` reports what the server actually spent rather than zero.

Reported token counts are validated before they are charged: they arrive from the same untrusted JSON as
the verdict, and an unchecked `int()` there is both a crash (`"unknown"`) and a hole (a negative count
that *reduces* recorded spend). Absurd, negative or non-integer values make the answer
`INVALID_RESPONSE` and move the budget by zero.

## Testing without a token

The default runner is `fake` - deterministic, rule-driven, no I/O. Every test and every default
configuration uses it, so the pipeline is provable offline. Live smoke is opt-in and never runs in CI:

```bash
OPSBRAIN_LIVE_REVIEW=/path/to/argv-file uv run pytest -k live_smoke
```

## Cache identity and redelivery

`review_id` is always re-derived from the request; a caller-supplied id is ignored rather than honoured.
Trusting it would let a request for subject B present the id of subject A and be answered from A's stored
`PASS` without the reviewer ever being asked about B.

The fingerprint covers the **effective** context — the text after clipping — plus the limits and the model
that produced it. Hashing the raw context would let a redelivery under a wider limit reuse a verdict given
for a clipped one, silently skipping whatever the wider window would have added.

Two requests for the same id cannot both reach the reviewer: an in-process lock per id covers one server,
and an atomic claim file covers a second process. The loser is told to re-issue rather than being charged
for a duplicate.

## Emergency stop

One switch blocks **every** autonomous decision:

```yaml
auto:
  decision:
    mode: autonomous
    emergency_stop: true
```

In the engine it is checked before any of the review, evidence, plan or verification work, so a stop
applies to work already mid-loop and not merely to work about to start, whatever the inputs look like. It
is *not* the very first check: an unrecognised `mode`, a mode that differs from the configured one, and a
policy `deny` are settled before it, because those are answers in their own right - a forbidden change is
`DENY` whether or not the emergency stop is set. The reasons it emits are `emergency_stop` and
`autonomy_off`; both are terminal, and neither ever turns into a retry.

The neighbouring switches are deliberately narrower:

- `autonomy_token` — presence is required for autonomous mode at all. It is read from the operator's
  configuration and never from a model's output, so a model cannot grant itself the ability to decide.
- `allow_destructive` — off by default. Without it, a change that destroys or replaces resources stays with
  a person, whatever the rest of the decision says.
- `mode: manual` — the operator's escape hatch. The engine is installed in front of the change store
  regardless, but in manual mode it does not decide, and the human path works exactly as it always did.

Turning the whole subsystem off is `auto.enabled: false`. Every other setting is inert in that case,
including the emergency stop, which then has nothing to stop.

