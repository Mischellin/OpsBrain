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

## Testing without a token

The default runner is `fake` - deterministic, rule-driven, no I/O. Every test and every default
configuration uses it, so the pipeline is provable offline. Live smoke is opt-in and never runs in CI:

```bash
OPSBRAIN_LIVE_REVIEW=/path/to/argv-file uv run pytest -k live_smoke
```
