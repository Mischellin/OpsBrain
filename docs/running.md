# Running it

How to exercise this repository, and what each command actually proves. Everything here runs offline:
no token, no cluster, no production host. The live paths are opt-in and say so.

## The four suites

```bash
uv run pytest -m unit          # a single module's own rules          146 tests
uv run pytest -m integration   # modules wired together, no mutation  487 tests
uv run pytest -m security      # an attempt to get past a gate         12 tests
uv run pytest -m e2e           # the whole chain, evidence to VERIFIED  4 tests
uv run pytest                  # all of it                              648
```

The split is by what a test *proves*, not by which file it lives in (`tests/conftest.py`, in
`pytest_collection_modifyitems`). A security regression is also an end-to-end test, and a directory
layout would have forced it to be one or the other.

`ruff` and `mypy --strict` cover `src`:

```bash
uv run ruff check .
uv run mypy src
```

## What each suite is actually evidence of

| suite | what it proves | what it does not |
|---|---|---|
| `unit` | each module's rules hold on their own inputs | that the modules are connected |
| `integration` | the pipeline is wired: evidence feeds review, review feeds the engine, the engine's approval reaches the gate | that a real change can get all the way through |
| `security` | eleven specific attempts to get through a gate all fail, and each names the invariant it defends | that there are no other attacks |
| `e2e` | one permitted change runs the whole chain with no `opsbrain approve` anywhere in it | anything about live infrastructure |

The `e2e` suite is the one to read first. It walks: evidence → an incorrect plan → a review finding →
a corrected plan → preflight PASS → the engine's approval → apply → canary → deterministic
verification → postflight → rollout. The only things stubbed are the outside world — OpenTofu, ssh,
Codex — through the `fake` executor and the `fake` reviewer. Every gate in the middle is the real one.

## The two fixtures that started this

Both are in `tests/test_auto_e2e.py`, and both are the shape of failure the whole design exists for:

- **A drop-in in the wrong directory.** `logrotate.d` holds logrotate's own configuration; systemd
  reads `logrotate.service.d`. The apply exits 0, the file exists, the unit is active, and nothing
  happened. Stopped by the review before the change is made, and — in the second test — by
  verification after it is applied by something that did not go through the first door.
- **A green apply that changed nothing.** The same chain with the unit active but the drop-in not in
  force. Every signal the apply produced is green; the verification fails; the rollout never opens a
  second stage; the postflight says `not_met` and tells the operator to roll back.

## The opt-in live check

Not run in CI, and not run in this work. It needs a real token and a real CLI, and it is a check of
the *reviewer's* capabilities, not of the workflow:

```bash
OPSBRAIN_LIVE_REVIEW=1 uv run pytest -m e2e
```

Without the variable the live runner reports itself unavailable and is refused — the stub guard is a
test in its own right (`test_the_stub_runner_may_not_stand_in_for_a_paid_one`), because the offline
suite proving the workflow is not evidence that the model works.

## What has actually been run here

| | result |
|---|---|
| `uv run pytest` | **648 passed, 1 skipped** |
| `uv run ruff check .` | clean |
| `uv run mypy src` | clean, 37 files |
| Live review against the real `codex` runner | **not run** — opt-in, needs a real token |
| Live OpenTofu / Ansible / kubectl against real infrastructure | **not run**, and not claimed |
| `@codex review` | requested on every push; 16 rounds worked through, ~140 findings closed |

The one skip is the live review, and it is skipped on purpose rather than because it failed.

## How a guard is proved

A test that passes on broken code is worse than no test, because it is a claim. Every guard added in
this work was checked by reverting the guard and confirming the test fails — a few of them needed two
attempts, because the first mutation removed a line the test never reached, and a mutation that changes
nothing looks exactly like a guard that cannot be seen.

That is worth stating plainly for the next person: **"the rollback did not break the test" is a result
that has to be checked before it is believed.** Sometimes the guard is genuinely covered twice and
nothing is wrong. Sometimes the string you replaced was not the string in the file, and you proved
nothing at all.
