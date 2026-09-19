# Architecture

```text
Claude ──MCP (stdio | loopback HTTP + bearer)──> server.py  12 tools, terse schemas
                                                   │  Core.call: audit, size cap, errors -> {"error": ...}
                                                   ▼
                          service.py = Readers (docs, hosts, k8s, network, observe)
                                     + Operators (tofu, ansible, drift)
             policy.py ── allow | confirm | deny        changes.py ── two-step gate
             jobs.py ──── detached operations           artifacts.py ─ redacted raw output
             parsers.py ─ raw text/JSON -> facts        redact.py ──── secret shapes
                                                   ▼
                          executor.py  the only module that starts processes (ssh, kubectl, ansible-playbook)
```

## Where the tokens go (and do not)

| Source of cost | What OpsBrain does |
| --- | --- |
| Tool schemas in every conversation | 12 tools with an `action` argument; a test caps the total schema size |
| `tofu plan` (hundreds of lines) | counters + address / action / changed attribute *names*, dangerous first |
| Ansible output | recap of non-ok hosts, changed tasks, first lines of failures |
| `kubectl get pods -A` | only pods that are not healthy or restart too much; Argo apps that are not Synced+Healthy |
| Logs | message shapes with counts (numbers and ids collapsed) + the last lines |
| Prometheus | labels common to all series hoisted; ranges reduced to min / avg / max / last |
| Healthy hosts | one word each; details only for hosts with a warning |
| Anything larger than `limits.max_chars` | stored as an artifact, the head returned |
| Re-reading docs | `docs status` = last memory-log entry + section index; `search` returns lines, `read` slices |

Every call records raw and returned bytes in `audit.jsonl`; `opsbrain stats` sums them up.

## Security invariants

1. **No free-form execution.** There is no shell / exec tool. Scripts are fixed templates; variable parts are names
   defined in the config or values matching a strict pattern, always `shlex.quote`d. Local commands are argv lists.
2. **Read-only by default.** Read capabilities default to `allow`, mutating and unknown ones to `confirm`; a `deny`
   on any matching rule wins over any `allow`.
3. **A mutation needs a change.** Bound to capability + target + content hash; expiring; single use. The tofu change
   points at a saved plan file, the Ansible change at a fingerprint of the whole ansible directory + arguments.
4. **Claude cannot approve.** Approval exists only as `opsbrain approve` and refuses to run without an interactive
   terminal. This is a guard against accidents and prompt injection, not against a hostile local process: anything
   running as you can write the change file. Destructive plans (destroy / replace) additionally need
   `--allow-destroy` and typing the change id, even when policy says `allow`.
5. **The router is never changed.** `network` has no mutating action; the export is always `hide-sensitive`.
6. **Secrets are not read.** Kubernetes Secrets are not a readable kind; the docs reader refuses vault / secret / env /
   key / state files; the tofu env file is sourced on the runner; the machine-readable plan (which may contain sensitive
   values) is parsed in memory and never stored.
7. **Redaction before storage.** Everything passes `redact.py` before it becomes an artifact, a result or an audit
   line. It is best effort: the real guarantee is 5 and 6.
8. **HTTP is loopback + bearer token**, with DNS-rebinding protection; stdio needs neither.

## Detached jobs

`(script) > log 2>&1; echo $? > rc` under `nohup` (remote) or a new session (local). The job record, log and rc file
are the whole state, so a job started before a server restart is still pollable. On first sight of the rc file the
job is *finalised*: parsed, stored as an artifact, possibly turned into a change, remote files removed. The drift
check is a group job over a tofu plan per stack, one local job running the playbooks in `--check` (with one retry when
a playbook reports only `unreachable`, a known ssh flake) and the router diff.
