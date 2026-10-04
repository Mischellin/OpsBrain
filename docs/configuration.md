# Configuration

One YAML file: `$OPSBRAIN_CONFIG` or `~/.opsbrain/config.yaml` (`opsbrain init` writes an example;
[examples/config.yaml](../examples/config.yaml)). Unknown keys are errors. The file holds no secrets.

| Key | Meaning |
| --- | --- |
| `repo` | local checkout of the infrastructure repository |
| `data_dir` | artifacts, changes, jobs, `audit.jsonl`, `http.token` (default `~/.opsbrain`) |
| `remote_job_dir` | where detached jobs keep log / rc on a runner (default `/tmp/opsbrain`, created 0700) |
| `ignore_failed_units` | systemd units whose failed state is known noise (not reported by `hosts status`) |
| `hosts.<name>` | `address`, `user` (root), `port`, `jump` (another host, directly reachable), `sudo`, `tags`, `services` (units that may be inspected and restarted), `kind` (`linux` \| `routeros`) |
| `tofu.<stack>` | `runner` (host), `dir`, `env_file` (sourced on the runner), `binary`, `source_dir` + `sync` (copy `*.tf` before a plan; never deletes remotely, reports `remote_only` files) |
| `ansible` | `dir`, `playbook_bin`, `playbooks_dir`, `playbooks` (allowlist; empty = all), `require_limit_for_apply`, `ssh_auth_sock_from_launchctl`, `env` |
| `k8s` | `kubectl`, `kubeconfig`, `context`, `argocd_namespace`, `restart_threshold` |
| `network` | `router` (host), `tracked_export` (repo-relative), `print_paths` (allowlist for `print`) |
| `observe` | `prometheus_url`, `loki_url`, `http_checks` (name -> URL), `verify_tls` |
| `docs` | `globs`, `status_file`, `memory_file` (the last `## ` entry is "the current state") |
| `drift` | `tofu_stacks` (empty = all), `playbooks`, `network` |
| `policy` | `capability[:target]` -> `allow` \| `confirm` \| `deny` |
| `limits` | `max_items`, `max_chars`, `change_ttl_s`, `artifact_retention_days`, `default_wait_s` |
| `http` | `host`, `port`, `allowed_hosts` for `serve --http` |

## Policy

Capabilities - read: `docs.read`, `hosts.read`, `tofu.plan`, `tofu.state`, `ansible.check`, `k8s.read`,
`network.read`, `observe.read`, `drift.check`; mutating: `hosts.restart`, `tofu.apply`, `tofu.unlock`,
`ansible.apply`, `k8s.refresh`, `k8s.sync`, `k8s.restart`.

Targets: host name (`hosts.*`), stack (`tofu.*`), playbook (`ansible.*`), namespace (`k8s.restart`, `k8s.read`),
application (`k8s.refresh`, `k8s.sync`). Wildcards: `tofu.*`, `*`. Resolution: the most specific matching rule,
except that a `deny` anywhere wins.

```yaml
policy:
  "k8s.refresh": allow
  "k8s.restart:okydoky-dev": allow
  "ansible.apply:proxmox": deny
```

## Autonomy (`auto`)

The whole autonomous pipeline is inert unless `auto.enabled` is true. See [autonomy.md](autonomy.md).

| Key | Meaning |
| --- | --- |
| `auto.enabled` | master switch; false keeps the manual two-step gate as the only path |
| `auto.review.runner` | `fake` (deterministic, no tokens) \| `codex` (external CLI) |
| `auto.review.command` | argv template; `{prompt}` is the request file, `{model}` the configured model. No shell |
| `auto.review.model` / `auth` | model id; `subscription` \| `api`. No hidden paid fallback |
| `auto.review.live` | without `true` no external binary is ever started |
| `auto.review.timeout_s` / `max_parallel` / `max_retries` | per-request transport bounds |
| `auto.review.max_model_calls` / `budget_usd` | hard ceilings, checked *before* a call is made |
| `auto.review.snapshot_dir` | read-only directory the reviewer is confined to |
| `auto.evidence.max_age_s` | freshness window for a bundle |
| `auto.decision.mode` | `manual` \| `autonomous`. Autonomous additionally requires `autonomy_token` |
| `auto.decision.max_repair_cycles` / `max_model_calls` / `max_wall_s` / `max_spend_usd` | recovery bounds |
| `auto.decision.allow_destructive` | autonomous execution of a destroying change; false by default |
| `auto.decision.emergency_stop` | one switch that blocks every autonomous decision |
| `auto.decision.default_profile` | which policy profile applies when none is matched |
| `auto.decision.policy_version` | bumped by the operator; an approval bound to another version is STALE |
| `auto.profiles[]` | per-profile evidence / precondition / verification / target requirements |
| `auto.autonomy_token` | presence required for autonomous mode; never read from model output |
