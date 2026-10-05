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
