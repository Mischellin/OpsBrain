# OpsBrain

Local MCP server that lets Claude operate an infrastructure **cheaply in tokens and safely**: OpenTofu, Ansible,
Kubernetes / Argo CD, hosts over ssh, a MikroTik router, Prometheus / Loki and the infrastructure repo's own docs.

- **Compact answers.** A tool returns the few facts that matter (counters, only what is wrong, only what differs).
  Raw output is redacted and kept on disk as an *artifact*; Claude reads a slice or greps it only when needed.
- **12 tools, not 120.** Tool schemas are paid for in every conversation; related operations share one tool.
- **No shell tool.** Commands are fixed templates; every argument is checked against the config or a strict pattern.
- **Read-only by default.** A mutation is two-step: `plan` / `check` creates a *change* bound to a hash of exactly what
  would be applied; a human approves it in a terminal (`opsbrain approve <id>`); `apply` consumes it once.
- **Long operations survive.** `tofu apply`, playbooks and the drift check run detached (log + rc file), so an MCP
  timeout or a dropped ssh session cannot interrupt them; `job` polls.
- **Audit and savings.** Every call is logged with raw vs returned bytes; `opsbrain stats` shows the tokens saved.

Docs: [architecture](docs/architecture.md) · [configuration](docs/configuration.md) · [руководство (RU)](docs/guide-ru.md)

## Install

```bash
uv tool install git+https://github.com/Mischellin/OpsBrain.git     # or: uv sync && uv run opsbrain ...
opsbrain init        # writes ~/.opsbrain/config.yaml - describe your hosts, stacks, playbooks
opsbrain doctor --net
opsbrain install     # prints the snippets for Claude Code, Claude Desktop and DevBrain
```

```bash
claude mcp add --scope user OpsBrain -- opsbrain serve
```

Requirements: Python >= 3.13, `ssh` with an agent; `ansible-playbook` / `kubectl` only if you use those tools.
OpsBrain stores no credentials: it uses what already works on this machine (ssh-agent, kubeconfig, ansible-vault
password file) and what lives on the runner (the tofu env file is sourced there and never read).

## Tools

| Tool | Actions |
| --- | --- |
| `overview` | inventory, pending changes, running jobs |
| `docs` | `status` (current state) · `search` · `read` - the infra repo's knowledge, secrets-bearing files refused |
| `hosts` | `list` · `ping` · `status` · `services` · `logs` · `restart`* |
| `tofu` | `plan` · `apply`* · `state` · `unlock`* |
| `ansible` | `playbooks` · `check` · `apply`* |
| `k8s` | `overview` · `get` · `describe` · `logs` · `events` · `refresh`* · `sync`* · `restart`* |
| `network` | `drift` · `export` · `print` - the router is never changed |
| `drift` | code vs live in one call: tofu plan + playbooks `--check` + router export |
| `observe` | `alerts` · `targets` · `query` · `logs` · `http` |
| `artifact` | `list` · `read` · `grep` |
| `job` | `status` · `list` |
| `change` | `list` · `show` · `discard` (approval exists only in the CLI) |

\* mutating: needs an approved change unless the policy says `allow`.

## A mutation, end to end

```text
Claude: tofu action=plan            -> {"changes":true,"add":0,"change":1,"destroy":0,
                                        "resources":[{"addr":"proxmox_vm.web","action":"change","attrs":["cores"]}],
                                        "change":"c-1f3a9b2c","artifact":"a-77aa01bc"}
You:    opsbrain approve c-1f3a9b2c -> shows the summary, asks to type "yes"  (destroy/replace: --allow-destroy + the id)
Claude: tofu action=apply change_id=c-1f3a9b2c
                                    -> {"ok":true,"applied":{"added":0,"changed":1,"destroyed":0},"post_plan_clean":true}
```

`apply` runs the **saved plan file**, so what is applied is what was approved; OpenTofu itself rejects the file if
the state moved in between. An Ansible change is void as soon as any file under the ansible directory changes.

## Use it from DevBrain

```bash
opsbrain serve --http          # 127.0.0.1:8765/mcp, bearer token in ~/.opsbrain/http.token
```

```yaml
connectors:
  opsbrain: {transport: http, url: "http://host.docker.internal:8765/mcp", secret: opsbrain, environment: production}
capabilities:
  infra.drift: {connector: opsbrain, tool: drift, description: "Code vs live infrastructure"}
  infra.tofu:  {connector: opsbrain, tool: tofu, mutating: true}
```

## Development

```bash
uv sync && uv run ruff check . && uv run mypy && uv run pytest -q
```

Tests use a fake executor and a fake HTTP client: no network, no ssh.
