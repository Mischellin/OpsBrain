<div align="center">

# 🛡️ OpsBrain

### **Deterministic, Token-Efficient MCP Server for Safe Infrastructure Operations by AI Coding Agents**

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-2.2+-8A2BE2.svg?style=flat-square&logo=anthropic&logoColor=white)](https://modelcontextprotocol.io/)
[![Linter: Ruff](https://img.shields.io/badge/linter-ruff-black.svg?style=flat-square)](https://github.com/astral-sh/ruff)
[![Type Checked: Mypy Strict](https://img.shields.io/badge/type_checked-mypy_strict-blue.svg?style=flat-square)](https://mypy-lang.org/)
[![Tests: Pytest](https://img.shields.io/badge/tests-71_passed-brightgreen.svg?style=flat-square)](https://pytest.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)

**OpenTofu · Ansible · Kubernetes · Argo CD · SSH · MikroTik · Prometheus & Loki**

---

</div>

OpsBrain is a local [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that lets autonomous coding agents (Claude Code, Claude Desktop, Cursor, DevBrain) manage and monitor real infrastructure **safely, cheaply in tokens, and with zero hallucinated bash commands**.

---

## ⚡ Why OpsBrain?

```
┌─────────────────────────────────┐
│     AI Agent (Claude / Codex)   │
└────────────────┬────────────────┘
                 │ MCP Protocol (12 compact schemas)
                 ▼
┌────────────────────────────────────────────────────────┐
│                      OpsBrain                          │
│  • Argument validation against strict config patterns  │
│  • Redaction of secrets, tokens, and noisy logs        │
│  • Two-phase mutation: Plan ──> Hash-Bound Token       │
└────────────────┬───────────────────────────────────────┘
                 │ Requires Terminal Approval
                 ▼
┌─────────────────────────────────┐      Approved      ┌─────────────────────────┐
│  CLI: opsbrain approve <hash>   ├───────────────────►│  Target Infrastructure  │
│      (Human in the loop)        │                    │  K8s / Tofu / Ansible   │
└─────────────────────────────────┘                    └─────────────────────────┘
```

1. **Token Economy (12 tools, not 120):**  
   Every tool schema is injected into the context window on every prompt. OpsBrain groups operations into 12 compact tools, returning only the essential diffs and counters. Full raw outputs are redacted and saved to local disk *artifacts* that can be grepped on demand.
2. **Zero Shell Execution:**  
   OpsBrain never exposes a raw `sh` or `exec` tool. Every command is executed through fixed, auditable templates with validated parameters.
3. **Cryptographically Bound Mutations:**  
   Mutating actions (`tofu apply`, `ansible apply`, `k8s restart`) are strictly two-phase:
   * Agent runs `plan` / `check` $\to$ receives a unique `change_id` bound to the hash of the plan.
   * A human operator approves it in a local terminal: `opsbrain approve <change_id>`.
   * Agent executes `apply` using the `change_id`. The change is invalidated if state drifts.
4. **Resilient Long-Running Operations:**  
   `tofu apply`, playbooks, and drift checks run detached (process log + return code file). MCP client timeouts or network drops do not corrupt runs; the agent polls execution status via `job`.
5. **Zero Credential Storage:**  
   OpsBrain never stores cloud credentials or SSH keys. It piggybacks on the existing local environment (`ssh-agent`, `~/.kube/config`, Ansible Vault password file).

---

## 📖 Documentation

* [Architecture & Design Principles](docs/architecture.md)
* [Configuration Guide](docs/configuration.md)
* [Руководство пользователя (на русском)](docs/guide-ru.md)

---

## 🚀 Quickstart & Installation

### 1. Install CLI
```bash
# Install with uv
uv tool install git+https://github.com/Mischellin/OpsBrain.git

# Initialize local configuration (~/.opsbrain/config.yaml)
opsbrain init

# Check environment connectivity (SSH, Kubeconfig, runners)
opsbrain doctor --net
```

### 2. Connect to AI Assistants

#### Claude Code (CLI)
```bash
claude mcp add --scope user OpsBrain -- opsbrain serve
```

#### Claude Desktop
```bash
opsbrain desktop install
```
*Builds a lightweight `.mcpb` bundle with a dependency-free Node launcher that preserves your local `PATH` and `ssh-agent`.*

#### HTTP Transport (DevBrain, Remote Agents)
```bash
opsbrain serve --http
# Listens on 127.0.0.1:8765/mcp with bearer token in ~/.opsbrain/http.token
```

---

## 🧰 Available MCP Tools

| Tool | Actions | Description |
| :--- | :--- | :--- |
| `overview` | `inventory`, `pending`, `running` | Global summary of hosts, running jobs, and pending approval changes |
| `docs` | `status`, `search`, `read` | Access to infrastructure repo documentation (secrets automatically blocked) |
| `hosts` | `list`, `ping`, `status`, `services`, `logs`, `restart`* | Host health, systemd service states, journalctl logs |
| `tofu` | `plan`, `apply`*, `state`, `unlock`* | OpenTofu / Terraform lifecycle management |
| `ansible` | `playbooks`, `check`, `apply`* | Playbook execution and drift verification |
| `k8s` | `overview`, `get`, `describe`, `logs`, `events`, `sync`*, `restart`* | Kubernetes cluster inspection, Argo CD synchronization |
| `network` | `drift`, `export`, `print` | Read-only inspection of MikroTik router configs and interfaces |
| `drift` | Single-call drift check | Runs `tofu plan` + `ansible --check` + router export in one command |
| `observe` | `alerts`, `targets`, `query`, `logs`, `http` | Prometheus / VictoriaMetrics alert checks, Loki log queries |
| `artifact` | `list`, `read`, `grep` | Read slices of large command outputs saved to disk |
| `job` | `status`, `list` | Poll and inspect detached background operations |
| `change` | `list`, `show`, `discard` | Inspect pending changes (human approval is CLI-only) |

*\* Mutating operation: requires an approved `change_id` unless explicitly permitted in security policy.*

---

## 🔍 End-to-End Walkthrough

```text
1. Claude calls OpenTofu plan:
   Claude: tofu action=plan
   OpsBrain: {
     "changes": true, "add": 0, "change": 1, "destroy": 0,
     "resources": [{"addr": "proxmox_vm.web", "action": "change", "attrs": ["cores"]}],
     "change": "c-1f3a9b2c",
     "artifact": "a-77aa01bc"
   }

2. Human approves the plan in terminal:
   $ opsbrain approve c-1f3a9b2c
   Target: proxmox_vm.web (change cores: 4 -> 8)
   Approve change c-1f3a9b2c? [type 'yes']: yes
   ✓ Change c-1f3a9b2c approved.

3. Claude executes the approved change:
   Claude: tofu action=apply change_id=c-1f3a9b2c
   OpsBrain: {
     "ok": true,
     "applied": {"added": 0, "changed": 1, "destroyed": 0},
     "post_plan_clean": true
   }
```

---

## 🧪 Development & Testing

OpsBrain includes a complete offline test suite with mock SSH and HTTP clients:

```bash
# Clone repository
git clone https://github.com/Mischellin/OpsBrain.git
cd OpsBrain

# Install dependencies and sync environment
uv sync

# Run linting, static type analysis, and test suite
uv run ruff check .
uv run mypy
uv run pytest -q
# 71 passed in ~3s
```

---

## 📄 License

MIT © [Mikhail Sidorkin](https://github.com/Mischellin)
