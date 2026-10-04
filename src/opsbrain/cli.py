"""`opsbrain` command line: serve, approve (the human side of the two-step gate), changes, doctor, stats."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from importlib import resources
from pathlib import Path

from . import __version__
from .config import ConfigError, config_path, load_config
from .service import OpsBrain
from .util import OpsError


def _ops(args: argparse.Namespace) -> OpsBrain:
    return OpsBrain(load_config(args.config))


def cmd_serve(args: argparse.Namespace) -> int:
    from .server import build_http_app, build_server, http_token

    ops = _ops(args)
    ops.artifacts.gc()
    if not args.http:
        build_server(ops).run(transport="stdio")
        return 0
    import uvicorn

    host, port = ops.config.http.host, args.port or ops.config.http.port
    print(f"OpsBrain MCP on http://{host}:{port}/mcp (bearer token: {ops.config.data_path / 'http.token'})",
          file=sys.stderr)
    http_token(ops.config.data_path)
    uvicorn.run(build_http_app(ops), host=host, port=port, log_level="warning")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    target = config_path(args.config)
    if target.exists():
        print(f"{target} already exists", file=sys.stderr)
        return 1
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    example = resources.files("opsbrain").joinpath("example-config.yaml").read_text(encoding="utf-8")
    target.write_text(example, encoding="utf-8")
    target.chmod(0o600)
    print(f"wrote {target}: edit it, then run `opsbrain doctor`")
    return 0


def cmd_changes(args: argparse.Namespace) -> int:
    changes = _ops(args).changes.list(include_closed=args.all)
    if not changes:
        print("no pending changes")
    for change in changes:
        brief = change.brief()
        flag = " DESTRUCTIVE" if change.dangerous else ""
        print(f"{brief['id']}  {brief['state']:<9} {brief['capability']}:{brief['target']}{flag}  {brief['summary']}")
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    ops = _ops(args)
    change = ops.changes.get(args.id)
    print(f"Change   {change.id}  ({change.capability} -> {change.target})")
    print(f"Summary  {change.summary}")
    for key, value in change.details.items():
        print(f"{key}:")
        for row in value if isinstance(value, list) else [value]:
            print(f"  {json.dumps(row, ensure_ascii=False)}")
    if change.dangerous:
        print("!! This change DESTROYS or REPLACES resources.")
    # an approval must come from a person at a terminal, not from an agent's non-interactive shell
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("refused: `opsbrain approve` needs an interactive terminal", file=sys.stderr)
        return 2
    expected = change.id if change.dangerous else "yes"
    if input(f"Type '{expected}' to approve: ").strip() != expected:
        print("not approved")
        return 1
    ops.changes.approve(change.id, allow_dangerous=args.allow_destroy)
    ops.audit.record(event="approved", change=change.id, capability=change.capability, target=change.target)
    print(f"approved: {change.id} (valid for {max(0, int(change.expires - time.time())) // 60} min)")
    return 0


def cmd_discard(args: argparse.Namespace) -> int:
    print(f"discarded: {_ops(args).changes.discard(args.id).id}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    problems = 0

    def report(ok: bool, text: str) -> None:
        nonlocal problems
        problems += 0 if ok else 1
        print(f"[{'ok' if ok else '!!'}] {text}")

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        report(False, str(exc))
        return 1
    report(True, f"config {config_path(args.config)}: {len(config.hosts)} hosts, {len(config.tofu)} tofu stack(s)")
    report(config.repo_path.is_dir(), f"repo {config.repo_path}")
    report(shutil.which("ssh") is not None, "ssh binary")
    if config.ansible:
        binary = Path(config.ansible.playbook_bin).expanduser()
        report(binary.is_file() or shutil.which(str(binary)) is not None, f"ansible-playbook ({binary})")
        report((config.repo_path / config.ansible.dir).is_dir(), f"ansible dir {config.ansible.dir}")
    if config.k8s:
        report(shutil.which(config.k8s.kubectl) is not None, f"kubectl ({config.k8s.kubectl})")
    if config.network and config.network.tracked_export:
        report((config.repo_path / config.network.tracked_export).is_file(), "tracked router export")
    confirm = [rule for rule, access in config.policy.items() if access.value == "allow"]
    print(f"[i ] policy: mutations default to confirm; explicitly allowed: {confirm or 'none'}")
    if args.net:
        ops = OpsBrain(config)
        ping = ops.hosts_ping()
        report(not ping["down"], f"ssh reachability {ping['up']}/{ping['total']} {ping['down'] or ''}")
    return 1 if problems else 0


def cmd_stats(args: argparse.Namespace) -> int:
    stats = _ops(args).audit.stats()
    print(f"calls: {stats['calls']}  raw: {stats['raw_bytes']} B  returned: {stats['returned_bytes']} B  "
          f"~tokens saved: {stats['tokens_saved_estimate']}")
    for tool, row in sorted(stats["per_tool"].items()):
        print(f"  {tool:<10} calls={row['calls']:<5} raw={row['raw_bytes']:<10} returned={row['out_bytes']}")
    return 0


def cmd_desktop(args: argparse.Namespace) -> int:
    from . import desktop

    config = load_config(args.config)  # a broken config must fail here, not silently inside Claude Desktop
    if args.action == "status":
        record = desktop.installed_extension()
        print(f"extension: {record or 'not installed'}")
        if desktop.legacy_config_entry():
            print("!! claude_desktop_config.json also defines OpsBrain: remove that entry (duplicate tools)")
        return 0 if record else 1
    bundle = desktop.build(config_path(args.config), config.data_path / "dist")
    print(f"built {bundle}")
    if args.action == "install":
        if desktop.legacy_config_entry():
            print("!! claude_desktop_config.json also defines OpsBrain: remove that entry (duplicate tools)")
        if args.no_open or not desktop.open_with_desktop(bundle):
            print("open the bundle with Claude Desktop (Settings -> Extensions -> Install extension)")
        else:
            print("Claude Desktop is showing the extension: press Install. Tools appear as mcp__OpsBrain__<tool>.")
    return 0


def cmd_autonomy(args: argparse.Namespace) -> int:
    """Inspect the autonomous pipeline. Read-only: it never decides and never mutates."""
    ops = _ops(args)
    auto = ops.auto
    if args.action == "status":
        view = auto.overview()
        print(f"enabled={view['enabled']} mode={view['mode']} autonomous={view['autonomous']} "
              f"policy={view['policy_version']}")
        if view["emergency_stop"]:
            print("!! emergency_stop is set: every autonomous decision is blocked")
        budget = view["budget"]
        print(f"review: runner={view['runner']} live={view['live']} model={view['model'] or '-'} "
              f"auth={view['auth']}")
        print(f"budget: calls={budget['model_calls']}/{budget['max_model_calls']} "
              f"tokens={budget['input_tokens']}+{budget['output_tokens']} spend=${budget['spend_usd']}")
        return 0 if view["enabled"] else 1
    if args.action == "capabilities":
        report = auto.reviews.capabilities()
        for key, value in sorted(report.items()):
            print(f"{key}: {value}")
        return 0 if report.get("ok") else 1
    if args.action == "reviews":
        for row in auto.reviews.list(args.limit):
            print(f"{row.get('review_id'):<20} {row.get('subject'):<15} {row.get('status'):<16} "
                  f"{row.get('verdict') or '-':<15} {row.get('model') or '-'}")
        return 0
    if args.action == "reasons":
        from opsbrain.auto.config import all_reason_codes

        for code in all_reason_codes():
            print(code)
        return 0
    if args.action == "preflights":
        for row in auto.preflight_list(args.limit):
            print(f"{row.get('plan'):<20} {row.get('outcome'):<14} approvable={row.get('approvable')!s:<6} "
                  f"{row.get('reason')}")
        return 0
    if args.action == "checks":
        view = auto.verify_overview()
        if not view.get("bound"):
            print("verification is not bound to a Core", file=sys.stderr)
            return 1
        print(f"observation_s={view['observation_s']} require_observation={view['require_observation']} "
              f"allow_state_changing_checks={view['allow_state_changing_checks']}")
        for row in auto.verification_checks():
            flag = " (acts)" if row["state_changing"] else ""
            print(f"  {row['check']:<28} {row['profile']:<9}{flag} {row['why']}")
        return 0
    if args.action == "verify-plan":
        if not args.id:
            print("usage: opsbrain autonomy verify-plan <plan-id>", file=sys.stderr)
            return 2
        answer = auto.verify_plan(args.id)
        print(json.dumps(answer, ensure_ascii=False, indent=2, default=str))
        return 1 if answer.get("status") == "not_verifiable" else 0
    if args.action == "evidence":
        view = auto.evidence_overview()
        print(f"bundles={view['bundles']} fresh_window_s={view['fresh_window_s']} "
              f"max_bundle_bytes={view['max_bundle_bytes']}")
        print(f"require_inventory_hash={view['require_inventory_hash']} "
              f"require_target_identity={view['require_target_identity']}")
        return 0
    if args.action == "bundles":
        for row in auto.evidence_list(args.limit):
            print(f"{row.get('id'):<20} {row.get('created'):<18} {(row.get('targets') or [])} {row.get('objective')}")
        return 0
    if args.action == "verify":
        if not args.id:
            print("usage: opsbrain autonomy verify <bundle-id>", file=sys.stderr)
            return 2
        answer = auto.verify_evidence(args.id)
        for check in answer["checks"]:
            print(f"[{'ok' if check['ok'] else '!!'}] {check['reason']}: {check['detail']}")
        return 0 if answer["passed"] else 1
    print(f"budget: {json.dumps(auto.reviews.usage(), ensure_ascii=False)}")
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    binary = shutil.which("opsbrain") or "opsbrain"
    print("Claude Desktop:\n  opsbrain desktop install\n")
    print("Claude Code (CLI):\n  claude mcp add --scope user OpsBrain -- " + binary + " serve\n")
    print("\nDevBrain connector (project config), with `opsbrain serve --http` running:")
    print("  connectors:\n    opsbrain: {transport: http, url: \"http://host.docker.internal:8765/mcp\", "
          "secret: opsbrain, environment: production}")
    print("  # devbrain secret set opsbrain   <- content of ~/.opsbrain/http.token")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="opsbrain", description="Token-cheap MCP server for infrastructure")
    parser.add_argument("--config", help="config file (default: $OPSBRAIN_CONFIG or ~/.opsbrain/config.yaml)")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="run the MCP server (stdio by default)")
    serve.add_argument("--http", action="store_true", help="streamable HTTP on loopback with a bearer token")
    serve.add_argument("--port", type=int)
    serve.set_defaults(handler=cmd_serve)
    commands.add_parser("init", help="write an example config").set_defaults(handler=cmd_init)
    changes = commands.add_parser("changes", help="list changes waiting for approval")
    changes.add_argument("--all", action="store_true")
    changes.set_defaults(handler=cmd_changes)
    approve = commands.add_parser("approve", help="approve one change (interactive terminal only)")
    approve.add_argument("id")
    approve.add_argument("--allow-destroy", action="store_true", help="required when resources are destroyed/replaced")
    approve.set_defaults(handler=cmd_approve)
    discard = commands.add_parser("discard", help="discard one change")
    discard.add_argument("id")
    discard.set_defaults(handler=cmd_discard)
    doctor = commands.add_parser("doctor", help="check config, binaries and (with --net) ssh reachability")
    doctor.add_argument("--net", action="store_true")
    doctor.set_defaults(handler=cmd_doctor)
    commands.add_parser("stats", help="token savings from the audit log").set_defaults(handler=cmd_stats)
    autonomy = commands.add_parser("autonomy", help="inspect the autonomous pipeline (read-only)")
    autonomy.add_argument("action", choices=["status", "capabilities", "reviews", "budget", "evidence",
                                            "bundles", "verify", "checks", "preflights", "reasons",
                                            "verify-plan"])
    autonomy.add_argument("id", nargs="?")
    autonomy.add_argument("--limit", type=int, default=20)
    autonomy.set_defaults(handler=cmd_autonomy)
    desktop = commands.add_parser("desktop", help="Claude Desktop extension (.mcpb): build | install | status")
    desktop.add_argument("action", choices=["build", "install", "status"])
    desktop.add_argument("--no-open", action="store_true")
    desktop.set_defaults(handler=cmd_desktop)
    commands.add_parser("install", help="print how to connect Claude Code and DevBrain").set_defaults(
        handler=cmd_install)

    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (ConfigError, OpsError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
