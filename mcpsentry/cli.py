"""Command-line entry points. Human output never shares MCP stdout."""

import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
import time
from datetime import datetime, timezone

from .audit import Audit, display
from .config import load
from .gateway import Gateway, read_baseline, serve
from .security import poisoned, Guard
from . import __version__
from .dlp import OutboundInspector, MAX_BYTES
from .approvals import Approvals
from .sandbox import command as sandbox_command, protect_state
from .runtimes import client_executable


def activity_line(event):
    stamp = datetime.fromtimestamp(event["timestamp"], timezone.utc).strftime("%H:%M:%S")
    # Reuse JSON escaping; backend-controlled names cannot emit terminal codes.
    tool = json.dumps(event["tool"], ensure_ascii=True)
    return f"{event['id']:>6} {stamp} {event['decision']:<11} {event['event']:<18} {tool} {event['reason']} {event['duration_ms']}ms"


def report_text(report):
    totals = report["totals"]
    lines = ["MCP-Sentry activity report", f"Session: {report['session'] or 'all'}",
             f"Attempts: {totals['attempted']} | Forwarded: {totals['forwarded']} | Blocked before dispatch: {totals['blocked_before_dispatch']}",
             f"Responses withheld: {totals['responses_blocked']} | Failures: {totals['failures']} | Tool errors: {totals['tool_errors']} | Monitor violations: {totals['monitor_violations']}",
             f"Redacted calls: {totals['redacted_calls']}",
             f"Average latency: {totals['average_duration_ms']}ms | Maximum: {totals['max_duration_ms']}ms", "", "Tool · attempted / forwarded / blocked"]
    lines.extend(f"{json.dumps(row['tool'], ensure_ascii=True)} · {row['attempted']} / {row['forwarded']} / {row['blocked_before_dispatch']}" for row in report["tools"])
    if report["tools_truncated"]:
        lines.append("Showing the top 500 tools; totals include all events.")
    return "\n".join(lines)


def demo_config():
    script = str(Path(__file__).with_name("demo_server.py"))
    return {
        "servers": {name: {"command": sys.executable, "args": [script, kind], "cwd": str(Path.cwd())} for name, kind in (("db", "database"), ("mail", "mail"))},
        "policy": {"default": "deny", "allow": ["db__read_customer", "mail__send"], "deny": ["*__delete*"], "sensitive_sources": ["db__*"], "recipient_allowlists": {"mail__send": {"to": ["team@example.com"]}}},
        "timeout_seconds": 5,
    }


async def demo(audit, dlp=False):
    from .demo_server import CUSTOMER, FAKE_SECRET
    gateway = Gateway(demo_config(), audit)
    try:
        tools = await gateway.start()
        print(f"MCP-Sentry · local demo · {len(tools)} tools · enforce mode")
        checks = [
            ("Authorized database read", {"name": "db__read_customer"}, None),
            ("Ordinary message to approved recipient", {"name": "mail__send", "arguments": {"to": "team@example.com", "body": "Summary completed."}}, None),
            ("Fake-secret transfer", {"name": "mail__send", "arguments": {"to": "team@example.com", "body": FAKE_SECRET}}, "secret_in_arguments"),
            ("Copied customer reference", {"name": "mail__send", "arguments": {"to": "team@example.com", "body": "Record: " + CUSTOMER}}, "sensitive_data_transfer"),
            ("Unapproved recipient", {"name": "mail__send", "arguments": {"to": "outside@example.com", "body": "Hello"}}, "recipient_not_allowed"),
            ("Destructive tool", {"name": "mail__delete_all"}, "tool_denied"),
        ]
        if dlp:
            import base64
            import gzip
            fictional_email = b"fictional.person@example.com"
            extra = [
                ("Payment card (published test fixture)", "4242424242424242", "sensitive_data:payment_card"),
                ("Email address in message body", fictional_email.decode(), "sensitive_data:email"),
                ("Base64 email address", base64.b64encode(fictional_email).decode(), "sensitive_data:email"),
                ("Compressed and Base64 email address", base64.b64encode(gzip.compress(fictional_email)).decode(), "sensitive_data:email"),
                ("Labeled identity data in JSON text", json.dumps({"passport_number": "FICTIONAL"}), "sensitive_data:sensitive_field"),
                ("Opaque inline binary attachment", "data:application/octet-stream;base64," + base64.b64encode(bytes(range(256))).decode(), "sensitive_data:opaque_payload"),
            ]
            checks.extend((label, {"name": "mail__send", "arguments": {"to": "team@example.com", "body": body}}, reason) for label, body, reason in extra)
        for label, params, expected in checks:
            result = await gateway.call(params)
            text = result["content"][0]["text"]
            if bool(result.get("isError")) != bool(expected) or (expected and expected not in text):
                raise RuntimeError("Demo did not produce expected security decision")
            print(f"{'BLOCK' if expected else 'ALLOW':5}  {label}" + (f" · {expected}" if expected else ""))
        print(f"\nAll {len(checks)} checks passed. No email sent. Audit: {audit.path}")
        return 0
    finally:
        await gateway.close()


async def feature_demo(audit):
    import base64
    from .redaction import REDACTABLE
    config = demo_config()
    config["servers"]["post"] = dict(config["servers"]["mail"])
    config["policy"]["allow"].append("post__send")
    config["policy"]["recipient_allowlists"]["post__send"] = {"to": ["team@example.com"]}
    config["policy"]["redaction"] = {"enabled": True, "rules": [{"tool": "mail__send", "paths": ["/body"], "categories": sorted(REDACTABLE)}]}
    gateway = Gateway(config, audit)
    try:
        await gateway.start()
        print("MCP-Sentry · redaction and cross-call demo · inert local tools")
        for body, label in (("Contact fictional.person@example.com", "Sensitive text redacted"), (base64.b64encode(b"fictional.person@example.com").decode(), "Encoded sensitive field removed")):
            result = await gateway.call({"name": "mail__send", "arguments": {"to": "team@example.com", "body": body}})
            if result.get("isError") or not result.get("_meta", {}).get("mcpsentry", {}).get("redacted"):
                raise RuntimeError("Redaction demo failed")
            print("REDACT  " + label)
        first = await gateway.call({"name": "post__send", "arguments": {"to": "team@example.com", "body": "alice@"}})
        if first.get("isError"):
            raise RuntimeError("Initial fragment demo failed")
        print("ALLOW   Initial fragment (already sent; cannot be retracted)")
        last = await gateway.call({"name": "post__send", "arguments": {"to": "team@example.com", "body": "example.com"}})
        if "cross_call_sensitive_transfer" not in last["content"][0]["text"]:
            raise RuntimeError("Cross-call demo failed")
        print("BLOCK   Completing fragment detected across tool calls")
        print("All four checks passed. No email or network request sent.")
        return 0
    finally:
        await gateway.close()


async def inspect(args, audit, config, baseline):
    # Reuse the authorized, validated snapshot; never reload commands between
    # the authorization check and execution.
    gateway = Gateway(config, audit, baseline=baseline)
    try:
        tools = await gateway.start()
        if args.command == "baseline":
            path = Path(args.output)
            # Never overwrite an approval implicitly.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(json.dumps(gateway.snapshot(tools), indent=2) + "\n")
            print(f"Baseline saved to {path}. Approval does not establish server safety.")
            return 0
        findings = []
        for tool in tools:
            if poisoned(tool):
                findings.append({"tool": tool["name"], "reason": "tool_poisoning", "severity": "high"})
            if gateway.changed(tool["name"], tools):
                findings.append({"tool": tool["name"], "reason": "tool_changed", "severity": "high"})
        if gateway.baseline is not None:
            current_names = {t["name"] for t in tools}
            for name in gateway.baseline["tools"].keys() - current_names:
                findings.append({"tool": name, "reason": "tool_removed", "severity": "high"})
            if gateway.baseline["configuration"] != gateway.snapshot(tools)["configuration"] and not tools:
                findings.append({"tool": "", "reason": "configuration_changed", "severity": "high"})
        from .catalog import differences
        catalog_changes = differences(gateway.approved, gateway.snapshot(tools))
        print(json.dumps({"catalog_changes": catalog_changes, "status": "findings" if findings else "no_known_patterns_matched", "tool_count": len(tools), "findings": findings, "coverage": "Advertised tool metadata only; does not establish server safety."}, indent=2, ensure_ascii=True))
        return 2 if findings else 0
    finally:
        await gateway.close()


def parser():
    p = argparse.ArgumentParser(prog="mcpsentry", description="MCP-Sentry: a local tools-only MCP stdio security gateway")
    p.add_argument("--version", action="version", version="MCP-Sentry " + __version__)
    commands = p.add_subparsers(dest="command", required=True)
    for name in ("run", "scan", "baseline"):
        sub = commands.add_parser(name)
        sub.add_argument("--config", required=True, help="Explicit JSON config; local commands execute and remote URLs are contacted")
        sub.add_argument("--allow-exec", action="store_true", help="Authorize launching the configured local server commands")
        sub.add_argument("--allow-network", action="store_true", help="Authorize contacting configured HTTP MCP servers")
        sub.add_argument("--state-dir", default=".mcpsentry")
        if name == "baseline":
            sub.add_argument("--output", required=True, help="New approval snapshot file; must not already exist")
        else:
            sub.add_argument("--baseline", help="Explicit approved snapshot; otherwise pin first discovery per session")
        if name == "run":
            sub.add_argument("--mode", choices=("monitor", "enforce"), default="enforce", help="Monitor reports policy violations but forwards calls")
    sub = commands.add_parser("demo", help="Run six inert security checks with two real stdio demo servers")
    sub.add_argument("--state-dir", default=".mcpsentry/demo")
    group = sub.add_mutually_exclusive_group()
    group.add_argument("--dlp", action="store_true", help="Include six additional outbound-data inspection scenarios")
    group.add_argument("--features", action="store_true", help="Demonstrate redaction and split-data leak prevention")
    sub = commands.add_parser("init", help="Write a runnable local demo configuration")
    sub.add_argument("--output", default="mcpsentry.json")
    sub = commands.add_parser("events", help="Read metadata-only JSON audit events")
    sub.add_argument("--state-dir", default=".mcpsentry")
    sub.add_argument("--follow", action="store_true")
    sub.add_argument("--session", help="Filter to one audit session ID")
    sub.add_argument("--decision", choices=("allow", "block", "would_block", "alert", "error", "enforce", "monitor"))
    sub.add_argument("--format", choices=("json", "table"), default="json")
    sub = commands.add_parser("report", help="Summarize audit attempts, blocks, failures and latency")
    sub.add_argument("--state-dir", default=".mcpsentry")
    sub.add_argument("--session")
    sub.add_argument("--format", choices=("json", "text"), default="text")
    sub = commands.add_parser("dashboard", help="Serve a private read-only audit dashboard on loopback")
    sub.add_argument("--state-dir", default=".mcpsentry")
    sub.add_argument("--port", type=int, default=8765)
    sub = commands.add_parser("setup", help="Preview or apply Claude Desktop/Cursor configuration with backup")
    sub.add_argument("--client", choices=("claude-desktop", "cursor"))
    sub.add_argument("--config")
    sub.add_argument("--target", help="Override the client JSON configuration path")
    sub.add_argument("--state-dir", default=".mcpsentry")
    sub.add_argument("--baseline")
    sub.add_argument("--allow-exec", action="store_true")
    sub.add_argument("--allow-network", action="store_true")
    sub.add_argument("--remove-server", action="append", default=[], help="Explicitly remove a direct client entry that would bypass Sentry")
    sub.add_argument("--apply", action="store_true", help="Apply the preview and save a private rollback backup")
    sub.add_argument("--rollback", help="Restore a setup backup, only if the installed file is unchanged")
    sub.add_argument("--interactive", action="store_true", help="Guide setup in a real terminal")
    sub = commands.add_parser("check", help="Inspect inline JSON arguments offline; prints categories only")
    sub.add_argument("--input", default="-", help="JSON argument file, or - for stdin")
    sub.add_argument("--tool", default="outbound__check", help="Tool alias for scoped DLP allow rules")
    sub.add_argument("--config", help="Optional policy configuration; no servers are started or contacted")
    sub = commands.add_parser("policy-test", help="Evaluate synthetic scenarios offline; never runs MCP servers")
    sub.add_argument("--config", required=True)
    sub.add_argument("--input", required=True)
    sub = commands.add_parser("redact", help="Create a private sanitized request file; no MCP tool is executed")
    sub.add_argument("--config", required=True)
    sub.add_argument("--input", required=True, help="Request JSON containing name and arguments")
    sub.add_argument("--output", required=True, help="New private output file; existing files are never overwritten")
    sub = commands.add_parser("sandbox-plan", help="Show fixed isolation arguments without running a server")
    sub.add_argument("--config", required=True)
    sub.add_argument("--state-dir", default=".mcpsentry")
    sub = commands.add_parser("approvals", help="List, review and explicitly grant one exact request")
    sub.add_argument("action", choices=("list", "review", "approve", "deny"))
    sub.add_argument("id", nargs="?")
    sub.add_argument("--state-dir", default=".mcpsentry")
    sub.add_argument("--payload", help="Exact request JSON: name and arguments; never persisted by the gateway")
    sub.add_argument("--confirm", help="Review code printed by the review command")
    sub.add_argument("--interactive", action="store_true", help="Review arguments and require a typed confirmation in a real terminal")
    commands.add_parser("doctor", help="Report optional runtime availability without installing or starting services")
    return p


def main():
    args = parser().parse_args()
    audit = None
    try:
        if args.command == "dashboard":
            from .dashboard import run
            if not 0 <= args.port <= 65535:
                raise ValueError("Port must be between 0 and 65535")
            run(args.state_dir, args.port)
            return
        if args.command == "setup":
            from .setup import plan, apply, rollback
            if args.rollback:
                if args.apply or args.interactive or args.remove_server:
                    raise ValueError("Rollback cannot be combined with setup changes")
                print(json.dumps(rollback(args.rollback), indent=2, ensure_ascii=True))
                return
            if args.interactive:
                if not sys.stdin.isatty():
                    raise ValueError("Interactive setup requires a real terminal")
                args.client = args.client or input("Client (claude-desktop/cursor): ").strip()
                args.config = args.config or input("MCP-Sentry configuration file: ").strip()
                if args.client not in {"claude-desktop", "cursor"}:
                    raise ValueError("Choose claude-desktop or cursor")
                config = load(args.config)
                if any("url" not in spec for spec in config["servers"].values()) and not args.allow_exec:
                    args.allow_exec = input("Reviewed local server commands? Authorize future launches (yes/no): ").strip() == "yes"
                if any("url" in spec for spec in config["servers"].values()) and not args.allow_network:
                    args.allow_network = input("Reviewed remote server URLs? Authorize future connections (yes/no): ").strip() == "yes"
            if not args.client or not args.config:
                raise ValueError("Pass --client and --config, or use --interactive")
            prepared = plan(args.client, args.config, args.state_dir, args.target, args.allow_exec, args.allow_network, args.baseline, args.remove_server)
            print(json.dumps(prepared[0], indent=2, ensure_ascii=True))
            if args.interactive and not args.apply:
                args.apply = input("Apply this plan and save a private backup? Type apply: ").strip() == "apply"
            if args.apply:
                print(json.dumps(apply(prepared), indent=2, ensure_ascii=True))
            return
        if args.command == "policy-test":
            from .simulation import simulate
            config = load(args.config)
            with open(args.input, "rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError("Scenario exceeds size limit")
            scenario = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON")))
            report = simulate(config["policy"], scenario)
            print(json.dumps(report, indent=2, ensure_ascii=True))
            raise SystemExit(0 if report["passed"] else 2)
        if args.command == "redact":
            config = load(args.config)
            if not config["policy"].get("redaction", {}).get("enabled", False):
                raise ValueError("Enable explicit redaction rules in the configuration first")
            with open(args.input, "rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError("Request exceeds inspection size limit")
            request = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON")))
            if not isinstance(request, dict) or set(request) != {"name", "arguments"} or not isinstance(request["name"], str) or not isinstance(request["arguments"], dict):
                raise ValueError("Request must contain a tool name and arguments object")
            rewritten, reasons, count = Guard(config["policy"]).prepare_call(request["name"], request["arguments"])
            if reasons:
                print(json.dumps({"status": "blocked", "reasons": reasons, "output_written": False}))
                raise SystemExit(2)
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(json.dumps({"name": request["name"], "arguments": rewritten}, ensure_ascii=True, indent=2) + "\n")
            print(json.dumps({"status": "written", "fields_changed": count, "output_written": True, "coverage": "Fresh-session policy/DLP check; no live source history or upstream metadata."}))
            return
        if args.command == "doctor":
            import importlib.util
            import shutil
            import subprocess
            docker = shutil.which("docker")
            daemon = False
            if docker:
                try:
                    daemon = subprocess.run([docker, "--context", "default", "version", "--format", "{{.Server.Version}}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3).returncode == 0
                except (OSError, subprocess.TimeoutExpired):
                    pass
            pdf_backend = "pypdf" if importlib.util.find_spec("pypdf") else "pdfminer" if importlib.util.find_spec("pdfminer") else None
            print(json.dumps({"version": __version__, "docker_cli": bool(docker), "docker_daemon": daemon, "pdf_parser": pdf_backend is not None, "pdf_backend": pdf_backend, "official_mcp_sdk": importlib.util.find_spec("mcp") is not None, "claude_cli": client_executable("claude") is not None, "cursor_cli": client_executable("cursor") is not None, "ollama_cli": shutil.which("ollama") is not None}, indent=2))
            return
        if args.command == "sandbox-plan":
            config = load(args.config)
            plans = {}
            for name, spec in config["servers"].items():
                if "sandbox" in spec:
                    protect_state(spec["sandbox"], args.state_dir)
                    plans[name] = sandbox_command(spec, "mcpsentry-preview")
            print(json.dumps(plans, indent=2))
            return
        if args.command == "approvals":
            store = Approvals(args.state_dir)
            try:
                if args.action == "list":
                    print(json.dumps(store.listing(), indent=2))
                elif not args.id:
                    raise ValueError("Approval ID required")
                elif args.action == "deny":
                    store.deny(args.id)
                    print("Approval denied")
                else:
                    if not args.payload:
                        raise ValueError("An exact request payload file is required")
                    with open(args.payload, "rb") as stream:
                        raw = stream.read(MAX_BYTES + 1)
                    if len(raw) > MAX_BYTES:
                        raise ValueError("Approval request exceeds size limit")
                    request = json.loads(raw)
                    row, code = store.verified(args.id, request)
                    if args.action == "review":
                        # Explicit local review intentionally shows arguments;
                        # they never go into the audit or approval database.
                        print(json.dumps({"request": request, "reasons": json.loads(row["reasons"]), "expires": row["expires"], "confirmation": code}, indent=2, ensure_ascii=True))
                    elif args.interactive:
                        if not sys.stdin.isatty():
                            raise ValueError("Interactive approval requires a real terminal")
                        print(json.dumps({"request": request, "reasons": json.loads(row["reasons"]), "expires": row["expires"]}, indent=2, ensure_ascii=True))
                        if input("Approve this exact transfer once? Type approve " + code + ": ").strip() != "approve " + code:
                            raise ValueError("Approval not granted")
                        store.approve(args.id, request, code)
                        print("Approved once; retry the same request before expiry")
                    elif not args.confirm:
                        raise ValueError("Review the exact request first, then pass --confirm with its review code")
                    else:
                        store.approve(args.id, request, args.confirm)
                        print("Approved once for this exact request and session; expires automatically")
            finally:
                store.close()
            return
        if args.command == "check":
            if args.input == "-":
                raw = sys.stdin.buffer.read(MAX_BYTES + 1)
            else:
                with open(args.input, "rb") as stream:
                    raw = stream.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError("Payload exceeds inspection size limit")
            payload = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON")))
            if not isinstance(payload, dict):
                raise ValueError("Payload must be a JSON argument object")
            policy = load(args.config)["policy"] if args.config else {}
            if not policy.get("dlp", {}).get("enabled", True):
                raise ValueError("DLP is disabled by this configuration; payload was not inspected")
            result = OutboundInspector(policy.get("dlp", {}), policy.get("block_secrets", True)).inspect(args.tool, payload)
            blocked = bool(result.categories) or result.limit_exceeded or result.semantic_error
            print(json.dumps({"decision": "block" if blocked else "no_known_pattern_matched", "categories": result.categories, "limit_exceeded": result.limit_exceeded, "semantic_error": result.semantic_error, "coverage": "Inline arguments only; no source-session tracking or tool allow/deny evaluation."}))
            raise SystemExit(2 if blocked else 0)
        if args.command == "init":
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(json.dumps(demo_config(), indent=2) + "\n")
            print(f"Demo configuration saved: {args.output}")
            return
        # Validation happens before opening audit or starting any server.
        if args.command in {"run", "scan", "baseline"}:
            if not args.allow_exec and not args.allow_network:
                raise ValueError("Authorize local commands with --allow-exec and/or HTTP connections with --allow-network after reviewing the configuration.")
            config = load(args.config)
            if any("url" not in spec for spec in config["servers"].values()) and not args.allow_exec:
                raise ValueError("Pass --allow-exec after reviewing server commands. They run with your OS permissions; this gateway is not a sandbox.")
            if any("url" in spec for spec in config["servers"].values()) and not args.allow_network:
                raise ValueError("Pass --allow-network after reviewing remote server URLs.")
            baseline = read_baseline(getattr(args, "baseline", None))
        audit = Audit(args.state_dir)
        if args.command == "demo":
            code = asyncio.run(feature_demo(audit) if args.features else demo(audit, args.dlp))
        elif args.command == "run":
            print(f"MCP-Sentry: {args.mode} mode; audit at {audit.path}", file=sys.stderr)
            asyncio.run(serve(Gateway(config, audit, args.mode, baseline)))
            code = 0
        elif args.command in {"scan", "baseline"}:
            code = asyncio.run(inspect(args, audit, config, baseline))
        elif args.command == "report":
            report = audit.report(args.session)
            print(json.dumps(report, indent=2, ensure_ascii=True) if args.format == "json" else report_text(report))
            code = 0
        else:
            last = 0
            while True:
                events = audit.events(last, args.session, args.decision)
                for event in events:
                    print(display(event) if args.format == "json" else activity_line(event), flush=True)
                    last = event["id"]
                if not args.follow:
                    if len(events) == 1000:
                        continue
                    break
                time.sleep(0.5)
            code = 0
    except KeyboardInterrupt:
        code = 130
    except Exception as exc:
        # Only controlled configuration messages are exposed. Backend failures
        # may contain credentials; do not print their exception representation.
        detail = str(exc) if isinstance(exc, (ValueError, FileExistsError, FileNotFoundError)) else "Operation failed; verify paths, permissions and backend configuration."
        print("MCP-Sentry: " + detail, file=sys.stderr)
        code = 3
    finally:
        if audit is not None:
            audit.close()
    raise SystemExit(code)
