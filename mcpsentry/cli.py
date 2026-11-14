"""Command-line entry points. Human output never shares MCP stdout."""

import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
import time

from .audit import Audit, display
from .config import load
from .gateway import Gateway, read_baseline, serve
from .security import poisoned


def demo_config():
    script = str(Path(__file__).with_name("demo_server.py"))
    return {
        "servers": {name: {"command": sys.executable, "args": [script, kind], "cwd": str(Path.cwd())} for name, kind in (("db", "database"), ("mail", "mail"))},
        "policy": {"default": "deny", "allow": ["db__read_customer", "mail__send"], "deny": ["*__delete*"], "sensitive_sources": ["db__*"], "recipient_allowlists": {"mail__send": {"to": ["team@example.com"]}}},
        "timeout_seconds": 5,
    }


async def demo(audit):
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
        for label, params, expected in checks:
            result = await gateway.call(params)
            text = result["content"][0]["text"]
            if bool(result.get("isError")) != bool(expected) or (expected and expected not in text):
                raise RuntimeError("Demo did not produce expected security decision")
            print(f"{'BLOCK' if expected else 'ALLOW':5}  {label}" + (f" · {expected}" if expected else ""))
        print(f"\nAll six checks passed. No email sent. Audit: {audit.path}")
        return 0
    finally:
        await gateway.close()


async def inspect(args, audit):
    config = load(args.config)
    gateway = Gateway(config, audit, baseline=read_baseline(getattr(args, "baseline", None)))
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
        print(json.dumps({"status": "findings" if findings else "no_known_patterns_matched", "tool_count": len(tools), "findings": findings, "coverage": "Advertised tool metadata only; does not establish server safety."}, indent=2, ensure_ascii=True))
        return 2 if findings else 0
    finally:
        await gateway.close()


def parser():
    p = argparse.ArgumentParser(prog="mcpsentry", description="MCP-Sentry: a local tools-only MCP stdio security gateway")
    p.add_argument("--version", action="version", version="MCP-Sentry 0.1.0")
    commands = p.add_subparsers(dest="command", required=True)
    for name in ("run", "scan", "baseline"):
        sub = commands.add_parser(name)
        sub.add_argument("--config", required=True, help="Explicit JSON config; server commands execute locally")
        sub.add_argument("--allow-exec", action="store_true", help="Authorize launching the configured local server commands")
        sub.add_argument("--state-dir", default=".mcpsentry")
        if name == "baseline":
            sub.add_argument("--output", required=True, help="New approval snapshot file; must not already exist")
        else:
            sub.add_argument("--baseline", help="Explicit approved snapshot; otherwise pin first discovery per session")
        if name == "run":
            sub.add_argument("--mode", choices=("monitor", "enforce"), default="enforce", help="Monitor reports policy violations but forwards calls")
    sub = commands.add_parser("demo", help="Run six inert security checks with two real stdio demo servers")
    sub.add_argument("--state-dir", default=".mcpsentry/demo")
    sub = commands.add_parser("init", help="Write a runnable local demo configuration")
    sub.add_argument("--output", default="mcpsentry.json")
    sub = commands.add_parser("events", help="Read metadata-only JSON audit events")
    sub.add_argument("--state-dir", default=".mcpsentry")
    sub.add_argument("--follow", action="store_true")
    return p


def main():
    args = parser().parse_args()
    audit = None
    try:
        if args.command == "init":
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(json.dumps(demo_config(), indent=2) + "\n")
            print(f"Demo configuration saved: {args.output}")
            return
        if args.command in {"run", "scan", "baseline"} and not args.allow_exec:
            raise ValueError("Pass --allow-exec after reviewing server commands. They run with your OS permissions; this gateway is not a sandbox.")
        # Validation happens before opening audit or starting any server.
        if args.command in {"run", "scan", "baseline"}:
            config = load(args.config)
            baseline = read_baseline(getattr(args, "baseline", None))
        audit = Audit(args.state_dir)
        if args.command == "demo":
            code = asyncio.run(demo(audit))
        elif args.command == "run":
            print(f"MCP-Sentry: {args.mode} mode; audit at {audit.path}", file=sys.stderr)
            asyncio.run(serve(Gateway(config, audit, args.mode, baseline)))
            code = 0
        elif args.command in {"scan", "baseline"}:
            code = asyncio.run(inspect(args, audit))
        else:
            last = 0
            while True:
                events = audit.events(last)
                for event in events:
                    print(display(event), flush=True)
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
