"""Opt-in real-client check with inert fixtures and a private temporary config."""

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from mcpsentry.cli import demo_config
from mcpsentry.audit import Audit
from mcpsentry.runtimes import client_executable


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", choices=("claude", "cursor"), required=True)
    args = parser.parse_args()
    executable = client_executable(args.client)
    if executable is None:
        print(json.dumps({"status": "unavailable", "reason": "client_not_installed", "client": args.client}))
        return 3
    if args.client == "cursor":
        print(json.dumps({"status": "manual_check_required", "reason": "Cursor GUI MCP session cannot be verified by this script"}))
        return 3
    with tempfile.TemporaryDirectory(prefix="mcpsentry-client-") as directory:
        directory = Path(directory)
        config = directory / "gateway.json"
        config.write_text(json.dumps(demo_config()))
        mcp = directory / "mcp.json"
        mcp.write_text(json.dumps({"mcpServers": {"sentry": {"command": sys.executable, "args": [str(ROOT / "scripts/run_gateway.py"), "run", "--config", str(config), "--allow-exec", "--state-dir", str(directory / "state")]}}}))
        prompt = "Use the sentry database read_customer tool once. Then call sentry mail send to team@example.com with body 4242424242424242 (a published fake test card). Report whether MCP-Sentry blocked it. Do not use any other tools."
        argv = [executable, "-p", prompt, "--bare", "--setting-sources", "", "--strict-mcp-config", "--mcp-config", str(mcp), "--tools", "", "--allowedTools", "mcp__sentry__db__read_customer,mcp__sentry__mail__send", "--max-turns", "4", "--output-format", "json", "--no-session-persistence"]
        process = subprocess.Popen(argv, cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            output, errors = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            print(json.dumps({"status": "unavailable", "reason": "client_timeout_or_network_auth_unavailable"}))
            return 3
        audit_path = directory / "state/audit.sqlite3"
        events = []
        if audit_path.exists():
            audit = Audit(directory / "state")
            events = audit.events()
            audit.close()
        allowed = any(e["tool"] == "db__read_customer" and e["event"] == "call_finished" and e["decision"] == "allow" for e in events)
        blocked = any(e["tool"] == "mail__send" and e["event"] == "call_blocked" and e["reason"] == "sensitive_data:payment_card" for e in events)
        # The client narrative is not evidence. Only actual gateway audit events
        # establish that the MCP calls and policy enforcement happened.
        passed = allowed and blocked
        diagnostic = (output + errors).lower()
        reason = "verified_gateway_events" if passed else "permission_or_filesystem_unavailable" if any(x in diagnostic for x in (b"eperm", b"eacces", b"operation not permitted")) else "auth_or_network_unavailable" if any(x in diagnostic for x in (b"login", b"api key", b"authentication", b"network", b"connect")) else "expected_gateway_events_missing"
        print(json.dumps({"status": "passed" if passed else "unavailable", "reason": reason, "exit_code": process.returncode, "database_read_verified": allowed, "card_block_verified": blocked}))
        return 0 if passed else 3


if __name__ == "__main__":
    raise SystemExit(main())
