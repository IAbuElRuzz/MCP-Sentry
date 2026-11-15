import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from mcpsentry.audit import Audit
from mcpsentry.cli import demo_config, report_text
from mcpsentry.config import load
from mcpsentry.gateway import Gateway
from mcpsentry.security import Guard, at_pointer, satisfies


class ConstraintTests(unittest.TestCase):
    def test_nested_constraints_and_missing_fields(self):
        guard = Guard({"default": "allow", "argument_constraints": {"db__*": {"/options/limit": {"type": "integer", "minimum": 1, "maximum": 50}, "/operation": {"enum": ["read"]}}}})
        self.assertIsNone(guard.inspect_call("db__query", {"operation": "read", "options": {"limit": 10}}))
        for limit in (True, "10", 0, 51):
            self.assertEqual(guard.inspect_call("db__query", {"operation": "read", "options": {"limit": limit}}), "argument_constraint")
        self.assertEqual(guard.inspect_call("db__query", {"operation": "read"}), "argument_constraint")

    def test_pointer_escapes_array_indices_and_lengths(self):
        self.assertEqual(at_pointer({"a/b": [{"~": "ok"}]}, "/a~1b/0/~0"), "ok")
        self.assertFalse(satisfies(True, {"enum": [1]}))
        self.assertFalse(satisfies([True], {"enum": [[1]]}))
        self.assertFalse(satisfies("12345", {"max_length": 4}))
        self.assertFalse(satisfies(123, {"max_length": 4}))
        self.assertTrue(satisfies("1234", {"max_length": 4}))

    def test_pattern_budget_is_shared_and_expires(self):
        now = [100.0]
        guard = Guard({"default": "allow", "call_limits": {"mail__*": {"max_calls": 2, "window_seconds": 60}}}, clock=lambda: now[0])
        for name in ("mail__send", "mail__reply"):
            self.assertIsNone(guard.inspect_call(name, {}))
            guard.record_dispatch(name)
        self.assertEqual(guard.inspect_call("mail__send", {}), "call_limit_exceeded")
        self.assertIsNone(guard.inspect_call("db__read", {}))
        now[0] = 160.0
        self.assertIsNone(guard.inspect_call("mail__send", {}))

    def test_bad_config_constraints_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            for rule in ({"minimum": 5, "maximum": 1}, {"type": "unknown"}, {"max_length": -1}, {"required": "false"}, {"enum": []}, {"minimum": True}):
                config = demo_config()
                config["policy"]["argument_constraints"] = {"*": {"/value": rule}}
                path.write_text(json.dumps(config))
                with self.assertRaises(ValueError):
                    load(path)


class AdvancedGatewayTests(unittest.IsolatedAsyncioTestCase):
    async def test_rate_limit_blocks_before_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory)
            config = demo_config()
            config["policy"]["call_limits"] = {"mail__*": {"max_calls": 1, "window_seconds": 60}}
            config["policy"]["argument_constraints"] = {"mail__send": {"/body": {"type": "string", "max_length": 20}}}
            gateway = Gateway(config, audit)
            try:
                await gateway.start()
                bad = await gateway.call({"name": "mail__send", "arguments": {"to": "team@example.com", "body": "x" * 21}})
                self.assertIn("argument_constraint", bad["content"][0]["text"])
                good = await gateway.call({"name": "mail__send", "arguments": {"to": "team@example.com", "body": "Hello"}})
                self.assertFalse(good.get("isError", False))
                limited = await gateway.call({"name": "mail__send", "arguments": {"to": "team@example.com", "body": "Hello again"}})
                self.assertIn("call_limit_exceeded", limited["content"][0]["text"])
                report = audit.report()
                self.assertEqual(report["totals"]["attempted"], 3)
                self.assertEqual(report["totals"]["forwarded"], 1)
                self.assertEqual(report["totals"]["blocked_before_dispatch"], 2)
            finally:
                await gateway.close()
                audit.close()


class ReportTests(unittest.TestCase):
    def test_session_filters_and_no_double_counting(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory)
            try:
                first = audit.session
                audit.record("call_started", "mail__send", "allow", "policy_passed")
                audit.record("call_finished", "mail__send", "allow", "completed", 20)
                audit.record("call_blocked", "mail__send", "block", "recipient_not_allowed")
                audit.session = "second-session"
                audit.record("call_started", "db__read", "would_block", "argument_constraint")
                audit.record("call_finished", "db__read", "block", "response_poisoning", 40)
                report = audit.report(first)
                self.assertEqual(report["totals"]["attempted"], 2)
                self.assertEqual(report["totals"]["forwarded"], 1)
                self.assertEqual(report["totals"]["average_duration_ms"], 20)
                self.assertEqual(len(audit.events(session=first, decision="block")), 1)
                whole = audit.report()
                self.assertEqual(whole["totals"]["attempted"], 3)
                self.assertEqual(whole["totals"]["responses_blocked"], 1)
                self.assertEqual(whole["totals"]["monitor_violations"], 1)
                self.assertIn("Attempts: 3", report_text(whole))
            finally:
                audit.close()

    def test_report_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory)
            audit.record("call_blocked", "fixture__tool", "block", "tool_denied")
            audit.close()
            result = subprocess.run([sys.executable, "-m", "mcpsentry", "report", "--state-dir", directory, "--format", "json"], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["totals"]["blocked_before_dispatch"], 1)
