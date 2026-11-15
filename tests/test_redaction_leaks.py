import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from mcpsentry.audit import Audit
from mcpsentry.cli import demo_config
from mcpsentry.config import load
from mcpsentry.gateway import Gateway
from mcpsentry.security import Guard

EMAIL = "fictional.person@example.com"
REFERENCE = "customer-private-reference-xyz98765"


def redaction_policy():
    return {"enabled": True, "rules": [{"tool": "mail__*", "paths": ["/body"], "categories": ["email", "payment_card", "credentials", "private_key", "tracked_data"]}]}


class RedactionTests(unittest.TestCase):
    def guard(self):
        return Guard({"default": "allow", "redaction": redaction_policy(), "recipient_allowlists": {"mail__send": {"to": ["team@example.com"]}}})

    def test_preserves_message_and_recipient_without_mutating_input(self):
        args = {"to": "team@example.com", "body": "Contact " + EMAIL + " for the public report."}
        original = copy.deepcopy(args)
        output, reasons, count = self.guard().prepare_call("mail__send", args)
        self.assertEqual(reasons, [])
        self.assertEqual(count, 1)
        self.assertEqual(output["body"], "Contact [REDACTED] for the public report.")
        self.assertEqual(output["to"], original["to"])
        self.assertEqual(args, original)

    def test_encoded_content_and_credentials_remove_whole_string(self):
        for body in (base64.b64encode(EMAIL.encode()).decode(), "password=fictional password with spaces", "SENTRY_FAKE_SECRET_REDACTION_12345678"):
            output, reasons, count = self.guard().prepare_call("mail__send", {"to": "team@example.com", "body": body})
            self.assertEqual(reasons, [])
            self.assertGreater(count, 0)
            self.assertEqual(output["body"], "")

    def test_partial_redaction_is_never_forwarded_when_other_fields_leak(self):
        args = {"to": "team@example.com", "body": EMAIL, "notes": EMAIL}
        output, reasons, count = self.guard().prepare_call("mail__send", args)
        self.assertTrue(reasons)
        self.assertEqual(count, 0)
        self.assertEqual(output, args)

    def test_keys_opaque_and_nonstring_fields_remain_blocked(self):
        for args in ({EMAIL: "value", "body": "Public"}, {"body": "data:image/png;base64," + base64.b64encode(bytes(range(256))).decode()}, {"body": {"email": EMAIL}}):
            _, reasons, count = self.guard().prepare_call("mail__send", args)
            self.assertTrue(reasons)
            self.assertEqual(count, 0)

    def test_hard_policies_cannot_be_bypassed_by_redaction(self):
        guard = self.guard()
        guard.policy["deny"] = ["mail__send"]
        _, reasons, count = guard.prepare_call("mail__send", {"to": "team@example.com", "body": EMAIL})
        self.assertEqual(reasons, ["tool_denied"])
        self.assertEqual(count, 0)
        guard = self.guard()
        _, reasons, count = guard.prepare_call("mail__send", {"to": "outside@example.com", "body": EMAIL})
        self.assertIn("recipient_not_allowed", reasons)
        self.assertEqual(count, 0)

    def test_redaction_is_explicit_and_disabled_by_default(self):
        args = {"body": EMAIL}
        output, reasons, count = Guard({"default": "allow"}).prepare_call("mail__send", args)
        self.assertEqual(output, args)
        self.assertTrue(reasons)
        self.assertEqual(count, 0)

    def test_rewritten_arguments_are_checked_against_constraints(self):
        guard = self.guard()
        guard.policy["argument_constraints"] = {"mail__send": {"/body": {"enum": [EMAIL]}}}
        args = {"to": "team@example.com", "body": EMAIL}
        output, reasons, count = guard.prepare_call("mail__send", args)
        self.assertTrue(reasons)
        self.assertEqual(output, args)
        self.assertEqual(count, 0)

    def test_config_protects_routing_and_declared_recipient_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            for pointer in ("/to", "/payload/url", "/destination"):
                config = demo_config()
                config["policy"]["recipient_allowlists"]["mail__send"]["destination"] = ["team@example.com"]
                config["policy"]["redaction"] = redaction_policy()
                config["policy"]["redaction"]["rules"][0]["paths"] = [pointer]
                path.write_text(json.dumps(config))
                with self.assertRaises(ValueError):
                    load(path)

    def test_offline_redact_cli_writes_private_output_and_no_payload_to_console(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = demo_config()
            config["policy"]["redaction"] = redaction_policy()
            (root / "config.json").write_text(json.dumps(config))
            (root / "request.json").write_text(json.dumps({"name": "mail__send", "arguments": {"to": "team@example.com", "body": EMAIL}}))
            argv = [sys.executable, "-m", "mcpsentry", "redact", "--config", str(root / "config.json"), "--input", str(root / "request.json"), "--output", str(root / "sanitized.json")]
            result = subprocess.run(argv, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(EMAIL, result.stdout + result.stderr)
            self.assertNotIn(EMAIL, (root / "sanitized.json").read_text())
            self.assertEqual((root / "sanitized.json").stat().st_mode & 0o777, 0o600)
            repeated = subprocess.run(argv, capture_output=True, text=True, timeout=5)
            self.assertEqual(repeated.returncode, 3)


class CrossCallTests(unittest.TestCase):
    def guard(self, **options):
        return Guard({"default": "allow", "sensitive_sources": ["db__*"], "cross_call": options})

    def dispatch(self, guard, name, args):
        reason = guard.inspect_call(name, args)
        self.assertIsNone(reason)
        guard.record_dispatch(name, args)

    def test_tracked_value_split_across_calls(self):
        guard = self.guard()
        guard.observe("db__read", {"text": REFERENCE})
        self.dispatch(guard, "mail__send", {"body": REFERENCE[:16]})
        self.assertIn("cross_call_sensitive_transfer", guard.inspect_reasons("mail__send", {"body": REFERENCE[16:]}))

    def test_unrelated_calls_do_not_erase_known_fragment_progress(self):
        guard = self.guard()
        guard.observe("db__read", {"text": REFERENCE})
        self.dispatch(guard, "mail__send", {"body": REFERENCE[:16]})
        self.dispatch(guard, "mail__send", {"body": "Unrelated public update."})
        self.assertIn("cross_call_sensitive_transfer", guard.inspect_reasons("mail__send", {"body": REFERENCE[16:]}))

    def test_custom_term_fragments(self):
        guard = Guard({"default": "allow", "dlp": {"custom_terms": ["PROJECT_ORBIT"]}})
        self.dispatch(guard, "one__send", {"body": "PROJECT_"})
        self.assertIn("cross_call_sensitive_transfer", guard.inspect_reasons("two__send", {"body": "ORBIT"}))

    def test_email_card_and_token_fragments_without_a_source(self):
        for value, split in ((EMAIL, 17), ("4242424242424242", 8), ("sk-abcdefghijklmnopqrstuvwx", 10)):
            guard = self.guard()
            self.dispatch(guard, "mail__send", {"body": value[:split]})
            self.assertIn("cross_call_sensitive_transfer", guard.inspect_reasons("mail__send", {"body": value[split:]}))

    def test_cross_tool_server_and_field_channels(self):
        guard = self.guard()
        self.dispatch(guard, "one__send", {"body": "alice@"})
        self.assertIn("cross_call_sensitive_transfer", guard.inspect_reasons("two__post", {"text": "example.com"}))
        guard = self.guard(scope="server")
        self.dispatch(guard, "one__send", {"body": "alice@"})
        self.assertIsNone(guard.inspect_call("two__post", {"body": "example.com"}))

    def test_individually_encoded_fragments(self):
        for encoder in (lambda x: base64.b64encode(x.encode()).decode(), lambda x: x.encode().hex()):
            guard = self.guard()
            self.dispatch(guard, "mail__send", {"body": encoder("alice@")})
            self.assertIn("cross_call_sensitive_transfer", guard.inspect_reasons("mail__send", {"body": encoder("example.com")}))

    def test_expiry_and_session_reset(self):
        now = [100.0]
        guard = Guard({"default": "allow", "cross_call": {"window_seconds": 10}}, clock=lambda: now[0])
        self.dispatch(guard, "mail__send", {"body": "alice@"})
        now[0] = 111
        self.assertIsNone(guard.inspect_call("mail__send", {"body": "example.com"}))
        self.assertIsNone(self.guard().inspect_call("mail__send", {"body": "example.com"}))

    def test_blocked_attempts_do_not_enter_history(self):
        guard = self.guard()
        self.assertTrue(guard.inspect_reasons("mail__send", {"body": EMAIL}))
        self.assertIsNone(guard.inspect_call("mail__send", {"body": "example.com"}))
        self.assertEqual(guard.window.history, {})

    def test_cross_call_completing_fragment_can_be_redacted(self):
        guard = self.guard()
        guard.policy["redaction"] = redaction_policy()
        self.dispatch(guard, "mail__send", {"body": "alice@"})
        output, reasons, count = guard.prepare_call("mail__send", {"body": "example.com"})
        self.assertEqual(reasons, [])
        self.assertEqual(output["body"], "")
        self.assertEqual(count, 1)

    def test_explicit_disable_and_capacity(self):
        guard = self.guard(enabled=False)
        self.dispatch(guard, "mail__send", {"body": "alice@"})
        self.assertIsNone(guard.inspect_call("mail__send", {"body": "example.com"}))
        guard = self.guard()
        self.assertIn("cross_call_tracking_capacity", guard.inspect_reasons("mail__send", {"body": "x" * 70000}))


class GatewayFeatureTests(unittest.IsolatedAsyncioTestCase):
    async def test_approval_binds_rewritten_arguments_and_history_is_cleared(self):
        with tempfile.TemporaryDirectory() as directory:
            config = demo_config()
            config["policy"]["redaction"] = redaction_policy()
            config["policy"]["approvals"] = {"enabled": True, "tools": ["mail__send"]}
            audit = Audit(directory)
            gateway = Gateway(config, audit)
            try:
                await gateway.start()
                request = {"name": "mail__send", "arguments": {"to": "team@example.com", "body": "Contact " + EMAIL}}
                pending = await gateway.call(request)
                self.assertIn("request_arguments_redacted=true", pending["content"][0]["text"])
                identifier = gateway.approvals.listing()[0]["id"]
                with self.assertRaises(ValueError):
                    gateway.approvals.verified(identifier, request)
                expected = {"name": request["name"], "arguments": {"to": "team@example.com", "body": "Contact [REDACTED]"}}
                _, code = gateway.approvals.verified(identifier, expected)
                gateway.approvals.approve(identifier, expected, code)
                result = await gateway.call(request)
                self.assertFalse(result.get("isError", False))
                self.assertTrue(result["_meta"]["mcpsentry"]["redacted"])
                self.assertTrue(gateway.guard.window.history)
                self.assertNotIn(EMAIL.encode(), audit.path.read_bytes())
            finally:
                await gateway.close()
                audit.close()
            self.assertEqual(gateway.guard.window.history, {})
            self.assertEqual(gateway.guard.values, {})

    async def test_only_redacted_content_is_dispatched_and_audited(self):
        with tempfile.TemporaryDirectory() as directory:
            config = demo_config()
            config["policy"]["redaction"] = redaction_policy()
            audit = Audit(directory)
            gateway = Gateway(config, audit)
            try:
                await gateway.start()
                backend = gateway.backends["mail"]
                original, calls = backend.request, []

                async def spy(method, params=None):
                    if method == "tools/call":
                        calls.append(copy.deepcopy(params))
                    return await original(method, params)

                backend.request = spy
                response = await gateway.call({"name": "mail__send", "arguments": {"to": "team@example.com", "body": "Contact " + EMAIL}})
                self.assertEqual(calls[0]["arguments"]["body"], "Contact [REDACTED]")
                self.assertTrue(response["_meta"]["mcpsentry"]["redacted"])
                self.assertNotIn(EMAIL.encode(), audit.path.read_bytes())
                self.assertEqual(audit.report()["totals"]["redacted_calls"], 1)
            finally:
                await gateway.close()
                audit.close()

    async def test_completing_call_is_blocked_before_forwarding(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory)
            gateway = Gateway(demo_config(), audit)
            try:
                await gateway.start()
                first = await gateway.call({"name": "mail__send", "arguments": {"to": "team@example.com", "body": "alice@"}})
                self.assertFalse(first.get("isError", False))
                second = await gateway.call({"name": "mail__send", "arguments": {"to": "team@example.com", "body": "example.com"}})
                self.assertIn("cross_call_sensitive_transfer", second["content"][0]["text"])
                self.assertNotIn(b"alice@", audit.path.read_bytes())
                self.assertEqual(audit.report()["totals"]["forwarded"], 1)
            finally:
                await gateway.close()
                audit.close()

    async def test_monitor_never_mutates_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            config = demo_config()
            config["policy"]["redaction"] = redaction_policy()
            audit = Audit(directory)
            gateway = Gateway(config, audit, mode="monitor")
            try:
                await gateway.start()
                backend = gateway.backends["mail"]
                original, calls = backend.request, []

                async def spy(method, params=None):
                    if method == "tools/call":
                        calls.append(copy.deepcopy(params))
                    return await original(method, params)

                backend.request = spy
                await gateway.call({"name": "mail__send", "arguments": {"to": "team@example.com", "body": EMAIL}})
                self.assertEqual(calls[0]["arguments"]["body"], EMAIL)
                self.assertEqual(audit.report()["totals"]["redacted_calls"], 0)
            finally:
                await gateway.close()
                audit.close()
