import asyncio
import base64
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, AsyncMock
import zipfile
from concurrent.futures import ThreadPoolExecutor

from mcpsentry.approvals import Approvals
from mcpsentry.audit import Audit
from mcpsentry.cli import demo_config
from mcpsentry.config import load
from mcpsentry.dlp import OutboundInspector
from mcpsentry.documents import extract, kind
from mcpsentry.gateway import Gateway
from mcpsentry.sandbox import command, protect_state, validate
from mcpsentry.transport import Backend


def office_fixture(text, family="word", extra=None):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        name = {"word": "word/document.xml", "xl": "xl/workbook.xml", "ppt": "ppt/presentation.xml"}[family]
        archive.writestr(name, '<root><p><t>' + text + '</t></p></root>')
        for name, content in (extra or {}).items():
            archive.writestr(name, content)
    return output.getvalue()


class SandboxTests(unittest.TestCase):
    def test_fixed_profile_and_secret_free_plan(self):
        spec = {"command": "python3", "args": ["/app/server.py"], "sandbox": {"image": "fixture:local"}, "env": {"SECRET": "not-in-argv"}}
        argv = command(spec, "mcpsentry-test")
        for flag in ("--network=none", "--read-only", "--cap-drop=ALL", "--user=65534:65534", "--pull=never"):
            self.assertIn(flag, argv)
        self.assertNotIn("not-in-argv", " ".join(argv))
        self.assertNotIn("--privileged", argv)
        self.assertIn("<private-env-descriptor>", argv)

    def test_mounts_cannot_expose_approval_state(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {"image": "fixture:local", "mounts": [{"source": directory, "target": "/workspace"}]}
            with self.assertRaises(ValueError):
                protect_state(config, Path(directory) / "private-state")

    def test_unsafe_profile_options_are_rejected(self):
        for profile in ({"image": "fixture", "network": "host"}, {"image": "--privileged"}, {"image": "fixture", "memory_mb": 1}):
            with self.assertRaises(ValueError):
                validate(profile, ".")

    def test_require_sandbox_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            config = demo_config()
            config["policy"]["require_sandbox"] = True
            path.write_text(json.dumps(config))
            with self.assertRaises(ValueError):
                load(path)


class ApprovalTests(unittest.TestCase):
    def test_atomic_consumption_across_connections(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Approvals(directory)
            request = {"name": "tool", "arguments": {"body": "fictional.person@example.com"}}
            params = ("session", "tool", "config", "definition", ["sensitive_data:email"], request["arguments"], 120)
            _, identifier = store.claim_or_request(*params)
            _, code = store.verified(identifier, request)
            store.approve(identifier, request, code)
            store.close()

            def consume(_):
                connection = Approvals(directory)
                try:
                    return connection.claim_or_request(*params)[0]
                finally:
                    connection.close()

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(consume, range(2)))
            self.assertEqual(results.count("consumed"), 1)

    def test_exact_request_single_use_and_no_raw_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Approvals(directory)
            request = {"name": "mail__send", "arguments": {"body": "fictional.person@example.com", "to": "team@example.com"}}
            params = ("session", request["name"], "config-hash", "tool-hash", ["sensitive_data:email"], request["arguments"], 120)
            try:
                status, identifier = store.claim_or_request(*params)
                self.assertEqual(status, "pending")
                _, code = store.verified(identifier, request)
                changed = {**request, "arguments": {**request["arguments"], "to": "outside@example.com"}}
                with self.assertRaises(ValueError):
                    store.approve(identifier, changed, code)
                store.approve(identifier, request, code)
                self.assertEqual(store.claim_or_request(*params)[0], "consumed")
                self.assertEqual(store.claim_or_request(*params)[0], "pending")
                for file in Path(directory).glob("*.sqlite3"):
                    self.assertNotIn(b"fictional.person@example.com", file.read_bytes())
            finally:
                store.close()


    def test_session_tool_config_and_expiry_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Approvals(directory)
            try:
                args = {"body": "fictional.person@example.com"}
                params = ("one", "tool", "config", "schema", ["sensitive_data:email"], args, 120)
                _, identifier = store.claim_or_request(*params)
                request = {"name": "tool", "arguments": args}
                _, code = store.verified(identifier, request)
                store.approve(identifier, request, code)
                for position in (0, 1, 2, 3):
                    changed = list(params)
                    changed[position] = "changed"
                    self.assertEqual(store.claim_or_request(*changed)[0], "pending")
                store.db.execute("UPDATE grants SET expires=0 WHERE id=?", (identifier,))
                store.db.commit()
                self.assertEqual(store.claim_or_request(*params)[0], "pending")
            finally:
                store.close()


class SandboxRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_no_host_fallback_or_server_env_injection(self):
        spec = {"command": "untrusted-program", "args": [], "cwd": str(Path.cwd()), "sandbox": {"image": "fixture:local"}, "env": {"PATH": "/untrusted/bin", "LD_PRELOAD": "untrusted-library"}}
        backend = Backend("fixture", spec, 1)
        with patch("mcpsentry.transport.asyncio.create_subprocess_exec", new=AsyncMock(side_effect=FileNotFoundError)) as launch:
            with self.assertRaises(FileNotFoundError):
                await backend.start()
            await backend.close()
        self.assertTrue(all(call.args[0] == "docker" for call in launch.call_args_list))
        self.assertNotEqual(launch.call_args_list[0].kwargs["env"].get("PATH"), "/untrusted/bin")
        self.assertNotIn("LD_PRELOAD", launch.call_args_list[0].kwargs["env"])


class ApprovalGatewayTests(unittest.IsolatedAsyncioTestCase):
    async def test_approval_cli_and_opaque_payloads_cannot_be_granted(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory)
            config = demo_config()
            config["policy"]["approvals"] = {"enabled": True}
            gateway = Gateway(config, audit)
            try:
                await gateway.start()
                opaque = await gateway.call({"name": "mail__send", "arguments": {"to": "team@example.com", "body": "file:///fictional/private.pdf"}})
                self.assertIn("opaque_payload", opaque["content"][0]["text"])
                self.assertEqual(gateway.approvals.listing(), [])
                request = {"name": "mail__send", "arguments": {"to": "team@example.com", "body": "fictional.person@example.com"}}
                await gateway.call(request)
                identifier = gateway.approvals.listing()[0]["id"]
                path = Path(directory) / "operator-request.json"
                path.write_text(json.dumps(request))
                prefix = [sys.executable, "-m", "mcpsentry", "approvals"]
                flags = [identifier, "--state-dir", directory, "--payload", str(path)]
                reviewed = await asyncio.to_thread(subprocess.run, prefix + ["review"] + flags, text=True, capture_output=True, timeout=5)
                self.assertEqual(reviewed.returncode, 0, reviewed.stderr)
                review = json.loads(reviewed.stdout)
                self.assertEqual(review["request"], request)
                approved = await asyncio.to_thread(subprocess.run, prefix + ["approve"] + flags + ["--confirm", review["confirmation"]], text=True, capture_output=True, timeout=5)
                self.assertEqual(approved.returncode, 0, approved.stderr)
                result = await gateway.call(request)
                self.assertFalse(result.get("isError", False))
            finally:
                await gateway.close()
                audit.close()

    async def test_mandatory_tool_approval_even_for_clean_content(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory)
            config = demo_config()
            config["policy"]["approvals"] = {"enabled": True, "tools": ["mail__send"]}
            gateway = Gateway(config, audit)
            try:
                await gateway.start()
                response = await gateway.call({"name": "mail__send", "arguments": {"to": "team@example.com", "body": "Public summary."}})
                self.assertIn("approval_pending", response["content"][0]["text"])
            finally:
                await gateway.close()
                audit.close()

    async def test_retry_requires_review_and_one_exact_grant(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory)
            config = demo_config()
            config["policy"]["approvals"] = {"enabled": True}
            gateway = Gateway(config, audit)
            try:
                await gateway.start()
                request = {"name": "mail__send", "arguments": {"to": "team@example.com", "body": "fictional.person@example.com"}}
                response = await gateway.call(request)
                self.assertIn("approval_pending", response["content"][0]["text"])
                identifier = gateway.approvals.listing()[0]["id"]
                _, code = gateway.approvals.verified(identifier, request)
                gateway.approvals.approve(identifier, request, code)
                response = await gateway.call(request)
                self.assertFalse(response.get("isError", False))
                response = await gateway.call(request)
                self.assertIn("approval_pending", response["content"][0]["text"])
            finally:
                await gateway.close()
                audit.close()

    async def test_one_approvable_reason_cannot_hide_another_violation(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory)
            config = demo_config()
            config["policy"]["approvals"] = {"enabled": True, "reasons": ["recipient_not_allowed"]}
            gateway = Gateway(config, audit)
            try:
                await gateway.start()
                request = {"name": "mail__send", "arguments": {"to": "outside@example.com", "body": "SENTRY_FAKE_SECRET_CONTROL_12345678"}}
                response = await gateway.call(request)
                self.assertTrue(response["isError"])
                self.assertEqual(gateway.approvals.listing(), [])
            finally:
                await gateway.close()
                audit.close()


class DocumentTests(unittest.TestCase):
    def test_office_families_and_split_runs(self):
        for family in ("word", "xl", "ppt"):
            raw = office_fixture("fictional.</t><t>person@example.com", family)
            self.assertEqual(kind(raw), "office")
            result = extract(raw, "office")
            self.assertTrue(result["complete"], result["issue"])
            self.assertIn("fictional.person@example.com", "".join(result["texts"]))
            inspection = OutboundInspector({}).inspect("out__send", {"body": base64.b64encode(raw).decode()})
            self.assertIn("email", inspection.categories)

    def test_public_office_text_can_pass(self):
        raw = office_fixture("Public release notes.")
        inspection = OutboundInspector({}).inspect("out__send", {"body": base64.b64encode(raw).decode()})
        self.assertEqual(inspection.categories, ())
        self.assertFalse(inspection.limit_exceeded)

    def test_entities_and_embedded_images_are_not_silently_clean(self):
        raw = office_fixture("Public", extra={"word/media/image.png": b"fake image"})
        self.assertFalse(extract(raw, "office")["complete"])
        raw = office_fixture("Public", extra={"word/evil.xml": b'<!DOCTYPE a [<!ENTITY x "secret">]><a>&x;</a>'})
        self.assertFalse(extract(raw, "office")["complete"])

    def test_missing_pdf_parser_and_malformed_pdf_fail_closed(self):
        result = extract(b"%PDF-1.7\nnot a valid document", "pdf")
        self.assertFalse(result["complete"])
        self.assertNotIn("not a valid document", result["issue"])


class SemanticTests(unittest.TestCase):
    def test_contextual_prose_categories(self):
        scanner = OutboundInspector({})
        for text, category in (("Confidential: unreleased acquisition strategy.", "confidential_text"), ("Alice was diagnosed with a serious condition.", "health_information"), ("Home address: a fictional street.", "personal_information")):
            self.assertIn(category, scanner.inspect("out__send", {"body": text}).categories)

    def test_classifier_can_add_but_cannot_remove_deterministic_findings(self):
        command = [sys.executable, "-c", 'import sys,json;json.load(sys.stdin);print(json.dumps({"categories":[]}))']
        result = OutboundInspector({"semantic": {"mode": "command", "command": command}}).inspect("out__send", {"body": "fictional.person@example.com"})
        self.assertIn("email", result.categories)
        self.assertFalse(result.semantic_error)

    def test_invalid_classifier_output_fails_closed(self):
        command = [sys.executable, "-c", 'print("not JSON")']
        result = OutboundInspector({"semantic": {"mode": "command", "command": command}}).inspect("out__send", {"body": "Public summary."})
        self.assertTrue(result.semantic_error)

    def test_classifier_timeout_and_excess_output_fail_closed(self):
        for script in ('import time;time.sleep(2)', 'print("x"*20000)'):
            command = [sys.executable, "-c", script]
            result = OutboundInspector({"semantic": {"mode": "command", "command": command, "timeout_seconds": 0.15}}).inspect("out__send", {"body": "Public summary."})
            self.assertTrue(result.semantic_error)
