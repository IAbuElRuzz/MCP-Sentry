import base64
import gzip
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import quote
import zipfile
import zlib

from mcpsentry.audit import Audit
from mcpsentry.cli import demo_config
from mcpsentry.config import load
from mcpsentry.dlp import MAX_BYTES, OutboundInspector, iban_checksum, luhn
from mcpsentry.gateway import Gateway
from mcpsentry.security import Guard

SECRET = "SENTRY_FAKE_SECRET_OUTBOUND_12345678"
EMAIL = "fictional.person@example.com"
CARD = "4242424242424242"  # Published Stripe test card; never a real account.


def archive(text, comment=b""):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as stream:
        stream.writestr("fixture.txt", text)
        stream.comment = comment
    return output.getvalue()


class DLPTests(unittest.TestCase):
    def inspect(self, payload, **kwargs):
        return OutboundInspector({}).inspect("outbound__send", payload, **kwargs)

    def test_credentials_across_providers_and_context(self):
        examples = [SECRET, "sk-" + "a" * 24, "AKIA" + "A" * 16, "ASIA" + "A" * 16, "ghp_" + "a" * 24,
                    "github_pat_" + "a" * 40, "xoxb-" + "a" * 24, "sk_live_" + "a" * 24,
                    "AIza" + "A" * 35, "password=fictional_password", "Bearer fictional_token_123456",
                    "Basic dXNlcjpwYXNzd29yZA==", "postgres://user:fictional_password@db.example.com/data"]
        for text in examples:
            with self.subTest(kind=text.split("_")[0][:8]):
                self.assertIn("credentials", self.inspect({"body": text}).categories)

    def test_private_keys(self):
        for label in ("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "PGP PRIVATE KEY BLOCK"):
            self.assertIn("private_key", self.inspect({"body": f"-----BEGIN {label}-----\nfake\n-----END {label}-----"}).categories)

    def test_jwt_structure(self):
        def part(value):
            return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

        token = part({"alg": "HS256", "typ": "JWT"}) + "." + part({"sub": "fictional-account"}) + ".fictional_signature_123"
        self.assertIn("credentials", self.inspect({"body": token}).categories)

    def test_personal_and_financial_identifiers(self):
        cases = [(EMAIL, "email"), ("+39 333 123 4567", "phone"), (CARD, "payment_card"),
                 ("4242 4242 4242 4242", "payment_card"), ("GB82WEST12345698765432", "iban"),
                 ("GB82 WEST 1234 5698 7654 32", "iban"), ("123-45-6789", "national_id")]
        for value, category in cases:
            with self.subTest(category=category):
                self.assertIn(category, self.inspect({"body": value}).categories)

    def test_checksums_reject_near_misses(self):
        self.assertTrue(luhn(CARD))
        self.assertFalse(luhn("4242424242424241"))
        self.assertFalse(luhn("0000000000000000"))
        self.assertTrue(iban_checksum("GB82 WEST 1234 5698 7654 32"))
        self.assertFalse(iban_checksum("GB83 WEST 1234 5698 7654 32"))
        self.assertNotIn("national_id", self.inspect({"body": "000-12-3456 and 666-12-3456 and 123-00-3456"}).categories)

    def test_sensitive_fields_and_numeric_values(self):
        for field in ("full_name", "date_of_birth", "passport_number", "tax_id", "codice_fiscale", "medical_record", "diagnosis"):
            self.assertIn("sensitive_field", self.inspect({"payload": {field: "fictional value"}}).categories)
        self.assertIn("credentials", self.inspect({"options": {"api_key": "short"}}).categories)
        self.assertIn("payment_card", self.inspect({"value": int(CARD)}).categories)
        self.assertEqual(self.inspect({"password": "", "passport_number": None}).categories, ())
        self.assertIn("phone", self.inspect({"phone_number": 3331234567}).categories)
        self.assertIn("payment_card", self.inspect({"cvv": 123}).categories)
        self.assertIn("credentials", self.inspect({"aws_secret_access_key": "fictional-value"}).categories)

    def test_secret_in_keys(self):
        self.assertIn("credentials", self.inspect({"payload": [{SECRET: "value"}]}).categories)

    def test_unicode_html_and_escape_normalization(self):
        texts = [SECRET[:10] + "\u200b" + SECRET[10:],
                 "".join(chr(ord(c) + 0xFEE0) if 33 <= ord(c) <= 126 else c for c in SECRET),
                 "fictional.person&#64;example.com", "fictional.person\\u0040example.com",
                 "fictional.person\\x40example.com"]
        for text in texts:
            self.assertTrue(self.inspect({"body": text}).categories)
        self.assertIn("credentials", self.inspect({"api\u200b_key": "fictional"}).categories)

    def test_nested_and_encoded_payloads(self):
        encodings = [
            quote(EMAIL, safe=""), quote(quote(EMAIL, safe=""), safe=""),
            base64.b64encode(EMAIL.encode()).decode(), base64.urlsafe_b64encode(EMAIL.encode()).decode().rstrip("="),
            EMAIL.encode().hex(), json.dumps({"data": {"email": EMAIL}}),
            base64.b64encode(gzip.compress(EMAIL.encode())).decode(),
            base64.b64encode(zlib.compress(EMAIL.encode())).decode(),
            base64.b64encode(archive(EMAIL)).decode(),
            "data:text/plain;base64," + base64.b64encode(EMAIL.encode()).decode(),
        ]
        for index, value in enumerate(encodings):
            with self.subTest(encoding=index):
                self.assertIn("email", self.inspect({"body": value}).categories)
        self.assertIn("email", self.inspect({"body": list(EMAIL.encode())}).categories)
        self.assertIn("payment_card", self.inspect({"body": list(map(int, CARD))}).categories)
        for value in (base64.b64encode(b"a@b.co").decode(), b"a@b.co".hex()):
            self.assertIn("email", self.inspect({"body": value}).categories)

    def test_zip_metadata_is_inspected(self):
        value = base64.b64encode(archive("Public fixture", comment=EMAIL.encode())).decode()
        self.assertIn("email", self.inspect({"body": value}).categories)

    def test_explicit_opaque_payloads_and_references_are_blocked(self):
        binary = base64.b64encode(bytes(range(256))).decode()
        for value in ({"content_base64": binary}, {"body": "Attached: data:image/png;base64," + binary},
                      {"body": binary}, {"attachment_path": "/fictional/record.pdf"}, {"body": "file:///fictional/data.csv"},
                      {"bytes": list(range(256))}, {"body": base64.b64encode(b"%PDF-1.7\nfictional").decode()}):
            self.assertIn("opaque_payload", self.inspect(value).categories)

    def test_compression_bombs_and_decoder_depth_fail_closed(self):
        bomb = base64.b64encode(gzip.compress(b"x" * (MAX_BYTES + 1))).decode()
        self.assertTrue(self.inspect({"body": bomb}).limit_exceeded)
        value = EMAIL
        for _ in range(6):
            value = base64.b64encode(value.encode()).decode()
        self.assertTrue(self.inspect({"body": value}).limit_exceeded)
        deep = {}
        for _ in range(40):
            deep = {"nested": deep}
        self.assertTrue(self.inspect(deep).limit_exceeded)

    def test_custom_fields_terms_and_env(self):
        with patch.dict(os.environ, {"MCP_TEST_CONFIDENTIAL": "FICTIONAL INTERNAL PROJECT"}):
            scanner = OutboundInspector({"custom_terms_env": ["MCP_TEST_CONFIDENTIAL"], "custom_terms": ["PRIVATE REFERENCE"], "sensitive_fields": ["internal_notes"]})
        self.assertIn("custom", scanner.inspect("out__send", {"body": "fictional internal project"}).categories)
        self.assertIn("custom", scanner.inspect("out__send", {"body": "private   reference"}).categories)
        self.assertIn("sensitive_field", scanner.inspect("out__send", {"internal_notes": "text"}).categories)
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                OutboundInspector({"custom_terms_env": ["MISSING_TEST_VARIABLE"]})

    def test_exceptions_are_tool_field_and_category_specific(self):
        scanner = OutboundInspector({"allow_rules": [{"tool": "mail__send", "path": "/to", "categories": ["email"]}]})
        self.assertEqual(scanner.inspect("mail__send", {"to": EMAIL}).categories, ())
        self.assertIn("email", scanner.inspect("mail__send", {"body": EMAIL}).categories)
        self.assertIn("email", scanner.inspect("other__send", {"to": EMAIL}).categories)
        self.assertIn("credentials", scanner.inspect("mail__send", {"to": SECRET}).categories)

    def test_recipient_allowlist_does_not_exempt_message_body(self):
        guard = Guard({"default": "allow", "recipient_allowlists": {"mail__send": {"to": [EMAIL]}}})
        self.assertIsNone(guard.inspect_call("mail__send", {"to": EMAIL, "body": "Public summary."}))
        self.assertEqual(guard.inspect_call("mail__send", {"to": EMAIL, "body": EMAIL}), "sensitive_data:email")
        guard = Guard({"default": "allow", "recipient_allowlists": {"mail__send": {"email": [EMAIL]}}})
        self.assertIsNone(guard.inspect_call("mail__send", {"email": [EMAIL], "body": "Public summary."}))

    def test_tracked_data_is_found_after_encoding_and_normalization(self):
        guard = Guard({"default": "allow", "sensitive_sources": ["db__*"]})
        reference = "CONFIDENTIAL CUSTOMER REFERENCE XYZ"
        guard.observe("db__read", {"text": reference})
        for text in (reference.lower(), reference.replace(" ", "  "), base64.b64encode(reference.encode()).decode(), quote(reference)):
            self.assertEqual(guard.inspect_call("out__send", {"body": text}), "sensitive_data_transfer")

    def test_clean_payloads_and_findings_privacy(self):
        for args in ({"body": "Public summary."}, {"count": 10, "options": {"max_tokens": 200}}, {"reference": "public-reference-1234"}):
            result = self.inspect(args)
            self.assertEqual(result.categories, ())
            self.assertFalse(result.limit_exceeded)
        self.assertNotIn(EMAIL, repr(self.inspect({"body": EMAIL})))
        self.assertNotIn(SECRET, repr(self.inspect({"body": SECRET})))

    def test_configuration_typos_do_not_disable_protection(self):
        invalid = [{"block_category": []}, {"enabled": "false"}, {"block_categories": ["unknown"]}, {"custom_terms": [" "]},
                   {"allow_rules": [{"tool": "*", "path": "*", "categories": ["email"]}]},
                   {"allow_rules": [{"tool": "*", "path": "/body", "categories": ["unknown"]}]}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            for dlp in invalid:
                config = demo_config()
                config["policy"]["dlp"] = dlp
                path.write_text(json.dumps(config))
                with self.assertRaises(ValueError):
                    load(path)

    def test_offline_cli_does_not_echo_payload(self):
        result = subprocess.run([sys.executable, "-m", "mcpsentry", "check"], input=json.dumps({"body": EMAIL}), text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)["categories"], ["email"])
        self.assertNotIn(EMAIL, result.stdout + result.stderr)


class DLPGatewayTests(unittest.IsolatedAsyncioTestCase):
    async def test_encoded_pii_is_never_forwarded_or_logged(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory)
            gateway = Gateway(demo_config(), audit)
            await gateway.start()
            backend = gateway.backends["mail"]
            original, dispatches = backend.request, []

            async def spy(method, params=None):
                if method == "tools/call":
                    dispatches.append(params)
                return await original(method, params)

            backend.request = spy
            try:
                encoded = base64.b64encode(gzip.compress(EMAIL.encode())).decode()
                response = await gateway.call({"name": "mail__send", "arguments": {"to": "team@example.com", "body": encoded}})
                self.assertTrue(response["isError"])
                self.assertIn("sensitive_data:email", response["content"][0]["text"])
                self.assertEqual(dispatches, [])
                for value in (EMAIL, encoded):
                    self.assertNotIn(value.encode(), audit.path.read_bytes())
                    self.assertNotIn(value, json.dumps(audit.events()))
                    self.assertNotIn(value, json.dumps(response))
            finally:
                await gateway.close()
                audit.close()

    async def test_monitor_mode_records_violation_but_forwards(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory)
            gateway = Gateway(demo_config(), audit, mode="monitor")
            try:
                await gateway.start()
                response = await gateway.call({"name": "mail__send", "arguments": {"to": "team@example.com", "body": CARD}})
                self.assertFalse(response.get("isError", False))
                self.assertTrue(any(e["decision"] == "would_block" and e["reason"] == "sensitive_data:payment_card" for e in audit.events()))
            finally:
                await gateway.close()
                audit.close()
