"""Real integrations run only when their dependencies/runtimes are present."""

import asyncio
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

from mcpsentry.audit import Audit
from mcpsentry.cli import demo_config
from mcpsentry.gateway import Gateway
from mcpsentry.sandbox import command

ROOT = Path(__file__).resolve().parents[1]


def pdf_fixture(text, catalog_extra=b""):
    escaped = text.encode("ascii").replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")
    content = b"BT /F1 12 Tf 72 720 Td (" + escaped + b") Tj ET"
    objects = [b"<< /Type /Catalog /Pages 2 0 R " + catalog_extra + b" >>",
               b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
               b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
               b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
               b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream"]
    data, offsets = b"%PDF-1.4\n", [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(data))
        data += str(index).encode() + b" 0 obj\n" + obj + b"\nendobj\n"
    xref = len(data)
    data += b"xref\n0 6\n0000000000 65535 f \n"
    data += b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets[1:])
    return data + b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n" + str(xref).encode() + b"\n%%EOF\n"


@unittest.skipUnless(importlib.util.find_spec("pdfminer"), "Optional pdfminer.six backend is not installed")
class PDFMinerTests(unittest.TestCase):
    def test_real_text_pdf_and_outbound_dlp(self):
        import base64
        from mcpsentry.documents import extract
        from mcpsentry.dlp import OutboundInspector
        raw = pdf_fixture("fictional.person@example.com")
        result = extract(raw, "pdf")
        if result["issue"] == "document_memory_watchdog_unavailable":
            self.skipTest("OS denies the memory watchdog; extraction fails closed")
        self.assertTrue(result["complete"], result["issue"])
        self.assertIn("fictional.person@example.com", "".join(result["texts"]))
        decision = OutboundInspector({}).inspect("out__send", {"body": base64.b64encode(raw).decode()})
        self.assertIn("email", decision.categories)

    def test_public_pdf_can_pass_but_active_pdf_is_incomplete(self):
        from mcpsentry.documents import extract
        result = extract(pdf_fixture("Public release notes."), "pdf")
        if result["issue"] == "document_memory_watchdog_unavailable":
            self.skipTest("OS denies the memory watchdog; extraction fails closed")
        self.assertTrue(result["complete"], result["issue"])
        active = pdf_fixture("Public release notes.", b"/OpenAction << /S /JavaScript /JS (noop) >>")
        self.assertFalse(extract(active, "pdf")["complete"])


@unittest.skipUnless(importlib.util.find_spec("mcp"), "Official MCP SDK optional dependency is not installed")
class SDKTests(unittest.IsolatedAsyncioTestCase):
    async def test_official_sdk_upstream_server(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "official_server.py"
            script.write_text('from mcp.server.fastmcp import FastMCP\nserver=FastMCP("fixture")\n@server.tool()\ndef echo(text: str) -> str:\n    return text\nserver.run()\n')
            config = {"servers": {"sdk": {"command": sys.executable, "args": [str(script)], "cwd": directory}}, "policy": {"default": "deny", "allow": ["sdk__echo"]}, "timeout_seconds": 10}
            audit = Audit(Path(directory) / "state")
            gateway = Gateway(config, audit)
            try:
                await gateway.start()
                result = await gateway.call({"name": "sdk__echo", "arguments": {"text": "Public release notes."}})
                self.assertFalse(result.get("isError", False))
                self.assertIn("Public release notes.", result["content"][0]["text"])
            finally:
                await gateway.close()
                audit.close()

    async def test_official_sdk_client(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text(json.dumps(demo_config()))
            params = StdioServerParameters(command=sys.executable, args=["-m", "mcpsentry", "run", "--config", str(config), "--allow-exec", "--state-dir", directory], cwd=str(ROOT))
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as client:
                    await client.initialize()
                    listing = await client.list_tools()
                    self.assertIn("mail__send", [t.name for t in listing.tools])
                    result = await client.call_tool("mail__send", {"to": "team@example.com", "body": "4242424242424242"})
                    self.assertTrue(result.isError)


@unittest.skipUnless(importlib.util.find_spec("pypdf"), "Optional pypdf dependency is not installed")
class PDFTests(unittest.TestCase):
    def test_real_pdf_text_extraction(self):
        from pypdf import PdfWriter
        from pypdf.generic import DictionaryObject, NameObject, DecodedStreamObject
        import io
        from mcpsentry.documents import extract
        writer = PdfWriter()
        page = writer.add_blank_page(width=612, height=792)
        font = DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"), NameObject("/BaseFont"): NameObject("/Helvetica")})
        page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): writer._add_object(font)})})
        stream = DecodedStreamObject()
        stream.set_data(b"BT /F1 12 Tf 72 720 Td (fictional.person@example.com) Tj ET")
        page[NameObject("/Contents")] = writer._add_object(stream)
        output = io.BytesIO()
        writer.write(output)
        result = extract(output.getvalue(), "pdf")
        self.assertTrue(result["complete"], result["issue"])
        self.assertIn("fictional.person@example.com", "".join(result["texts"]))


@unittest.skipUnless(os.environ.get("MCP_SENTRY_RUN_DOCKER_TESTS") == "1", "Docker runtime test requires explicit opt-in and a prebuilt local image")
class DockerTests(unittest.TestCase):
    def test_container_network_and_filesystem_restrictions(self):
        code = """import json,os,socket
result={'uid':os.getuid()}
try:
 open('/must-not-write','w').close();result['readonly']=False
except OSError: result['readonly']=True
try:
 socket.create_connection(('1.1.1.1',443),timeout=1);result['network_blocked']=False
except OSError: result['network_blocked']=True
print(json.dumps(result))
"""
        spec = {"command": "python3", "args": ["-c", code], "sandbox": {"image": "mcpsentry-demo:local"}}
        result = subprocess.run(command(spec, "mcpsentry-test-" + uuid.uuid4().hex), text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"uid": 65534, "readonly": True, "network_blocked": True})
