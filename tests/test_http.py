import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mcpsentry.audit import Audit
from mcpsentry.config import load
from mcpsentry.gateway import Gateway
from mcpsentry.http_transport import HTTPBackend, pinned_connection, read_result, resolve_target
from mcpsentry.transport import BackendError, LIMIT


class Fixture(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, status, body=b"", content_type="application/json", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_DELETE(self):
        self.server.received.append(("DELETE", dict(self.headers), None))
        self.reply(204)

    def do_POST(self):
        message = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method = message["method"]
        self.server.received.append((method, dict(self.headers), message))
        if self.server.failure:
            self.reply(self.server.failure, extra={"Location": "http://169.254.169.254/"})
            return
        if method != "initialize" and self.headers.get("MCP-Session-Id") != "private-session-id":
            self.reply(400)
            return
        if "id" not in message:
            self.reply(202)
            return
        if method == "initialize":
            result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}, "serverInfo": {"name": "http-fixture", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "echo", "description": "An inert fixture", "inputSchema": {"type": "object"}}]}
        else:
            result = {"content": [{"type": "text", "text": message["params"]["arguments"].get("text", "fixture result")}]}
        data = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode()
        extra = {"MCP-Session-Id": "private-session-id"} if method == "initialize" else None
        if self.server.sse:
            # Include a heartbeat and empty priming event before the response.
            data = b": heartbeat\n\nid: seed\ndata:\n\ndata: " + data + b"\n\n"
            self.reply(200, data, "text/event-stream", extra)
        else:
            self.reply(200, data, extra=extra)


class HTTPTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        try:
            self.server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        except PermissionError:
            self.skipTest("Environment prohibits binding a loopback socket; socket-free HTTP framing tests still run")
        self.server.daemon_threads = True
        self.server.received, self.server.failure, self.server.sse = [], None, False
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.spec = {"url": f"http://127.0.0.1:{self.server.server_port}/mcp", "allow_private_network": True, "allow_insecure_http": True}
        self.backend = HTTPBackend("web", self.spec, 2)

    async def asyncTearDown(self):
        await self.backend.close()
        await asyncio.to_thread(self.server.shutdown)
        self.server.server_close()
        self.thread.join(timeout=2)

    async def test_json_session_and_tool_calls(self):
        with patch.dict(os.environ, {"MCP_TEST_AUTH": "Bearer fake-test-token"}):
            self.spec["headers_env"] = {"Authorization": "MCP_TEST_AUTH"}
            await self.backend.start()
        self.assertEqual((await self.backend.tools())[0]["name"], "echo")
        result = await self.backend.request("tools/call", {"name": "echo", "arguments": {"text": "ordinary text"}})
        self.assertEqual(result["content"][0]["text"], "ordinary text")
        self.assertEqual(self.server.received[1][1]["MCP-Session-Id"], "private-session-id")
        self.assertTrue(all(item[1]["Authorization"] == "Bearer fake-test-token" for item in self.server.received))
        self.assertTrue(all(item[1]["MCP-Protocol-Version"] == "2025-11-25" for item in self.server.received))
        await self.backend.close()
        self.assertEqual(self.server.received[-1][0], "DELETE")

    async def test_inline_sse(self):
        self.server.sse = True
        await self.backend.start()
        self.assertEqual((await self.backend.tools())[0]["name"], "echo")

    async def test_redirect_is_not_followed_or_retried(self):
        self.server.failure = 302
        with self.assertRaises(BackendError):
            await self.backend.start()
        self.assertEqual(len(self.server.received), 1)

    async def test_session_expiry_does_not_retry_operation(self):
        await self.backend.start()
        before = len(self.server.received)
        self.server.failure = 404
        with self.assertRaises(BackendError):
            await self.backend.request("tools/call", {"name": "echo", "arguments": {}})
        self.assertEqual(len(self.server.received), before + 1)
        self.assertTrue(self.backend.broken)

    async def test_http_gateway_enforces_before_network_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(directory)
            config = {"servers": {"web": self.spec}, "policy": {"default": "allow", "argument_constraints": {"web__echo": {"/text": {"type": "string", "max_length": 10}}}}, "timeout_seconds": 2}
            gateway = Gateway(config, audit)
            try:
                await gateway.start()
                blocked = await gateway.call({"name": "web__echo", "arguments": {"text": "too long to forward"}})
                self.assertIn("argument_constraint", blocked["content"][0]["text"])
                self.assertFalse(any(row[0] == "tools/call" for row in self.server.received))
                allowed = await gateway.call({"name": "web__echo", "arguments": {"text": "hello"}})
                self.assertEqual(allowed["content"][0]["text"], "hello")
                self.assertNotIn(b"private-session-id", audit.path.read_bytes())
            finally:
                await gateway.close()
                audit.close()

    async def test_private_network_opt_in_is_required(self):
        self.spec["allow_private_network"] = False
        with self.assertRaises(BackendError):
            await self.backend.start()
        self.assertEqual(self.server.received, [])


class WireConnection:
    """Exercise stdlib's real HTTPResponse parser without opening a socket."""

    def __init__(self, state):
        self.state = state
        self.sock = None
        self.raw = b""

    def request(self, method, path, body=None, headers=None):
        message = json.loads(body) if body else None
        rpc = message["method"] if message else "DELETE"
        self.state.received.append((rpc, dict(headers), message))
        status, payload, content_type = 200, b"", "application/json"
        extra = {}
        if method == "DELETE":
            status = 204
        elif self.state.failure:
            status = self.state.failure
            extra["Location"] = "http://169.254.169.254/"
        elif rpc != "initialize" and headers.get("MCP-Session-Id") != "private-session-id":
            status = 400
        elif "id" not in message:
            status = 202
        else:
            if rpc == "initialize":
                result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}, "serverInfo": {"name": "wire-fixture", "version": "1"}}
                extra["MCP-Session-Id"] = "private-session-id"
            elif rpc == "tools/list":
                result = {"tools": [{"name": "echo", "description": "An inert fixture", "inputSchema": {"type": "object"}}]}
            else:
                result = {"content": [{"type": "text", "text": message["params"]["arguments"].get("text", "fixture result")}]}
            payload = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode()
            if self.state.sse:
                content_type = "text/event-stream"
                payload = b": heartbeat\n\nid: seed\ndata:\n\ndata: " + payload + b"\n\n"
        headers_out = {"Content-Type": content_type, **extra}
        if self.state.chunked and payload:
            headers_out["Transfer-Encoding"] = "chunked"
            parts = [payload[i:i+17] for i in range(0, len(payload), 17)]
            payload = b"".join(f"{len(p):x}\r\n".encode() + p + b"\r\n" for p in parts) + b"0\r\n\r\n"
        else:
            headers_out["Content-Length"] = str(len(payload))
        self.raw = f"HTTP/1.1 {status} Fixture\r\n".encode() + b"".join(f"{k}: {v}\r\n".encode() for k, v in headers_out.items()) + b"\r\n" + payload

    def connect(self):
        pass

    def getresponse(self):
        import http.client
        raw = self.raw

        class Socket:
            def makefile(self, *args, **kwargs):
                return io.BytesIO(raw)

        response = http.client.HTTPResponse(Socket())
        response.begin()
        return response

    def close(self):
        pass


class WireHTTPTests(HTTPTests):
    async def asyncSetUp(self):
        self.server = SimpleNamespace(server_port=8123, received=[], failure=None, sse=False, chunked=False)
        self.spec = {"url": "http://127.0.0.1:8123/mcp", "allow_private_network": True, "allow_insecure_http": True}
        self.backend = HTTPBackend("web", self.spec, 2)
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8123))]
        self.dns = patch("mcpsentry.http_transport.socket.getaddrinfo", return_value=addresses)
        self.connections = patch("mcpsentry.http_transport.pinned_connection", side_effect=lambda *args: WireConnection(self.server))
        self.dns.start()
        self.connections.start()

    async def asyncTearDown(self):
        await self.backend.close()
        self.connections.stop()
        self.dns.stop()

    async def test_chunked_sse(self):
        self.server.sse = self.server.chunked = True
        await self.backend.start()
        result = await self.backend.request("tools/call", {"name": "echo", "arguments": {"text": "chunked fixture"}})
        self.assertEqual(result["content"][0]["text"], "chunked fixture")

    async def test_late_connect_cannot_dispatch_after_timeout(self):
        import time
        self.backend.timeout = 0.02

        def delayed_connect(connection):
            time.sleep(0.08)

        with patch.object(WireConnection, "connect", delayed_connect):
            with self.assertRaises(BackendError):
                await self.backend.start()
            await asyncio.sleep(0.1)
        self.assertEqual(self.server.received, [])
        self.assertTrue(self.backend.broken)


class HTTPBoundaryTests(unittest.TestCase):
    def test_mixed_public_private_dns_is_rejected(self):
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in ("1.1.1.1", "127.0.0.1")]
        with patch("mcpsentry.http_transport.socket.getaddrinfo", return_value=addresses):
            with self.assertRaises(BackendError):
                resolve_target("fixture.example", 443)

    def test_link_local_is_always_rejected(self):
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]
        with patch("mcpsentry.http_transport.socket.getaddrinfo", return_value=addresses):
            with self.assertRaises(BackendError):
                resolve_target("metadata.example", 80, allow_private=True)

    def test_non_link_local_metadata_endpoints_are_rejected(self):
        for family, ip in ((socket.AF_INET, "100.100.100.200"), (socket.AF_INET6, "fd00:ec2::254")):
            addresses = [(family, socket.SOCK_STREAM, 6, "", (ip, 80))]
            with patch("mcpsentry.http_transport.socket.getaddrinfo", return_value=addresses):
                with self.assertRaises(BackendError):
                    resolve_target("metadata.example", 80, allow_private=True)

    def test_plaintext_is_limited_to_loopback(self):
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 80))]
        with patch("mcpsentry.http_transport.socket.getaddrinfo", return_value=addresses):
            with self.assertRaises(BackendError):
                resolve_target("fixture.example", 80, insecure=True)

    def test_socket_uses_validated_address_without_second_dns_lookup(self):
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443))]
        connection = pinned_connection("fixture.example", 443, addresses, 2, True)
        with patch("mcpsentry.http_transport.socket.socket") as factory, patch("mcpsentry.http_transport.socket.getaddrinfo") as dns:
            connection._create_connection(("fixture.example", 443))
            factory.return_value.connect.assert_called_once_with(("1.1.1.1", 443))
            dns.assert_not_called()

    def test_config_rejects_ambiguous_servers_and_reserved_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            invalid = [
                {"url": "http://127.0.0.1/mcp"},
                {"url": "https://user:password@example.com/mcp"},
                {"url": "https://example.com/mcp", "command": "python"},
                {"url": "https://example.com/mcp", "headers_env": {"Host": "EVIL"}},
            ]
            for spec in invalid:
                path.write_text(json.dumps({"servers": {"remote": spec}}))
                with self.assertRaises(ValueError):
                    load(path)

    def test_remote_config_parses_without_contacts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"servers": {"remote": {"url": "https://example.com/mcp", "headers_env": {"Authorization": "MCP_AUTH"}}}}))
            self.assertIn("url", load(path)["servers"]["remote"])

    def test_oversized_response_is_rejected(self):
        class Response:
            def __init__(self):
                self.buffer = io.BytesIO(b"x" * (LIMIT + 1))

            def getheader(self, name, default=None):
                return "application/json" if name == "Content-Type" else default

            def read1(self, n):
                return self.buffer.read(n)

        import time
        with self.assertRaises(BackendError):
            read_result(Response(), 1, time.monotonic() + 5)
