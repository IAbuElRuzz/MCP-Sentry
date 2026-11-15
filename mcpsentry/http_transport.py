"""Bounded Streamable HTTP upstream client (POST JSON / inline SSE).

No redirects, automatic tool retries, proxy environment, or background GET
streams. DNS answers are checked and the validated address is pinned to the
socket; HTTPS still validates the original hostname and certificate.
"""

import asyncio
import http.client
import ipaddress
import json
import os
import socket
import ssl
import time
from urllib.parse import urlsplit

from . import __version__
from .security import encode
from .transport import Backend, BackendError, LIMIT, VERSIONS


def resolve_target(host, port, *, allow_private=False, insecure=False):
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise BackendError("http_dns_failed")
    for _, _, _, _, address in addresses:
        ip = ipaddress.ip_address(address[0].split("%", 1)[0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        # Metadata/link-local destinations are never allowed, even with opt-in.
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved or ip in {ipaddress.ip_address("100.100.100.200"), ipaddress.ip_address("fd00:ec2::254")}:
            raise BackendError("http_destination_forbidden")
        if not allow_private and not ip.is_global:
            raise BackendError("http_private_destination_forbidden")
        if insecure and not ip.is_loopback:
            raise BackendError("plaintext_http_requires_loopback")
    return addresses


def pinned_connection(host, port, addresses, timeout, secure):
    def connect(_address, timeout=timeout, source_address=None):
        # Every address in this list was validated. Do not resolve host again.
        last = None
        for family, socktype, proto, _, address in addresses:
            sock = socket.socket(family, socktype, proto)
            try:
                sock.settimeout(timeout)
                if source_address:
                    sock.bind(source_address)
                sock.connect(address)
                return sock
            except OSError as exc:
                last = exc
                sock.close()
        raise last or BackendError("http_connection_failed")

    connection = (http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl.create_default_context()) if secure else http.client.HTTPConnection(host, port, timeout=timeout))
    connection._create_connection = connect
    return connection


def decode_message(raw, request_id):
    message = json.loads(raw)
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        raise BackendError("invalid_http_message")
    if "method" in message:
        if "id" in message:
            raise BackendError("http_server_requests_unsupported")
        return None
    if type(message.get("id")) is not int or message["id"] != request_id:
        raise BackendError("mismatched_http_response")
    if "error" in message or not isinstance(message.get("result"), dict):
        raise BackendError("http_rpc_error")
    return message["result"]


def read_result(response, request_id, deadline):
    content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
    if response.getheader("Content-Encoding", "identity").lower() != "identity":
        raise BackendError("http_encoding_unsupported")
    total, buffer, lines, events = 0, b"", [], 0
    if content_type not in {"application/json", "text/event-stream"}:
        raise BackendError("http_content_type_unsupported")
    while True:
        if time.monotonic() >= deadline:
            raise BackendError("http_deadline_exceeded")
        chunk = response.read1(min(65536, LIMIT + 1 - total))
        total += len(chunk)
        if total > LIMIT:
            raise BackendError("http_message_too_large")
        if content_type == "application/json":
            buffer += chunk
            if not chunk:
                result = decode_message(buffer, request_id)
                if result is None:
                    raise BackendError("http_response_missing")
                return result
            continue
        buffer += chunk
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            line = line.rstrip(b"\r")
            if line == b"":
                if lines:
                    events += 1
                    if events > 128:
                        raise BackendError("too_many_http_events")
                    payload = b"\n".join(lines)
                    lines = []
                    if not payload.strip():
                        continue
                    result = decode_message(payload, request_id)
                    if result is not None:
                        return result
            elif line.startswith(b"data:"):
                value = line[5:]
                lines.append(value[1:] if value.startswith(b" ") else value)
        if not chunk:
            # Resumption/reconnect is deliberately unsupported: a call whose
            # response stream drops must not be silently executed a second time.
            raise BackendError("http_stream_ended_without_result")


class HTTPBackend(Backend):
    def __init__(self, name, spec, timeout):
        super().__init__(name, spec, timeout)
        self.url = urlsplit(spec["url"])
        self.session_id = None
        self.version = "2025-11-25"
        self.connection = None
        self.headers = {}

    async def start(self):
        for header, variable in self.spec.get("headers_env", {}).items():
            value = os.environ.get(variable)
            if not value or len(value) > 8192 or any(ord(c) < 32 or ord(c) > 126 for c in value):
                raise BackendError("missing_or_invalid_http_header_environment")
            self.headers[header] = value
        result = await self.request("initialize", {"protocolVersion": self.version, "capabilities": {}, "clientInfo": {"name": "MCP-Sentry", "version": __version__}})
        if result.get("protocolVersion") not in VERSIONS - {"2024-11-05"}:
            raise BackendError("unsupported_http_protocol")
        self.version = result["protocolVersion"]
        await self._exchange_async({"jsonrpc": "2.0", "method": "notifications/initialized"})

    async def request(self, method, params=None):
        async with self.lock:
            if self.broken:
                raise BackendError("backend_unavailable")
            self.counter += 1
            return await self._exchange_async({"jsonrpc": "2.0", "id": self.counter, "method": method, "params": params or {}})

    def _abort(self):
        connection = self.connection
        if connection is not None:
            if connection.sock is not None:
                try:
                    connection.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            connection.close()

    async def _exchange_async(self, message=None, terminate=False):
        try:
            return await asyncio.wait_for(asyncio.to_thread(self._exchange, message, terminate), self.timeout)
        except (TimeoutError, OSError, ValueError, RecursionError, http.client.HTTPException, BackendError) as exc:
            self.broken = True
            self._abort()
            raise BackendError("http_backend_request_failed") from exc
        except asyncio.CancelledError:
            self.broken = True
            self._abort()
            raise

    def _exchange(self, message, terminate):
        deadline = time.monotonic() + self.timeout
        secure = self.url.scheme == "https"
        if not secure and not self.spec.get("allow_insecure_http", False):
            raise BackendError("plaintext_http_requires_explicit_opt_in")
        host, port = self.url.hostname, self.url.port or (443 if secure else 80)
        addresses = resolve_target(host, port, allow_private=self.spec.get("allow_private_network", False), insecure=not secure)
        # A timed-out DNS lookup may complete later; never dispatch after expiry.
        if self.broken or time.monotonic() >= deadline:
            raise BackendError("http_deadline_exceeded")
        connection = pinned_connection(host, port, addresses, max(0.01, deadline - time.monotonic()), secure)
        self.connection = connection
        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json", "MCP-Protocol-Version": self.version, **self.headers}
        if self.session_id is not None:
            headers["MCP-Session-Id"] = self.session_id
        path = self.url.path or "/"
        if self.url.query:
            path += "?" + self.url.query
        body = None if terminate else encode(message).encode()
        if body is not None and len(body) > LIMIT:
            raise BackendError("http_message_too_large")
        try:
            # A worker may finish DNS/connect after its asyncio deadline. Check
            # again after connecting so it cannot dispatch a late tool call.
            connection.connect()
            if self.broken or time.monotonic() >= deadline:
                raise BackendError("http_deadline_exceeded")
            connection.request("DELETE" if terminate else "POST", path, body=body, headers=headers)
            response = connection.getresponse()
            if terminate:
                return None
            # HTTP redirects and session expiry are never retried automatically.
            if "id" not in message:
                if response.status not in {202, 204}:
                    raise BackendError("http_notification_failed")
                return None
            if response.status != 200:
                raise BackendError("http_request_failed")
            session = response.getheader("MCP-Session-Id")
            if message["method"] == "initialize" and session is not None:
                if not 1 <= len(session) <= 1024 or any(not 0x21 <= ord(c) <= 0x7e for c in session):
                    raise BackendError("invalid_http_session_id")
                self.session_id = session
            return read_result(response, message["id"], deadline)
        finally:
            connection.close()
            self.connection = None

    async def close(self):
        if self.session_id is not None and not self.broken:
            try:
                await self._exchange_async(terminate=True)
            except BackendError:
                pass
        self._abort()
        self.session_id = None
