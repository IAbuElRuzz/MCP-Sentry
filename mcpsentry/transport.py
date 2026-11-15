"""Bounded newline JSON-RPC over local stdio. Backends never get client sampling."""

import asyncio
import json
import os
import signal
import uuid
import tempfile

from .security import encode
from . import __version__
from .sandbox import command as sandbox_command

LIMIT = 1_048_576
VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}


class BackendError(Exception):
    pass


class Backend:
    def __init__(self, name, spec, timeout):
        self.name, self.spec, self.timeout = name, spec, timeout
        self.process = None
        self.counter = 0
        self.lock = asyncio.Lock()
        self.broken = False
        self.container_name = "mcpsentry-" + uuid.uuid4().hex if "sandbox" in spec else None

    async def start(self):
        # Explicit env only, plus minimal process/locale search environment.
        env = {k: v for k, v in os.environ.items() if k in {"PATH", "SYSTEMROOT", "LANG", "LC_ALL", "TMPDIR"}}
        if not self.container_name:
            env.update(self.spec.get("env", {}))
        # An unlinked, inherited descriptor avoids both secret process argv and
        # applying server environment variables to the host Docker CLI itself.
        env_file = tempfile.TemporaryFile() if self.container_name and self.spec.get("env") else None
        try:
            if env_file:
                env_file.write("".join(k + "=" + v + "\n" for k, v in self.spec["env"].items()).encode())
                env_file.seek(0)
            descriptor = "/dev/fd/" + str(env_file.fileno()) if env_file else None
            argv = sandbox_command(self.spec, self.container_name, descriptor) if self.container_name else [self.spec["command"], *self.spec["args"]]
            self.process = await asyncio.create_subprocess_exec(*argv, cwd=self.spec["cwd"], env=env, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, limit=LIMIT + 1, start_new_session=True, pass_fds=(env_file.fileno(),) if env_file else ())
            # Keep the descriptor alive until Docker has read the env-file.
            result = await self.request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "MCP-Sentry", "version": __version__}})
        finally:
            if env_file:
                env_file.close()
        if result.get("protocolVersion") not in VERSIONS:
            raise BackendError("unsupported_backend_protocol")
        await self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    async def send(self, message):
        raw = (encode(message) + "\n").encode()
        if len(raw) > LIMIT:
            raise BackendError("message_too_large")
        self.process.stdin.write(raw)
        await self.process.stdin.drain()

    async def request(self, method, params=None):
        async with self.lock:
            if self.broken:
                raise BackendError("backend_unavailable")
            try:
                return await asyncio.wait_for(self._request(method, params or {}), self.timeout)
            except (TimeoutError, OSError, ValueError, RecursionError, BackendError) as exc:
                self.broken = True
                raise BackendError("backend_request_failed") from exc

    async def _request(self, method, params):
        self.counter += 1
        request_id = self.counter
        await self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        for _ in range(128):
            raw = await self.process.stdout.readline()
            if not raw or len(raw) > LIMIT:
                raise BackendError("invalid_backend_message")
            message = json.loads(raw)
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                raise BackendError("invalid_backend_message")
            if "method" in message:
                if "id" in message:
                    await self.send({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "Server-initiated requests are not supported"}})
                # Notifications are not forwarded into the client's context.
                continue
            if message.get("id") != request_id:
                raise BackendError("mismatched_backend_response")
            if "error" in message or not isinstance(message.get("result"), dict):
                raise BackendError("backend_error")
            return message["result"]
        raise BackendError("too_many_backend_messages")

    async def tools(self):
        tools, cursor, seen = [], None, set()
        for _ in range(32):
            result = await self.request("tools/list", {"cursor": cursor} if cursor else {})
            page = result.get("tools")
            if not isinstance(page, list):
                raise BackendError("invalid_tool_list")
            tools.extend(page)
            if len(tools) > 512:
                raise BackendError("too_many_tools")
            cursor = result.get("nextCursor")
            if cursor is None:
                return tools
            if not isinstance(cursor, str) or not cursor or cursor in seen:
                raise BackendError("invalid_pagination")
            seen.add(cursor)
        raise BackendError("too_many_pages")

    async def close(self):
        try:
            await self._close_process()
        finally:
            if self.container_name:
                try:
                    cleanup = await asyncio.create_subprocess_exec("docker", "--context", "default", "rm", "--force", self.container_name, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                    try:
                        await asyncio.wait_for(cleanup.wait(), 3)
                    except TimeoutError:
                        cleanup.kill()
                        await cleanup.wait()
                except OSError:
                    pass

    async def _close_process(self):
        if self.process is None:
            return
        if self.process.stdin:
            self.process.stdin.close()
        try:
            await asyncio.wait_for(self.process.wait(), 0.5)
        except TimeoutError:
            pass
        # Also terminate descendants in the dedicated process group.
        try:
            os.killpg(self.process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(self.process.wait(), 1)
        except TimeoutError:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await self.process.wait()
