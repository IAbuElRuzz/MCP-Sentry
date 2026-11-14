"""A deliberately small tools-only MCP server and upstream client."""

import asyncio
import json
import re
import time
from pathlib import Path

from .security import Guard, encode, fingerprint, poisoned
from .transport import Backend, BackendError, LIMIT, VERSIONS


class Gateway:
    def __init__(self, config, audit, mode="enforce", baseline=None):
        self.config, self.audit, self.mode = config, audit, mode
        self.guard = Guard(config["policy"])
        self.backends = {}
        self.approved = None
        self.baseline = baseline
        self.routes = {}

    async def start(self):
        try:
            for name, spec in self.config["servers"].items():
                backend = Backend(name, spec, self.config["timeout_seconds"])
                self.backends[name] = backend
                await backend.start()
            tools = await self.discover()
            current = self.snapshot(tools)
            self.approved = self.baseline if self.baseline is not None else current
            self.audit.record("session_started", decision=self.mode)
            return tools
        except BaseException:
            await self.close()
            raise

    async def discover(self):
        tools, routes = [], {}
        for name, backend in self.backends.items():
            for tool in await backend.tools():
                if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", tool["name"]):
                    raise BackendError("invalid_tool_name")
                if not isinstance(tool.get("inputSchema"), dict):
                    raise BackendError("invalid_tool_schema")
                alias = name + "__" + tool["name"]
                if alias in routes:
                    raise BackendError("duplicate_tool_name")
                routes[alias] = (backend, tool["name"])
                # Drop extensions/annotations: upstream claims are not trusted.
                public = {k: tool[k] for k in ("description", "inputSchema", "outputSchema", "title") if k in tool}
                public["name"] = alias
                tools.append(public)
        if len(encode(tools).encode()) > LIMIT // 2:
            raise BackendError("aggregate_catalog_too_large")
        self.routes = routes
        return tools

    def snapshot(self, tools):
        # Bind approvals to configured command, arguments, cwd and environment,
        # without storing any of those possibly sensitive values in the file.
        return {"version": 1, "configuration": fingerprint(self.config), "tools": {t["name"]: fingerprint(t) for t in tools}}

    def changed(self, tool, tools):
        current = self.snapshot(tools)
        return (self.approved.get("configuration") != current["configuration"] or self.approved.get("tools", {}).get(tool) != current["tools"].get(tool))

    async def list_tools(self):
        tools = await self.discover()
        visible = []
        for tool in tools:
            p = self.config["policy"]
            reason = "tool_changed" if p.get("block_tool_changes", True) and self.changed(tool["name"], tools) else "tool_poisoning" if p.get("block_poisoning", True) and poisoned(tool) else None
            if reason:
                self.audit.record("catalog_finding", tool["name"], "alert", reason)
                if self.mode == "enforce":
                    continue
            visible.append(tool)
        return {"tools": visible}

    async def call(self, params):
        if set(params) - {"name", "arguments", "_meta"}:
            raise ValueError("Unsupported tools/call parameters")
        name, args = params.get("name"), params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(args, dict):
            raise ValueError("Tool name and argument object required")
        started = time.monotonic()
        # Always refresh immediately before dispatch. This cannot prevent a
        # dishonest server from lying about behavior or changing after the check.
        tools = await self.discover()
        tool = next((t for t in tools if t["name"] == name), None)
        if tool is None:
            self.audit.record("call_blocked", "", "block", "unknown_tool")
            return self.blocked("unknown_tool")
        p = self.config["policy"]
        reason = self.guard.inspect_call(name, args)
        if p.get("block_tool_changes", True) and self.changed(name, tools):
            reason = "tool_changed"
        if p.get("block_poisoning", True) and poisoned(tool):
            reason = "tool_poisoning"
        if reason and self.mode == "enforce":
            self.audit.record("call_blocked", name, "block", reason)
            return self.blocked(reason)
        # Write intent before dispatch; audit failure prevents the operation.
        self.audit.record("call_started", name, "would_block" if reason else "allow", reason or "policy_passed")
        backend, original = self.routes[name]
        try:
            result = await backend.request("tools/call", {"name": original, "arguments": args})
            if not isinstance(result.get("content"), list) or not isinstance(result.get("isError", False), bool):
                raise BackendError("invalid_tool_result")
            # This MVP inspects text and structured JSON only. Do not silently
            # bypass inspection via images, embedded resources or custom blocks.
            if any(not isinstance(block, dict) or block.get("type") != "text" or not isinstance(block.get("text"), str) for block in result["content"]):
                self.audit.record("response_blocked", name, "block", "unsupported_content")
                return self.blocked("unsupported_content")
            public = {k: result[k] for k in ("structuredContent", "isError") if k in result}
            public["content"] = [{"type": "text", "text": block["text"]} for block in result["content"]]
            self.guard.observe(name, public)
            response_poison = p.get("block_poisoning", True) and poisoned(public)
            decision = "block" if response_poison and self.mode == "enforce" else "would_block" if response_poison else "error" if public.get("isError") else "allow"
            self.audit.record("call_finished", name, decision, "response_poisoning" if response_poison else "tool_error" if public.get("isError") else "completed", int((time.monotonic() - started) * 1000))
            if decision == "block":
                return self.blocked("response_poisoning")
            return public
        except BackendError:
            self.audit.record("call_failed", name, "error", "backend_failure", int((time.monotonic() - started) * 1000))
            return self.blocked("backend_failure; outcome may be unknown, do not retry blindly")

    @staticmethod
    def blocked(reason):
        return {"isError": True, "content": [{"type": "text", "text": "MCP-Sentry blocked: " + reason}]}

    async def close(self):
        for backend in reversed(list(self.backends.values())):
            await backend.close()
        self.backends.clear()


async def serve(gateway):
    """Serialized stdio endpoint. stdout contains protocol messages only."""
    import sys
    reader = asyncio.StreamReader(limit=LIMIT + 1)
    protocol = asyncio.StreamReaderProtocol(reader)
    transport, _ = await asyncio.get_running_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)
    initialized = ready = False
    started = False
    try:
        while True:
            try:
                raw = await reader.readline()
                if not raw:
                    break
                if len(raw) > LIMIT:
                    break
            except ValueError:
                break
            request_id = None
            notify = False
            try:
                message = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON")))
                if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
                    raise ValueError("Invalid JSON-RPC request")
                notify = "id" not in message
                request_id = message.get("id")
                if not notify and (isinstance(request_id, bool) or not isinstance(request_id, (str, int))):
                    raise ValueError("Invalid request id")
                method, params = message["method"], message.get("params", {})
                if not isinstance(params, dict):
                    raise ValueError("params must be an object")
                if notify:
                    if method == "notifications/initialized" and initialized:
                        ready = True
                    continue
                if method == "ping":
                    result = {}
                elif method == "initialize" and not initialized:
                    requested = params.get("protocolVersion")
                    version = requested if requested in VERSIONS else "2025-11-25"
                    result = {"protocolVersion": version, "capabilities": {"tools": {}}, "serverInfo": {"name": "MCP-Sentry", "version": "0.1.0"}}
                    initialized = True
                elif not ready:
                    raise ValueError("Initialize the MCP session first")
                elif method in {"tools/list", "tools/call"}:
                    if not started:
                        await gateway.start()
                        started = True
                    result = await gateway.list_tools() if method == "tools/list" else await gateway.call(params)
                else:
                    response = {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Only tools/list and tools/call are supported"}}
                    sys.stdout.write(encode(response) + "\n")
                    sys.stdout.flush()
                    continue
                response = {"jsonrpc": "2.0", "id": request_id, "result": result}
            except (ValueError, TypeError, RecursionError):
                response = {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32602, "message": "Invalid request or parameters"}}
            except Exception:
                # Backend messages and arguments must never leak via errors.
                response = {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32603, "message": "Gateway unavailable; check local configuration and backend health"}}
            if not notify:
                sys.stdout.write(encode(response) + "\n")
                sys.stdout.flush()
    finally:
        transport.close()
        await gateway.close()


def read_baseline(path):
    if path is None:
        return None
    path = Path(path)
    if path.stat().st_size > LIMIT:
        raise ValueError("Baseline too large")
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("configuration"), str) or not isinstance(data.get("tools"), dict):
        raise ValueError("Invalid baseline")
    return data
