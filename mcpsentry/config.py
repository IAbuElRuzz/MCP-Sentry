"""Strict configuration: typos must not silently weaken policy."""

import json
import math
import re
from pathlib import Path
from urllib.parse import urlsplit
from .dlp import validate_config as validate_dlp
from .sandbox import validate as validate_sandbox
from .approvals import validate as validate_approvals
from .redaction import validate as validate_redaction
from .leaks import validate as validate_cross_call


def keys(value, allowed, where):
    if not isinstance(value, dict) or set(value) - set(allowed):
        raise ValueError(f"Invalid or unknown configuration keys in {where}")


def strings(value, where):
    if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value):
        raise ValueError(f"{where} must be a list of nonempty strings")
    return value


def load(path):
    path = Path(path).resolve()
    if path.stat().st_size > 1_000_000:
        raise ValueError("Configuration exceeds 1 MB")
    data = json.loads(path.read_text())
    keys(data, {"servers", "policy", "timeout_seconds"}, "root")
    servers = data.get("servers")
    if not isinstance(servers, dict) or not servers or len(servers) > 32:
        raise ValueError("Configure between 1 and 32 servers")
    for name, spec in servers.items():
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,24}", name):
            raise ValueError("Server names must be 1–24 letters, digits, underscores or hyphens")
        if "url" in spec:
            keys(spec, {"url", "headers_env", "allow_private_network", "allow_insecure_http"}, "HTTP server")
            url = spec["url"]
            if not isinstance(url, str) or len(url) > 8192 or any(ord(c) <= 32 or ord(c) == 127 for c in url):
                raise ValueError("HTTP URL must be a string without whitespace or control characters")
            parsed = urlsplit(url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
                raise ValueError("HTTP server requires an http(s) URL without credentials or fragment")
            try:
                parsed.port
            except ValueError:
                raise ValueError("Invalid HTTP port") from None
            for key in ("allow_private_network", "allow_insecure_http"):
                if not isinstance(spec.get(key, False), bool):
                    raise ValueError(f"{key} must be boolean")
            if parsed.scheme == "http" and not spec.get("allow_insecure_http", False):
                raise ValueError("HTTPS is required unless allow_insecure_http is explicitly enabled for loopback")
            headers = spec.get("headers_env", {})
            if not isinstance(headers, dict):
                raise ValueError("headers_env must map HTTP headers to environment variable names")
            protected = {"host", "connection", "content-length", "transfer-encoding", "accept", "content-type", "mcp-session-id", "mcp-protocol-version"}
            for header, variable in headers.items():
                if not isinstance(header, str) or not re.fullmatch(r"[A-Za-z0-9-]+", header) or header.lower() in protected or not isinstance(variable, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", variable):
                    raise ValueError("Invalid or reserved headers_env entry")
            continue
        keys(spec, {"command", "args", "cwd", "env", "sandbox"}, "server")
        if not isinstance(spec.get("command"), str) or not spec["command"]:
            raise ValueError("Each server requires a command")
        spec["args"] = strings(spec.get("args", []), "args")
        cwd = spec.get("cwd", ".")
        if not isinstance(cwd, str):
            raise ValueError("cwd must be a string")
        spec["cwd"] = str((path.parent / cwd).resolve())
        if "sandbox" in spec:
            validate_sandbox(spec["sandbox"], path.parent)
        env = spec.get("env", {})
        if not isinstance(env, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in env.items()):
            raise ValueError("env must map names to strings")
        if "sandbox" in spec and any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k) or any(c in v for c in ("\n", "\r", "\x00")) for k, v in env.items()):
            raise ValueError("Sandbox environment requires valid names and single-line values")
    policy = data.setdefault("policy", {})
    keys(policy, {"default", "allow", "deny", "sensitive_sources", "sensitive_destinations", "recipient_allowlists", "argument_constraints", "call_limits", "dlp", "redaction", "cross_call", "require_sandbox", "approvals", "block_secrets", "block_tool_changes", "block_poisoning", "destinations", "responses"}, "policy")
    if not isinstance(policy.get("require_sandbox", False), bool):
        raise ValueError("require_sandbox must be boolean")
    if policy.get("require_sandbox") and any("url" not in s and "sandbox" not in s for s in servers.values()):
        raise ValueError("Every local server must configure a sandbox when require_sandbox is true")
    from .protections import validate
    validate(policy)
    validate_dlp(policy.get("dlp", {}))
    validate_approvals(policy.get("approvals", {}))
    validate_redaction(policy.get("redaction", {}))
    validate_cross_call(policy.get("cross_call", {}))
    if policy.get("redaction", {}).get("enabled") and not policy.get("dlp", {}).get("enabled", True):
        raise ValueError("Redaction requires DLP inspection to remain enabled")
    if policy.get("default", "deny") not in {"allow", "deny"}:
        raise ValueError("policy.default must be allow or deny")
    for key in ("allow", "deny", "sensitive_sources", "sensitive_destinations"):
        strings(policy.get(key, []), key)
    for key in ("block_secrets", "block_tool_changes", "block_poisoning"):
        if not isinstance(policy.get(key, True), bool):
            raise ValueError(f"{key} must be boolean")
    recipients = policy.get("recipient_allowlists", {})
    if not isinstance(recipients, dict):
        raise ValueError("recipient_allowlists must be an object")
    for tool, fields in recipients.items():
        if not isinstance(tool, str) or not isinstance(fields, dict) or not fields:
            raise ValueError("Recipient restrictions require tool and argument fields")
        for field, values in fields.items():
            if not isinstance(field, str):
                raise ValueError("Recipient field must be a string")
            strings(values, "recipient values")
    protected_recipients = {field for fields in recipients.values() for field in fields}
    for rule in policy.get("redaction", {}).get("rules", []):
        if any(pointer[1:].split("/")[0].replace("~1", "/").replace("~0", "~") in protected_recipients for pointer in rule["paths"]):
            raise ValueError("Redaction cannot change configured recipient fields")
    destination_paths = {r["path"] for r in policy.get("destinations", {}).get("rules", [])}
    for rule in policy.get("redaction", {}).get("rules", []):
        if any(a == b or a.startswith(b + "/") or b.startswith(a + "/") for a in rule["paths"] for b in destination_paths):
            raise ValueError("Redaction cannot change destination fields")
    constraints = policy.get("argument_constraints", {})
    if not isinstance(constraints, dict):
        raise ValueError("argument_constraints must be an object")
    for pattern, fields in constraints.items():
        if not isinstance(pattern, str) or not pattern or not isinstance(fields, dict) or not fields:
            raise ValueError("Argument constraints require tool patterns and JSON pointers")
        for pointer, rule in fields.items():
            if not isinstance(pointer, str) or not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
                raise ValueError("Constraint paths must be non-root JSON pointers, e.g. /options/limit")
            keys(rule, {"required", "type", "enum", "minimum", "maximum", "max_length"}, "argument constraint")
            if not rule:
                raise ValueError("Empty argument constraint")
            if "required" in rule and not isinstance(rule["required"], bool):
                raise ValueError("required must be boolean")
            if "type" in rule and rule["type"] not in ("string", "number", "integer", "boolean", "array", "object", "null"):
                raise ValueError("Unsupported constraint type")
            if "enum" in rule and (not isinstance(rule["enum"], list) or not rule["enum"]):
                raise ValueError("enum must contain at least one JSON value")
            for bound in ("minimum", "maximum"):
                if bound in rule and (isinstance(rule[bound], bool) or not isinstance(rule[bound], (int, float)) or not math.isfinite(rule[bound])):
                    raise ValueError("Numeric constraints must have finite bounds")
            if "minimum" in rule and "maximum" in rule and rule["minimum"] > rule["maximum"]:
                raise ValueError("minimum exceeds maximum")
            if "max_length" in rule and (type(rule["max_length"]) is not int or not 0 <= rule["max_length"] <= 1_048_576):
                raise ValueError("max_length must be an integer between 0 and 1048576")
    limits = policy.get("call_limits", {})
    if not isinstance(limits, dict):
        raise ValueError("call_limits must be an object")
    for pattern, rule in limits.items():
        if not isinstance(pattern, str) or not pattern:
            raise ValueError("Call limits require tool patterns")
        keys(rule, {"max_calls", "window_seconds"}, "call limit")
        if type(rule.get("max_calls")) is not int or not 1 <= rule["max_calls"] <= 10000:
            raise ValueError("max_calls must be an integer between 1 and 10000")
        window = rule.get("window_seconds")
        if isinstance(window, bool) or not isinstance(window, (int, float)) or not 0.1 <= window <= 86400:
            raise ValueError("window_seconds must be between 0.1 and 86400")
    timeout = data.get("timeout_seconds", 10)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0.1 <= timeout <= 120:
        raise ValueError("timeout_seconds must be between 0.1 and 120")
    data["timeout_seconds"] = timeout
    return data
