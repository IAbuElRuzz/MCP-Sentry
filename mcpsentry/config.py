"""Strict configuration: typos must not silently weaken policy."""

import json
import re
from pathlib import Path


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
        raise ValueError("Configure between 1 and 32 local servers")
    for name, spec in servers.items():
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,24}", name):
            raise ValueError("Server names must be 1–24 letters, digits, underscores or hyphens")
        keys(spec, {"command", "args", "cwd", "env"}, "server")
        if not isinstance(spec.get("command"), str) or not spec["command"]:
            raise ValueError("Each server requires a command")
        spec["args"] = strings(spec.get("args", []), "args")
        cwd = spec.get("cwd", ".")
        if not isinstance(cwd, str):
            raise ValueError("cwd must be a string")
        spec["cwd"] = str((path.parent / cwd).resolve())
        env = spec.get("env", {})
        if not isinstance(env, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in env.items()):
            raise ValueError("env must map names to strings")
    policy = data.setdefault("policy", {})
    keys(policy, {"default", "allow", "deny", "sensitive_sources", "sensitive_destinations", "recipient_allowlists", "block_secrets", "block_tool_changes", "block_poisoning"}, "policy")
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
    timeout = data.get("timeout_seconds", 10)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0.1 <= timeout <= 120:
        raise ValueError("timeout_seconds must be between 0.1 and 120")
    data["timeout_seconds"] = timeout
    return data
