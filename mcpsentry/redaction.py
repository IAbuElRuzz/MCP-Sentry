"""Explicit string-field redaction. Routing and opaque payloads stay blocked."""

import copy
import fnmatch
import re

from .dlp import CATEGORIES, EMAIL, PHONE, CARD, IBAN, IBAN_GROUPED, SSN, TOKENS, ASSIGNMENT, AUTH, URL_AUTH, JWT, luhn, iban_checksum

PROTECTED = {"to", "from", "cc", "bcc", "recipient", "recipients", "url", "uri", "host", "hostname", "endpoint", "path", "file_path", "command", "args", "method", "operation"}
REDACTABLE = CATEGORIES - {"opaque_payload"} | {"tracked_data"}


def validate(config):
    if not isinstance(config, dict) or set(config) - {"enabled", "rules"} or not isinstance(config.get("enabled", False), bool):
        raise ValueError("Invalid redaction configuration")
    rules = config.get("rules", [])
    if not isinstance(rules, list) or len(rules) > 128:
        raise ValueError("redaction.rules must contain at most 128 rules")
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {"tool", "paths", "categories"}:
            raise ValueError("Redaction rules require tool, paths, and categories")
        if not isinstance(rule["tool"], str) or not 1 <= len(rule["tool"]) <= 128:
            raise ValueError("Redaction requires a bounded tool pattern")
        if not isinstance(rule["categories"], list) or not rule["categories"] or any(not isinstance(c, str) or c not in REDACTABLE for c in rule["categories"]):
            raise ValueError("Invalid redaction categories; opaque payloads cannot be redacted")
        if not isinstance(rule["paths"], list) or not 1 <= len(rule["paths"]) <= 32:
            raise ValueError("Redaction requires exact string-field paths")
        for path in rule["paths"]:
            if not isinstance(path, str) or not path.startswith("/") or len(path) > 2048 or re.search(r"~(?![01])", path):
                raise ValueError("Redaction paths must be exact non-root JSON pointers")
            parts = [p.replace("~1", "/").replace("~0", "~") for p in path[1:].split("/")]
            if any(p.casefold() in PROTECTED or p.startswith("@") for p in parts):
                raise ValueError("Redaction cannot target routing, operation or reserved fields")


def mask(text, categories):
    if categories - {"email", "phone", "payment_card", "iban", "national_id"}:
        return ""  # No reliable offsets for semantics, private keys or custom terms.
    rules = []
    if "email" in categories:
        rules.append((EMAIL, None))
    if "phone" in categories:
        rules.append((PHONE, None))
    if "payment_card" in categories:
        rules.append((CARD, luhn))
    if "iban" in categories:
        rules.extend([(IBAN, iban_checksum), (IBAN_GROUPED, iban_checksum)])
    if "national_id" in categories:
        rules.append((SSN, None))
    if "credentials" in categories:
        rules.extend((p, None) for p in (TOKENS, ASSIGNMENT, AUTH, URL_AUTH, JWT))
    changed = text
    for pattern, validator in rules:
        changed = pattern.sub(lambda m: "[REDACTED]" if validator is None or validator(m.group(0)) else m.group(0), changed)
    return changed if changed != text else ""  # Encoded content: discard the whole field.


def candidate(arguments, tool, config, inspection):
    """Return a new argument object and count; never return previews/paths to logs."""
    output, changed = copy.deepcopy(arguments), set()
    for rule in config.get("rules", []):
        if not fnmatch.fnmatchcase(tool, rule["tool"]):
            continue
        for pointer in rule["paths"]:
            categories = {category for category, path in inspection.locations if path == pointer or path.startswith(pointer + "/")}
            flow = any(path == pointer or path.startswith(pointer + "/") for path in inspection.transfer_paths)
            if not categories and not flow:
                continue
            if flow and "tracked_data" not in rule["categories"]:
                continue
            if not categories <= set(rule["categories"]):
                continue
            parts = [p.replace("~1", "/").replace("~0", "~") for p in pointer[1:].split("/")]
            parent = output
            try:
                for part in parts[:-1]:
                    parent = parent[int(part)] if isinstance(parent, list) else parent[part]
                key = int(parts[-1]) if isinstance(parent, list) else parts[-1]
                original = parent[key]
                if not isinstance(original, str):
                    continue
                replacement = "" if flow else mask(original, categories)
                if replacement != original:
                    parent[key] = replacement
                    changed.add(pointer)
            except (KeyError, IndexError, ValueError, TypeError):
                continue
    return output, changed
