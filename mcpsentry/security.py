"""Deterministic rules and bounded, session-local sensitive-value tracking."""

import fnmatch
import hashlib
import json
import re

SECRET = re.compile(r"(?:sk-(?:proj-)?[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,}|SENTRY_FAKE_SECRET_[A-Za-z0-9_-]{8,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)")
POISON = [
    re.compile(r"(?:do not|don't|never)\s+(?:tell|inform|mention|disclose).{0,60}(?:user|human)", re.I | re.S),
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions", re.I),
    re.compile(r"replaces?\s+.{0,60}(?:other|every).{0,30}tools?", re.I | re.S),
]


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def fingerprint(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def matches(name, patterns):
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def texts(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from texts(item)
    elif isinstance(value, list):
        for item in value:
            yield from texts(item)


def poisoned(tool):
    return any(rule.search(encode(tool)) for rule in POISON)


class Guard:
    def __init__(self, policy):
        self.policy = policy
        self.values = {}  # Raw values stay in process memory; never persisted.
        self.saturated = False

    def inspect_call(self, name, args):
        p = self.policy
        if matches(name, p.get("deny", [])):
            return "tool_denied"
        if p.get("default", "deny") == "deny" and not matches(name, p.get("allow", [])):
            return "tool_not_allowed"
        for pattern, fields in p.get("recipient_allowlists", {}).items():
            if not fnmatch.fnmatchcase(name, pattern):
                continue
            for field, allowed in fields.items():
                value = args.get(field)
                actual = value if isinstance(value, list) else [value]
                if not actual or any(not isinstance(x, str) or x not in allowed for x in actual):
                    return "recipient_not_allowed"
        outgoing = list(texts(args))
        if p.get("block_secrets", True) and any(SECRET.search(x) for x in outgoing):
            return "secret_in_arguments"
        if not matches(name, p.get("sensitive_destinations", [])):
            if self.saturated:
                return "sensitive_tracking_capacity"
            if any(value in text for text in outgoing for value in self.values):
                return "sensitive_data_transfer"
        return None

    def observe(self, name, result):
        sensitive = matches(name, self.policy.get("sensitive_sources", []))
        candidates = set()
        for text in texts(result):
            candidates.update(m.group(0) for m in SECRET.finditer(text))
            if sensitive:
                # Track structured scalar fields and entire text blocks. JSON text
                # is also decoded so a copied field can be detected independently.
                if len(text) >= 12:
                    candidates.add(text)
                try:
                    decoded = json.loads(text)
                    candidates.update(x for x in texts(decoded) if len(x) >= 12)
                except (ValueError, RecursionError):
                    pass
        for value in candidates:
            if value in self.values:
                continue
            if len(self.values) >= 2048 or sum(map(len, self.values)) + len(value) > 2_000_000:
                self.saturated = True
                break
            self.values[value] = name
        return len(candidates), self.saturated
