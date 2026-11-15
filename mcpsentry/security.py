"""Deterministic rules and bounded, session-local sensitive-value tracking."""

import fnmatch
import hashlib
import json
import re
import time
from collections import deque
from dataclasses import replace
from .dlp import LEGACY_SECRET as SECRET, OutboundInspector, canonical
from .leaks import LeakWindow
from .redaction import candidate as redact_candidate

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


def texts(value, include_keys=False):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if include_keys:
                yield key
            yield from texts(item, include_keys)
    elif isinstance(value, list):
        for item in value:
            yield from texts(item, include_keys)


def poisoned(tool):
    return any(rule.search(encode(tool)) for rule in POISON)


MISSING = object()


def at_pointer(value, pointer):
    for part in pointer[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict):
            value = value.get(part, MISSING)
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", part):
            index = int(part)
            value = value[index] if index < len(value) else MISSING
        else:
            return MISSING
    return value


def satisfies(value, rule):
    if value is MISSING:
        return not rule.get("required", True)
    types = {"string": lambda v: isinstance(v, str), "number": lambda v: type(v) in (int, float), "integer": lambda v: type(v) is int,
             "boolean": lambda v: type(v) is bool, "array": lambda v: isinstance(v, list), "object": lambda v: isinstance(v, dict), "null": lambda v: v is None}
    if "type" in rule and not types[rule["type"]](value):
        return False
    # Canonical JSON equality keeps true distinct from 1, including inside arrays.
    if "enum" in rule and not any(encode(value) == encode(item) for item in rule["enum"]):
        return False
    if "minimum" in rule or "maximum" in rule:
        if type(value) not in (int, float):
            return False
        if "minimum" in rule and value < rule["minimum"] or "maximum" in rule and value > rule["maximum"]:
            return False
    if "max_length" in rule and (not isinstance(value, (str, list, dict)) or len(value) > rule["max_length"]):
        return False
    return True


class Guard:
    def __init__(self, policy, clock=time.monotonic):
        self.policy = policy
        self.values = {}  # Raw values stay in process memory; never persisted.
        self.saturated = False
        self.clock = clock
        self.dispatches = {pattern: deque(maxlen=rule["max_calls"]) for pattern, rule in policy.get("call_limits", {}).items()}
        dlp = policy.get("dlp", {})
        self.inspector = OutboundInspector(dlp, policy.get("block_secrets", True)) if dlp.get("enabled", True) else None
        self.window = LeakWindow(policy.get("cross_call", {}), clock) if policy.get("cross_call", {}).get("enabled", True) else None
        self.last_inspection = None
        self.recipient_fields = ()

    def prepare_call(self, name, args):
        original, changed = args, set()
        reasons = self.inspect_reasons(name, args)
        original_reasons, original_inspection, original_recipients = list(reasons), self.last_inspection, self.recipient_fields
        config = self.policy.get("redaction", {})
        if not config.get("enabled", False) or not reasons:
            return args, reasons, 0
        for _ in range(2):
            eligible = reasons and all(r in {"secret_in_arguments", "sensitive_data_transfer", "cross_call_sensitive_transfer"} or r.startswith("sensitive_data:") and r != "sensitive_data:opaque_payload" for r in reasons)
            if not config.get("enabled", False) or not eligible or self.last_inspection is None:
                break
            rewritten, paths = redact_candidate(args, name, config, self.last_inspection)
            if not paths:
                break
            remaining = self.inspect_reasons(name, rewritten)
            changed.update(paths)
            args, reasons = rewritten, remaining
            if not reasons:
                return args, reasons, len(changed)
        # Never forward a partly sanitized request that still violates policy.
        self.last_inspection, self.recipient_fields = original_inspection, original_recipients
        return original, original_reasons, 0

    def inspect_call(self, name, args):
        reasons = self.inspect_reasons(name, args)
        return reasons[0] if reasons else None

    def inspect_reasons(self, name, args):
        p = self.policy
        self.last_inspection = None
        self.recipient_fields = ()
        reasons = []
        if matches(name, p.get("deny", [])):
            return ["tool_denied"]
        if p.get("default", "deny") == "deny" and not matches(name, p.get("allow", [])):
            return ["tool_not_allowed"]
        for pattern, fields in p.get("argument_constraints", {}).items():
            if fnmatch.fnmatchcase(name, pattern):
                if any(not satisfies(at_pointer(args, pointer), rule) for pointer, rule in fields.items()):
                    reasons.append("argument_constraint")
        for pattern, rule in p.get("call_limits", {}).items():
            if fnmatch.fnmatchcase(name, pattern):
                entries = self.dispatches[pattern]
                while entries and entries[0] <= self.clock() - rule["window_seconds"]:
                    entries.popleft()
                if len(entries) >= rule["max_calls"]:
                    reasons.append("call_limit_exceeded")
        recipient_fields = []
        for pattern, fields in p.get("recipient_allowlists", {}).items():
            if not fnmatch.fnmatchcase(name, pattern):
                continue
            for field, allowed in fields.items():
                value = args.get(field)
                actual = value if isinstance(value, list) else [value]
                if not actual or any(not isinstance(x, str) or x not in allowed for x in actual):
                    reasons.append("recipient_not_allowed")
                    continue
                if isinstance(value, list):
                    recipient_fields.append("/" + field.replace("~", "~0").replace("/", "~1"))
                    recipient_fields.extend("/" + field.replace("~", "~0").replace("/", "~1") + "/" + str(index) for index in range(len(value)))
                else:
                    recipient_fields.append("/" + field.replace("~", "~0").replace("/", "~1"))
        outgoing = list(texts(args, include_keys=True))
        self.recipient_fields = tuple(recipient_fields)
        trusted = matches(name, p.get("sensitive_destinations", []))
        if not trusted:
            if self.saturated:
                reasons.append("sensitive_tracking_capacity")
        if self.inspector is not None:
            inspection = self.inspector.inspect(name, args, () if trusted else self.values, recipient_fields)
            self.last_inspection = inspection
            if inspection.limit_exceeded:
                reasons.append("dlp_inspection_limit")
            if inspection.semantic_error:
                reasons.append("semantic_inspection_failed")
            if {"credentials", "private_key"} & set(inspection.categories):
                reasons.append("secret_in_arguments")
            if inspection.tracked_transfer:
                reasons.append("sensitive_data_transfer")
            reasons.extend("sensitive_data:" + category for category in inspection.categories if category not in {"credentials", "private_key"})
        else:
            if p.get("block_secrets", True) and any(SECRET.search(x) for x in outgoing):
                reasons.append("secret_in_arguments")
            if not trusted and any(value in canonical(text) for text in outgoing for value in self.values):
                reasons.append("sensitive_data_transfer")
        if self.window is not None:
            reason = self.window.inspect(name, args, () if trusted else self.values, self.inspector, recipient_fields)
            if reason:
                reasons.append(reason)
                if self.last_inspection is not None and self.window.matched:
                    category, path = self.window.matched
                    if category == "tracked_data":
                        self.last_inspection = replace(self.last_inspection, transfer_paths=(*self.last_inspection.transfer_paths, path))
                    else:
                        self.last_inspection = replace(self.last_inspection, locations=(*self.last_inspection.locations, (category, path)))
        return list(dict.fromkeys(reasons))

    def record_dispatch(self, name, arguments=None):
        for pattern, entries in self.dispatches.items():
            if fnmatch.fnmatchcase(name, pattern):
                entries.append(self.clock())
        if self.window is not None and arguments is not None:
            self.window.record(name, arguments, self.recipient_fields)

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
            value = canonical(value)
            if value in self.values:
                continue
            if len(self.values) >= 2048 or sum(map(len, self.values)) + len(value) > 2_000_000:
                self.saturated = True
                break
            self.values[value] = name
        return len(candidates), self.saturated
