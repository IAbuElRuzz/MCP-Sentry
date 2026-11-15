"""Bounded in-memory reconstruction of fragments across dispatched calls."""

from collections import deque
import base64
import binascii
import fnmatch
import html
import re
from urllib.parse import unquote

from .dlp import TOKENS, PRIVATE_KEY, EMAIL, PHONE, CARD, IBAN, IBAN_GROUPED, SSN, AUTH, URL_AUTH, ASSIGNMENT, canonical, normalize, luhn, iban_checksum


def validate(config):
    if not isinstance(config, dict) or set(config) - {"enabled", "window_seconds", "max_calls", "scope"}:
        raise ValueError("Invalid cross_call configuration")
    if not isinstance(config.get("enabled", True), bool):
        raise ValueError("cross_call.enabled must be boolean")
    if type(config.get("max_calls", 16)) is not int or not 2 <= config.get("max_calls", 16) <= 64:
        raise ValueError("cross_call.max_calls must be between 2 and 64")
    seconds = config.get("window_seconds", 120)
    if type(seconds) not in (int, float) or not 1 <= seconds <= 3600:
        raise ValueError("cross_call.window_seconds must be between 1 and 3600")
    if config.get("scope", "session") not in ("session", "server"):
        raise ValueError("cross_call.scope must be session or server")


def variants(text):
    """A raw channel and one independently decoded readable channel."""
    result = {"raw": normalize(text).casefold()}
    decoded = html.unescape(unquote(text, errors="replace"))
    if decoded == text:
        for encoding in ("hex", "base64"):
            try:
                if encoding == "hex" and re.fullmatch(r"(?:[a-fA-F0-9]{2}){3,}", text):
                    candidate = bytes.fromhex(text).decode("utf-8")
                elif encoding == "base64" and re.fullmatch(r"[A-Za-z0-9+/_-]{4,}={0,2}", text):
                    candidate = base64.b64decode(text.replace("-", "+").replace("_", "/") + "=" * (-len(text) % 4), validate=True).decode("utf-8")
                else:
                    continue
                if all(c.isprintable() or c.isspace() for c in candidate):
                    decoded = candidate
                    break
            except (ValueError, UnicodeError, binascii.Error):
                pass
    if decoded != text and all(c.isprintable() or c.isspace() for c in decoded):
        result["decoded"] = normalize(decoded).casefold()
    result.setdefault("decoded", result["raw"])
    return result


def channels(arguments, excluded=()):
    output, aggregate, nodes, size = {}, {"raw": [], "decoded": []}, 0, 0

    def walk(value, path="", depth=0):
        nonlocal nodes, size
        nodes += 1
        if nodes > 4096 or depth > 32:
            raise ValueError("cross_call_capacity")
        if path in excluded:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                # Key fragments are a separate channel and are never logged.
                store(key, "/@keys")
                walk(child, path + "/" + key.replace("~", "~0").replace("/", "~1"), depth + 1)
        elif isinstance(value, list):
            for child in value:
                walk(child, path + "/[]", depth + 1)
        elif isinstance(value, str) or type(value) in (int, float):
            store(str(value), path)

    def store(text, path):
        nonlocal size
        values = variants(text)
        for kind, text in values.items():
            size += len(text)
            if size > 65536 or len(output) >= 128 and (path, kind) not in output:
                raise ValueError("cross_call_capacity")
            output[(path, kind)] = output.get((path, kind), "") + text
        if path != "/@keys":
            aggregate["raw"].append(values["raw"])
            aggregate["decoded"].append(values.get("decoded", values["raw"]))

    walk(arguments)
    for kind, fragments in aggregate.items():
        output[("/@values", kind)] = "".join(fragments)
    if sum(map(len, output.values())) > 131072:
        raise ValueError("cross_call_capacity")
    return output


def valid_ssn(value):
    area, group, serial = map(int, value.split("-"))
    return 0 < area < 900 and area != 666 and group != 0 and serial != 0


class LeakWindow:
    def __init__(self, config, clock):
        self.config, self.clock = config, clock
        self.history = {}
        self.untracked_until = 0
        self.matched = None
        self.destinations = {}

    def destination(self, tool):
        return self.destinations.get(tool, tool.split("__", 1)[0]) if self.config.get("scope", "session") == "server" else "session"

    def purge(self):
        cutoff = self.clock() - self.config.get("window_seconds", 120)
        for key in list(self.history):
            entries = self.history[key]
            while entries and entries[0][0] <= cutoff:
                entries.popleft()
            if not entries:
                del self.history[key]

    def inspect(self, tool, arguments, tracked, inspector, excluded=()):
        self.matched = None
        self.purge()
        if self.untracked_until > self.clock():
            return "cross_call_tracking_capacity"
        try:
            current = channels(arguments, excluded)
        except (ValueError, RecursionError):
            return "cross_call_tracking_capacity"
        entries = self.history.get(self.destination(tool), ())
        if self.destination(tool) not in self.history and len(self.history) >= 32:
            return "cross_call_tracking_capacity"
        projected = sum(len(v) for queue in self.history.values() for _, values in queue for v in values.values()) + sum(map(len, current.values()))
        if projected > 2_000_000:
            return "cross_call_tracking_capacity"
        known = [("".join(canonical(value).split()), "tracked_data") for value in tracked if len(canonical(value)) >= 12]
        categories = inspector.categories if inspector else set()
        comparisons = 0
        if inspector and "custom" in categories:
            known.extend(("".join(term.split()), "custom") for term in inspector.custom_terms)
        for (path, kind), fragment in current.items():
            if not fragment:
                continue
            previous = "".join(values.get((path, kind), "") for _, values in entries)
            if not previous:
                continue
            combined, boundary = previous + fragment, len(previous)
            compact = "".join(combined.split())
            compact_boundary = len("".join(previous.split()))
            for value, category in known:
                if category == "custom" and any(fnmatch.fnmatchcase(tool, r["tool"]) and r["path"] == path and "custom" in r["categories"] for r in inspector.config.get("allow_rules", [])):
                    continue
                start = compact.find(value)
                while start >= 0:
                    if start < compact_boundary < start + len(value):
                        self.matched = (category, path)
                        return "cross_call_sensitive_transfer"
                    start = compact.find(value, start + 1)
                # Keep multiple prefix positions so unrelated calls in this
                # channel do not erase an earlier exact fragment sequence.
                progress = {0}
                for _, values in entries:
                    piece = "".join(values.get((path, kind), "").split())
                    if piece:
                        comparisons += len(progress)
                        if comparisons > 200000:
                            return "cross_call_tracking_capacity"
                        progress |= {position + len(piece) for position in tuple(progress) if position + len(piece) < len(value) and value.startswith(piece, position)}
                        if len(progress) > 128:
                            return "cross_call_tracking_capacity"
                current = "".join(fragment.split())
                if any(position > 0 and current.startswith(value[position:]) for position in progress):
                    self.matched = (category, path)
                    return "cross_call_sensitive_transfer"
            patterns = [("credentials", p, None) for p in (TOKENS, AUTH, URL_AUTH, ASSIGNMENT)]
            patterns += [("private_key", PRIVATE_KEY, None), ("email", EMAIL, None), ("phone", PHONE, None), ("payment_card", CARD, luhn), ("iban", IBAN, iban_checksum), ("iban", IBAN_GROUPED, iban_checksum), ("national_id", SSN, valid_ssn)]
            for category, pattern, validator in patterns:
                if category not in categories:
                    continue
                if inspector and any(fnmatch.fnmatchcase(tool, r["tool"]) and r["path"] == path and category in r["categories"] for r in inspector.config.get("allow_rules", [])):
                    continue
                pattern = re.compile(pattern.pattern, pattern.flags | re.I)
                # Complete findings in the current call already go through the
                # normal DLP/approval path; do not turn an approved whole value
                # into a spurious reconstruction finding on its next retry.
                if any(validator is None or validator(m.group(0)) for m in pattern.finditer(fragment)):
                    continue
                for match in pattern.finditer(combined):
                    if match.start() < boundary < match.end() and (validator is None or validator(match.group(0))):
                        if any(old.start() == match.start() and old.end() == boundary and (validator is None or validator(old.group(0))) for old in pattern.finditer(previous)):
                            continue
                        self.matched = (category, path)
                        return "cross_call_sensitive_transfer"
        return None

    def record(self, tool, arguments, excluded=()):
        self.purge()
        try:
            values = channels(arguments, excluded)
            size = sum(len(v) for queue in self.history.values() for _, previous in queue for v in previous.values()) + sum(map(len, values.values()))
            if size > 2_000_000:
                raise ValueError("capacity")
        except (ValueError, RecursionError):
            self.untracked_until = self.clock() + self.config.get("window_seconds", 120)
            return
        key = self.destination(tool)
        if key not in self.history and len(self.history) >= 32:
            self.untracked_until = self.clock() + self.config.get("window_seconds", 120)
            return
        queue = self.history.setdefault(key, deque(maxlen=self.config.get("max_calls", 16)))
        queue.append((self.clock(), values))
