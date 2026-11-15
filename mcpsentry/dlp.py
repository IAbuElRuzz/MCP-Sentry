"""Bounded outbound data inspection. Findings never contain matched content.

This is deterministic DLP, not a semantic classifier. Decoders operate only on
inline arguments; they never open paths, fetch URLs, or execute content.
"""

import base64
import binascii
from collections import deque
from dataclasses import dataclass, field
import fnmatch
import html
import io
import json
import os
import re
import unicodedata
from urllib.parse import unquote
import zipfile
import zlib
from .documents import kind as document_kind, extract as extract_document
from .semantic import validate as validate_semantic, context_categories, classify as classify_semantic


CATEGORIES = frozenset({"credentials", "private_key", "payment_card", "iban", "national_id", "email", "phone", "sensitive_field", "custom", "opaque_payload", "confidential_text", "health_information", "personal_information"})
LEGACY_SECRET = re.compile(r"(?:sk-(?:proj-)?[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,}|SENTRY_FAKE_SECRET_[A-Za-z0-9_-]{8,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)")
TOKENS = re.compile(r"(?:sk-(?:proj-)?[A-Za-z0-9_-]{16,}|(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{16,}|(?:sk|rk)_live_[A-Za-z0-9]{16,}|AIza[A-Za-z0-9_-]{35}|SENTRY_FAKE_SECRET_[A-Za-z0-9_-]{8,})")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----")
ASSIGNMENT = re.compile(r"\b(?:password|passwd|pwd|api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token)\s*[:=]\s*[\"']?[^\s\"',;}{]{4,}", re.I)
AUTH = re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9+/_=.-]{8,}", re.I)
URL_AUTH = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@", re.I)
EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\.[A-Za-z]{2,63}(?![\w.-])")
PHONE = re.compile(r"(?<![\w+])\+[1-9](?:[ .()\-]*[0-9]){7,14}(?![0-9])")
CARD = re.compile(r"(?<![0-9])(?:[0-9][ -]?){12,18}[0-9](?![0-9])")
SSN = re.compile(r"(?<![0-9])([0-9]{3})-([0-9]{2})-([0-9]{4})(?![0-9])")
IBAN = re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b", re.I)
IBAN_GROUPED = re.compile(r"\b[A-Z]{2}[0-9]{2}(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?\b", re.I)
B64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{4,}={0,2}(?![A-Za-z0-9+/_=-])")
HEX = re.compile(r"(?<![A-Za-z0-9])(?:[A-Fa-f0-9]{2}){3,}(?![A-Za-z0-9])")
DATA_URI = re.compile(r"data:[^\s,]{0,200};base64,([A-Za-z0-9+/_=-]+)", re.I)
JWT = re.compile(r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})(?![A-Za-z0-9_-])")
ESCAPE = re.compile(r"\\u([a-fA-F0-9]{4})|\\x([a-fA-F0-9]{2})")
SECRET_FIELDS = frozenset({"password", "passwd", "pwd", "passwordhash", "secret", "secretkey", "apikey", "apisecret", "apitoken", "token", "auth", "accesskey", "awsaccesskeyid", "awssecretaccesskey", "accesstoken", "refreshtoken", "clientsecret", "sessiontoken", "authorization", "authentication", "credentials", "privatekey", "cookie", "setcookie", "connectionstring"})
PERSONAL_FIELDS = frozenset({"fullname", "firstname", "lastname", "customername", "patientname", "employeename", "dateofbirth", "birthdate", "dob", "postaladdress", "homeaddress", "streetaddress", "passport", "passportnumber", "nationalid", "socialsecuritynumber", "ssn", "taxid", "fiscalcode", "codicefiscale", "accountnumber", "routingnumber", "medicalrecord", "medicalrecords", "diagnosis", "patientrecord", "healthrecord"})
LABELED_PII = {"email": "email", "emailaddress": "email", "phone": "phone", "phonenumber": "phone", "mobile": "phone", "mobilenumber": "phone", "telephone": "phone", "telephonenumber": "phone", "cardnumber": "payment_card", "creditcardnumber": "payment_card", "cvv": "payment_card", "cvc": "payment_card", "iban": "iban", "ssn": "national_id"}
ENCODED_FIELDS = frozenset({"base64", "contentbase64", "filebase64", "attachmentbase64", "bytes", "binary", "attachmentdata"})
FILE_FIELDS = frozenset({"filepath", "attachmentpath", "uploadpath", "fileuri", "attachmenturi"})
MAX_BYTES = 1_048_576


def validate_config(config):
    allowed = {"enabled", "block_categories", "custom_terms", "custom_terms_env", "sensitive_fields", "allow_rules", "semantic"}
    if not isinstance(config, dict) or set(config) - allowed:
        raise ValueError("Invalid or unknown DLP configuration keys")
    if not isinstance(config.get("enabled", True), bool):
        raise ValueError("dlp.enabled must be boolean")
    validate_semantic(config.get("semantic", {}))
    categories = config.get("block_categories", list(CATEGORIES))
    if not isinstance(categories, list) or any(not isinstance(x, str) or x not in CATEGORIES for x in categories):
        raise ValueError("Unknown DLP block category")
    for key in ("custom_terms", "custom_terms_env", "sensitive_fields"):
        values = config.get(key, [])
        if not isinstance(values, list) or len(values) > 128 or any(not isinstance(x, str) or not x or len(x) > 4096 for x in values):
            raise ValueError(f"dlp.{key} must be a list of at most 128 nonempty bounded strings")
    if any(len(canonical(x)) < 3 for x in config.get("custom_terms", [])):
        raise ValueError("Custom DLP terms require at least three normalized characters")
    if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", x) for x in config.get("custom_terms_env", [])):
        raise ValueError("Invalid custom DLP term environment variable name")
    rules = config.get("allow_rules", [])
    if not isinstance(rules, list) or len(rules) > 128:
        raise ValueError("dlp.allow_rules must contain at most 128 rules")
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {"tool", "path", "categories"}:
            raise ValueError("DLP allow rules require tool, path, and categories")
        if not isinstance(rule["tool"], str) or not 1 <= len(rule["tool"]) <= 128:
            raise ValueError("DLP allow rules require a bounded tool pattern")
        pointer = rule["path"]
        if not isinstance(pointer, str) or not pointer.startswith("/") or len(pointer) > 2048 or re.search(r"~(?![01])", pointer):
            raise ValueError("DLP allow-rule paths must be exact non-root JSON pointers")
        if not isinstance(rule["categories"], list) or not rule["categories"] or any(not isinstance(x, str) or x not in CATEGORIES for x in rule["categories"]):
            raise ValueError("DLP allow rules contain unknown categories")


def normalize(text):
    return "".join(str(unicodedata.decimal(c)) if unicodedata.category(c) == "Nd" else c for c in unicodedata.normalize("NFKC", text) if unicodedata.category(c) != "Cf")


def canonical(text):
    return " ".join(normalize(text).casefold().split())


def field_name(text):
    return re.sub(r"[^a-z0-9]", "", normalize(text).casefold())


def luhn(value):
    digits = re.sub(r"[ -]", "", value)
    if not 13 <= len(digits) <= 19 or len(set(digits)) < 2:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        n = int(char)
        if index % 2:
            n = n * 2
            n = n - 9 if n > 9 else n
        total += n
    return total % 10 == 0


def iban_checksum(value):
    value = value.replace(" ", "").upper()
    if not 15 <= len(value) <= 34 or not re.fullmatch(r"[A-Z]{2}[0-9]{2}[A-Z0-9]+", value):
        return False
    rem = 0
    for char in value[4:] + value[:4]:
        for digit in str(ord(char) - 55) if char.isalpha() else char:
            rem = (rem * 10 + int(digit)) % 97
    return rem == 1


def b64decode(value):
    value = value.replace("-", "+").replace("_", "/")
    return base64.b64decode(value + "=" * (-len(value) % 4), validate=True)


@dataclass(frozen=True)
class Inspection:
    categories: tuple[str, ...]
    tracked_transfer: bool = False
    limit_exceeded: bool = False
    semantic_error: bool = False
    locations: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    transfer_paths: tuple[str, ...] = field(default=(), repr=False)


class OutboundInspector:
    def __init__(self, config, block_secrets=True):
        self.config = config
        self.categories = set(config.get("block_categories", CATEGORIES))
        if not block_secrets:
            self.categories -= {"credentials", "private_key"}
        self.custom_terms = [canonical(term) for term in config.get("custom_terms", [])]
        for variable in config.get("custom_terms_env", []):
            term = os.environ.get(variable)
            if not term or not 3 <= len(canonical(term)) <= 4096:
                raise ValueError("Missing or invalid custom DLP term environment variable")
            self.custom_terms.append(canonical(term))
        self.fields = PERSONAL_FIELDS | {field_name(x) for x in config.get("sensitive_fields", [])}

    def inspect(self, tool, arguments, tracked=(), recipient_fields=()):
        context = _Context(self, tool, tracked, recipient_fields)
        context.walk(arguments, "", 0, 0)
        complete = True
        if self.config.get("semantic", {}).get("mode") == "command":
            categories, complete = classify_semantic(context.semantic_texts, self.config["semantic"])
            # Model classifications are aggregate: no field exception can bless
            # a classifier finding across an entire request.
            for category in categories:
                context.finding(category, "/@semantic")
        return Inspection(tuple(sorted(context.found)), context.transfer, context.limited, not complete, tuple(sorted(context.locations)), tuple(sorted(context.transfer_paths)))


class _Context:
    def __init__(self, inspector, tool, tracked, recipients):
        self.inspector, self.tool = inspector, tool
        self.known = tuple(canonical(value) for value in tracked)
        self.recipients = set(recipients)
        self.found, self.transfer, self.limited = set(), False, False
        self.nodes = self.characters = self.decoded = 0
        self.documents_seen = 0
        self.semantic_texts = []
        self.locations, self.transfer_paths = set(), set()

    def finding(self, category, path):
        if category not in self.inspector.categories:
            return
        if category == "email" and path in self.recipients:
            return
        for rule in self.inspector.config.get("allow_rules", []):
            if fnmatch.fnmatchcase(self.tool, rule["tool"]) and rule["path"] == path and category in rule["categories"]:
                return
        self.found.add(category)
        self.locations.add((category, path))

    def walk(self, value, path, depth, layers):
        self.nodes += 1
        if self.nodes > 20_000 or depth > 32:
            self.limited = True
            return
        if self.limited:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                escaped = key.replace("~", "~0").replace("/", "~1")
                child = path + "/" + escaped
                label = field_name(key)
                if item is not None and item != "" and item != [] and item != {}:
                    if type(item) is not bool and (label in SECRET_FIELDS or label.endswith(("password", "apikey", "accesstoken", "clientsecret", "privatekey", "secretkey"))):
                        self.finding("private_key" if "privatekey" in label else "credentials", child)
                    if label in LABELED_PII:
                        self.finding(LABELED_PII[label], child)
                    if label in self.inspector.fields:
                        self.finding("sensitive_field", child)
                    if label in FILE_FIELDS:
                        self.finding("opaque_payload", child)
                # A key is transmitted too. Its allow-rule path is distinct from
                # its value so approval for /to cannot bless a sensitive key.
                self.text(key, child + "/@key", layers)
                if label in ENCODED_FIELDS and isinstance(item, str) and item:
                    self.explicit_binary(item, child, layers)
                elif label in ENCODED_FIELDS and isinstance(item, list) and item and all(type(x) is int and 0 <= x <= 255 for x in item):
                    self.payload(bytes(item), child, layers, explicit=True)
                self.walk(item, child, depth + 1, layers)
        elif isinstance(value, list):
            if 8 <= len(value) <= MAX_BYTES and all(type(x) is int and 0 <= x <= 255 for x in value):
                raw = bytes(value)
                if self.readable(raw):
                    self.payload(raw, path, layers, explicit=False)
                if len(value) <= 19 and all(x <= 9 for x in value):
                    self.text("".join(map(str, value)), path, layers)
            for index, item in enumerate(value):
                self.walk(item, path + "/" + str(index), depth + 1, layers)
        elif isinstance(value, str):
            self.text(value, path, layers)
        elif type(value) in (int, float):
            self.text(str(value), path, layers)

    @staticmethod
    def readable(raw):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return not text or sum(c.isprintable() or c in "\r\n\t" for c in text) / len(text) > 0.9

    def explicit_binary(self, text, path, layers):
        if text.startswith("data:") and ";base64," in text[:256]:
            text = text.split(",", 1)[1]
        try:
            raw = b64decode(re.sub(r"\s", "", text))
        except (ValueError, binascii.Error):
            # An explicitly opaque field with invalid encoding is uninspectable.
            self.finding("opaque_payload", path)
            return
        self.payload(raw, path, layers, explicit=True)

    def payload(self, raw, path, layers, explicit=False):
        if layers >= 4:
            self.limited = True
            return
        self.decoded += len(raw)
        if len(raw) > MAX_BYTES or self.decoded > 4 * MAX_BYTES:
            self.limited = True
            return
        doc = document_kind(raw)
        if doc is not None:
            self.documents_seen += 1
            if self.documents_seen > 4:
                self.limited = True
                return
            result = extract_document(raw, doc)
            for text in result["texts"]:
                self.text(text, path, layers + 1)
            if not result["complete"]:
                self.finding("opaque_payload", path)
            return
        if raw.startswith((b"\x1f\x8b", b"x\x9c", b"x\xda", b"x\x01")):
            try:
                decoder = zlib.decompressobj(31 if raw.startswith(b"\x1f\x8b") else 15)
                inflated = decoder.decompress(raw, MAX_BYTES + 1)
                if len(inflated) > MAX_BYTES or decoder.unconsumed_tail:
                    self.limited = True
                    return
                if not decoder.eof or decoder.unused_data:
                    self.finding("opaque_payload", path)
                    return
                self.payload(inflated, path, layers + 1, explicit=True)
            except zlib.error:
                self.finding("opaque_payload", path)
            return
        if raw.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            try:
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    entries = archive.infolist()
                    if len(entries) > 32 or sum(x.file_size for x in entries) > MAX_BYTES:
                        self.limited = True
                        return
                    self.text(archive.comment.decode("utf-8", errors="replace"), path, layers + 1)
                    for entry in entries:
                        # Names can themselves carry sensitive data. No files are
                        # extracted and file names are never used as disk paths.
                        self.text(entry.filename, path, layers + 1)
                        self.text(entry.comment.decode("utf-8", errors="replace"), path, layers + 1)
                        self.text(entry.extra.decode("utf-8", errors="ignore"), path, layers + 1)
                        if not entry.is_dir():
                            with archive.open(entry) as stream:
                                content = stream.read(MAX_BYTES + 1)
                            self.payload(content, path, layers + 1, explicit=True)
            except (ValueError, RuntimeError, OSError, zipfile.BadZipFile, NotImplementedError):
                self.finding("opaque_payload", path)
            return
        if raw.startswith((b"%PDF-", b"\x89PNG", b"\xff\xd8\xff", b"BZh", b"\xfd7zXZ\x00", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")):
            self.finding("opaque_payload", path)
            return
        if self.readable(raw):
            self.text(raw.decode("utf-8"), path, layers + 1)
        elif explicit:
            self.finding("opaque_payload", path)

    def text(self, original, path, layers):
        queue, seen = deque([(original, layers)]), set()
        while queue and not self.limited:
            text, layer = queue.popleft()
            if text in seen:
                continue
            seen.add(text)
            self.characters += len(text)
            if self.characters > 4 * MAX_BYTES:
                self.limited = True
                return
            self.detect(text, path)
            if self.inspector.config.get("semantic", {}).get("mode") == "command":
                self.semantic_texts.append(text)
            normalized = normalize(text)
            compact = canonical(text)
            if any(term and term in compact for term in self.inspector.custom_terms):
                self.finding("custom", path)
            if any(value and value in compact for value in self.known):
                self.transfer = True
                self.transfer_paths.add(path)
            derived = {normalized, html.unescape(normalized)}
            if "%" in normalized:
                try:
                    derived.add(unquote(normalized, errors="strict"))
                except UnicodeError:
                    pass
            if "\\u" in normalized or "\\x" in normalized:
                derived.add(ESCAPE.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)), normalized))
            derived.discard(text)
            for candidate in derived:
                if candidate not in seen:
                    if layer >= 4:
                        self.limited = True
                        return
                    queue.append((candidate, layer + 1))
            if text.lstrip().startswith(("{", "[", '"')):
                try:
                    decoded = json.loads(text)
                    if not isinstance(decoded, str) or decoded != text:
                        if layer >= 4:
                            self.limited = True
                            return
                        self.walk(decoded, path, 0, layer + 1)
                except (ValueError, RecursionError):
                    pass
            for match in B64.finditer(text):
                try:
                    raw = b64decode(match.group(0))
                    self.payload(raw, path, layer, explicit=match.group(0).endswith("=") and len(match.group(0)) >= 16)
                except (ValueError, binascii.Error):
                    pass
            for match in HEX.finditer(text):
                self.payload(bytes.fromhex(match.group(0)), path, layer, explicit=False)
            for match in DATA_URI.finditer(text):
                self.explicit_binary(match.group(0), path, layer)

    def detect(self, text, path):
        if self.inspector.config.get("semantic", {}).get("mode", "context") != "off":
            for category in context_categories(text):
                self.finding(category, path)
        if text.lower().startswith("file://") or text and sum(c.isprintable() or c in "\r\n\t" for c in text) / len(text) < 0.9:
            self.finding("opaque_payload", path)
        if TOKENS.search(text) or ASSIGNMENT.search(text) or AUTH.search(text) or URL_AUTH.search(text):
            self.finding("credentials", path)
        if PRIVATE_KEY.search(text):
            self.finding("private_key", path)
        if EMAIL.search(text):
            self.finding("email", path)
        if PHONE.search(text):
            self.finding("phone", path)
        if any(luhn(m.group(0)) for m in CARD.finditer(text)):
            self.finding("payment_card", path)
        if any(iban_checksum(m.group(0)) for rule in (IBAN, IBAN_GROUPED) for m in rule.finditer(text)):
            self.finding("iban", path)
        for match in SSN.finditer(text):
            area, group, serial = map(int, match.groups())
            if 0 < area < 900 and area != 666 and group and serial:
                self.finding("national_id", path)
        for match in JWT.finditer(text):
            try:
                header, payload = (json.loads(b64decode(match.group(i))) for i in (1, 2))
                if isinstance(header, dict) and "alg" in header and isinstance(payload, dict):
                    self.finding("credentials", path)
            except (ValueError, UnicodeError, binascii.Error, RecursionError):
                pass
