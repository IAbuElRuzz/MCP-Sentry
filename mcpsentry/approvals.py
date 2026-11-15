"""Single-use grants bound to session, configuration, tool definition and args.

Raw arguments are never persisted. HMAC prevents offline guessing of argument
values from a stored commitment. The local operator must provide the exact
request file, review it, then explicitly confirm its review code.
"""

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
import uuid
from .dlp import CATEGORIES

OVERRIDABLE = {"sensitive_data:*", "sensitive_data_transfer", "secret_in_arguments", "recipient_not_allowed"}


def validate(config):
    if not isinstance(config, dict) or set(config) - {"enabled", "ttl_seconds", "reasons", "tools"}:
        raise ValueError("Invalid approval configuration")
    if not isinstance(config.get("enabled", False), bool):
        raise ValueError("approvals.enabled must be boolean")
    tools = config.get("tools", [])
    if not isinstance(tools, list) or len(tools) > 128 or any(not isinstance(t, str) or not 1 <= len(t) <= 128 for t in tools):
        raise ValueError("approvals.tools must contain bounded tool-name patterns")
    ttl = config.get("ttl_seconds", 120)
    if type(ttl) is not int or not 10 <= ttl <= 600:
        raise ValueError("Approval ttl_seconds must be between 10 and 600")
    reasons = config.get("reasons", ["sensitive_data:*", "sensitive_data_transfer"])
    allowed = OVERRIDABLE | {"sensitive_data:" + c for c in CATEGORIES - {"opaque_payload"}}
    if not isinstance(reasons, list) or not reasons or any(not isinstance(x, str) or x not in allowed for x in reasons):
        raise ValueError("Approvals may override only explicitly supported transfer reasons")


class Approvals:
    def __init__(self, directory):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o022:
            raise ValueError("Approval state directory must be owned by this user and not writable by other users")
        key_path = directory / "approval.key"
        try:
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(secrets.token_bytes(32))
        if key_path.is_symlink() or key_path.stat().st_mode & 0o077:
            raise ValueError("Approval key must be an owner-only regular file")
        self.key = key_path.read_bytes()
        if len(self.key) != 32:
            raise ValueError("Invalid approval key")
        path = directory / "approvals.sqlite3"
        if path.is_symlink():
            raise ValueError("Approval database must not be a symlink")
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)
        self.db = sqlite3.connect(path, timeout=3)
        self.db.row_factory = sqlite3.Row
        self.db.execute("CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, session TEXT, tool TEXT, config_hash TEXT, tool_hash TEXT, reasons TEXT, commitment TEXT, expires REAL, status TEXT)")
        self.db.commit()

    def commitment(self, binding, request):
        raw = json.dumps({"binding": binding, "request": request}, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
        return hmac.new(self.key, raw, hashlib.sha256).hexdigest()

    def claim_or_request(self, session, tool, config_hash, tool_hash, reasons, arguments, ttl):
        binding = {"session": session, "tool": tool, "config_hash": config_hash, "tool_hash": tool_hash, "reasons": sorted(reasons)}
        commitment = self.commitment(binding, {"name": tool, "arguments": arguments})
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT * FROM grants WHERE commitment=? AND expires>? AND status IN ('pending','approved','denied') ORDER BY expires DESC LIMIT 1", (commitment, time.time())).fetchone()
            if row is not None:
                if row["status"] == "approved":
                    self.db.execute("UPDATE grants SET status='consumed' WHERE id=? AND status='approved'", (row["id"],))
                    self.db.commit()
                    return "consumed", row["id"]
                self.db.commit()
                return row["status"], row["id"]
            count = self.db.execute("SELECT COUNT(*) FROM grants WHERE status IN ('pending','approved') AND expires>?", (time.time(),)).fetchone()[0]
            if count >= 256:
                self.db.rollback()
                return "queue_full", None
            identifier = uuid.uuid4().hex
            self.db.execute("INSERT INTO grants VALUES(?,?,?,?,?,?,?,?,?)", (identifier, session, tool, config_hash, tool_hash, json.dumps(sorted(reasons)), commitment, time.time() + ttl, "pending"))
            self.db.commit()
            return "pending", identifier
        except BaseException:
            self.db.rollback()
            raise

    def listing(self):
        return [dict(r) for r in self.db.execute("SELECT id,session,tool,reasons,expires,status FROM grants WHERE expires>? ORDER BY expires LIMIT 256", (time.time(),))]

    def verified(self, identifier, request):
        row = self.db.execute("SELECT * FROM grants WHERE id=?", (identifier,)).fetchone()
        if row is None or row["expires"] <= time.time() or row["status"] != "pending":
            raise ValueError("Approval is missing, expired or no longer pending")
        binding = {k: row[k] for k in ("session", "tool", "config_hash", "tool_hash")}
        binding["reasons"] = json.loads(row["reasons"])
        if not hmac.compare_digest(self.commitment(binding, request), row["commitment"]):
            raise ValueError("Request does not match this approval exactly")
        code = hmac.new(self.key, (identifier + row["commitment"]).encode(), hashlib.sha256).hexdigest()[:16]
        return row, code

    def approve(self, identifier, request, confirmation):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            _, code = self.verified(identifier, request)
            if not hmac.compare_digest(code, confirmation):
                raise ValueError("Confirmation does not match the reviewed request")
            self.db.execute("UPDATE grants SET status='approved' WHERE id=? AND status='pending'", (identifier,))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def deny(self, identifier):
        self.db.execute("UPDATE grants SET status='denied' WHERE id=? AND status IN ('pending','approved')", (identifier,))
        self.db.commit()

    def close(self):
        self.db.close()
