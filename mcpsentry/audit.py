"""Metadata-only SQLite audit trail. No arguments, responses or backend errors."""

import json
import os
from pathlib import Path
import sqlite3
import time
import uuid


class Audit:
    def __init__(self, directory):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = directory / "audit.sqlite3"
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        os.chmod(self.path, 0o600)
        self.db = sqlite3.connect(self.path)
        self.db.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, timestamp REAL, session TEXT, event TEXT, tool TEXT, decision TEXT, reason TEXT, duration_ms INTEGER)")
        self.db.commit()
        self.session = uuid.uuid4().hex

    def record(self, event, tool="", decision="", reason="", duration_ms=0):
        self.db.execute("INSERT INTO events(timestamp,session,event,tool,decision,reason,duration_ms) VALUES(?,?,?,?,?,?,?)", (time.time(), self.session, event, tool, decision, reason, duration_ms))
        self.db.commit()

    def events(self, after=0):
        self.db.row_factory = sqlite3.Row
        return [dict(row) for row in self.db.execute("SELECT * FROM events WHERE id > ? ORDER BY id LIMIT 1000", (after,))]

    def close(self):
        self.db.close()


def display(event):
    # JSON escaping prevents untrusted tool names from injecting terminal controls.
    return json.dumps(event, ensure_ascii=True)
