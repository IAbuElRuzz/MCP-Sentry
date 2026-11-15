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

    def events(self, after=0, session=None, decision=None):
        self.db.row_factory = sqlite3.Row
        where, params = ["id > ?"], [after]
        for field, value in (("session", session), ("decision", decision)):
            if value is not None:
                where.append(field + " = ?")
                params.append(value)
        return [dict(row) for row in self.db.execute("SELECT * FROM events WHERE " + " AND ".join(where) + " ORDER BY id LIMIT 1000", params)]

    def report(self, session=None):
        self.db.row_factory = sqlite3.Row
        where, params = (" WHERE session = ?", (session,)) if session is not None else ("", ())
        # Each metric has one defined event boundary; calls are not double-counted
        # just because they generated both started and finished audit records.
        aggregate = """
            COUNT(*) AS events,
            COALESCE(SUM(event IN ('call_started','call_blocked')),0) AS attempted,
            COALESCE(SUM(event = 'call_started'),0) AS forwarded,
            COALESCE(SUM(event = 'call_blocked'),0) AS blocked_before_dispatch,
            COALESCE(SUM(event = 'call_redacted'),0) AS redacted_calls,
            COALESCE(SUM(event = 'response_blocked' OR (event = 'call_finished' AND decision = 'block')),0) AS responses_blocked,
            COALESCE(SUM(event = 'call_failed'),0) AS failures,
            COALESCE(SUM(event = 'call_finished' AND decision = 'error'),0) AS tool_errors,
            COALESCE(SUM(event = 'call_started' AND decision = 'would_block'),0) AS monitor_violations,
            ROUND(AVG(CASE WHEN event IN ('call_finished','call_failed') THEN duration_ms END),1) AS average_duration_ms,
            MAX(CASE WHEN event IN ('call_finished','call_failed') THEN duration_ms END) AS max_duration_ms
        """
        # A read transaction keeps totals and grouped results consistent while
        # another process is appending events.
        self.db.execute("BEGIN")
        try:
            totals = dict(self.db.execute("SELECT " + aggregate + " FROM events" + where, params).fetchone())
            tools = [dict(row) for row in self.db.execute("SELECT tool," + aggregate + " FROM events" + where + (" AND" if where else " WHERE") + " tool != '' GROUP BY tool ORDER BY attempted DESC,tool LIMIT 501", params)]
            reasons = [dict(row) for row in self.db.execute("SELECT reason, COUNT(*) AS count FROM events" + where + (" AND" if where else " WHERE") + " (decision IN ('block','would_block','alert') OR event = 'call_failed') GROUP BY reason ORDER BY count DESC,reason LIMIT 100", params)]
        finally:
            self.db.rollback()
        return {"session": session, "totals": totals, "tools": tools[:500], "tools_truncated": len(tools) > 500, "findings": reasons}

    def close(self):
        self.db.close()


def display(event):
    # JSON escaping prevents untrusted tool names from injecting terminal controls.
    return json.dumps(event, ensure_ascii=True)
