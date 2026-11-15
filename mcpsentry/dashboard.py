"""Loopback-only, token-protected, read-only audit dashboard."""
import hmac
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import secrets
import sqlite3
from urllib.parse import parse_qs, urlsplit
from .audit import Audit

ASSETS = Path(__file__).with_name('web')


class Reader:
    report = Audit.report

    def __init__(self, path):
        self.db = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True, timeout=2)
        self.db.execute('PRAGMA query_only=ON')

    def snapshot(self, session=None, decision=None, after=0):
        report = self.report(session)
        self.db.row_factory = sqlite3.Row
        sessions = [dict(r) for r in self.db.execute('SELECT session,MAX(timestamp) AS last_seen,COUNT(*) AS events FROM events GROUP BY session ORDER BY last_seen DESC LIMIT 100')]
        where, params = ['id > ?'], [after]
        if session:
            where.append('session = ?')
            params.append(session)
        if decision:
            where.append('decision = ?')
            params.append(decision)
        events = [dict(r) for r in self.db.execute('SELECT id,timestamp,session,event,tool,decision,reason,duration_ms FROM events WHERE ' + ' AND '.join(where) + ' ORDER BY id DESC LIMIT 200', params)]
        return {'report': report, 'sessions': sessions, 'events': events, 'limit': 200, 'notice': 'Latest 200 matching metadata events. Totals cover the selected session across all decisions.'}


def make_server(state_dir, port=8765, token=None):
    token = token or secrets.token_urlsafe(32)
    path = Path(state_dir).resolve() / 'audit.sqlite3'

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, status, data, content_type='application/json'):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            host = f'127.0.0.1:{self.server.server_port}'
            if self.headers.get('Host') != host or self.headers.get('Origin') not in (None, 'http://' + host):
                self.send(403, b'{"error":"Forbidden host or origin"}')
                return
            parsed = urlsplit(self.path)
            assets = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8')}
            if parsed.path in assets:
                name, mime = assets[parsed.path]
                self.send(200, (ASSETS / name).read_bytes(), mime)
                return
            if parsed.path != '/api/activity':
                self.send(404, b'{"error":"Not found"}')
                return
            if not hmac.compare_digest(self.headers.get('Authorization', '').encode('utf-8'), ('Bearer ' + token).encode('utf-8')):
                self.send(401, b'{"error":"Dashboard token required"}')
                return
            try:
                query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=8)
                if set(query) - {'session', 'decision', 'after'} or any(len(v) != 1 for v in query.values()):
                    raise ValueError()
                session = query.get('session', [None])[0] or None
                decision = query.get('decision', [None])[0] or None
                if session is not None and (len(session) > 64 or not session.isalnum()):
                    raise ValueError()
                if decision not in (None, 'allow', 'block', 'would_block', 'alert', 'error', 'enforce', 'monitor'):
                    raise ValueError()
                after = int(query.get('after', ['0'])[0])
                if not 0 <= after <= 2**63 - 1:
                    raise ValueError()
                if not path.is_file():
                    data = {'empty': True, 'sessions': [], 'events': [], 'notice': 'No audit database yet. Run MCP-Sentry using this state directory.'}
                else:
                    reader = Reader(path)
                    try:
                        data = reader.snapshot(session, decision, after)
                    finally:
                        reader.db.close()
                self.send(200, json.dumps(data, ensure_ascii=True).encode())
            except (ValueError, OverflowError):
                self.send(400, b'{"error":"Invalid filter"}')
            except (sqlite3.Error, OSError):
                self.send(503, b'{"error":"Audit database unavailable; check the state directory"}')

    return HTTPServer(('127.0.0.1', port), Handler), token


def run(state_dir, port=8765):
    try:
        server, token = make_server(state_dir, port)
    except OSError:
        raise ValueError('Cannot bind the dashboard to loopback; check port availability and local network permissions') from None
    print(f'MCP-Sentry dashboard: http://127.0.0.1:{server.server_port}/#token={token}', flush=True)
    print('Read-only local dashboard. Keep this URL private. Press Ctrl+C to stop.', flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
