import copy
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from mcpsentry.audit import Audit
from mcpsentry.dashboard import Reader, make_server, ASSETS
from mcpsentry.setup import plan, apply, rollback, target_path
from mcpsentry.cli import demo_config


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / 'gateway.json'
        self.config.write_text(json.dumps(demo_config()))
        self.target = self.root / 'client.json'

    def prepare(self, **kw):
        return plan('cursor', self.config, self.root / 'state', self.target, allow_exec=True, **kw)

    def test_preview_no_write_and_no_secret_output(self):
        self.target.write_text(json.dumps({'mcpServers': {'direct': {'env': {'KEY': 'private-fixture'}}}, 'theme': 'dark'}))
        before = self.target.read_bytes()
        with patch('subprocess.Popen', side_effect=AssertionError('No servers during setup')):
            prepared = self.prepare()
        self.assertEqual(self.target.read_bytes(), before)
        self.assertNotIn('private-fixture', json.dumps(prepared[0]))
        self.assertEqual(prepared[0]['direct_servers_remaining'], ['direct'])
        args = prepared[0]['entry']['args']
        self.assertIn('--allow-exec', args)
        self.assertTrue(Path(args[args.index('--config') + 1]).is_absolute())

    def test_merge_backup_private_and_exact_rollback(self):
        before = b'{"mcpServers":{"direct":{"command":"example"}},"theme":"dark"}\n'
        self.target.write_bytes(before)
        result = apply(self.prepare())
        merged = json.loads(self.target.read_bytes())
        self.assertEqual(merged['theme'], 'dark')
        self.assertIn('direct', merged['mcpServers'])
        self.assertIn('MCP-Sentry', merged['mcpServers'])
        if os.name == 'posix':
            self.assertEqual(Path(result['backup']).stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)
        rollback(result['backup'])
        self.assertEqual(self.target.read_bytes(), before)

    def test_new_file_rollback_and_idempotency(self):
        result = apply(self.prepare())
        self.assertFalse(apply(self.prepare())['applied'])
        rollback(result['backup'])
        self.assertFalse(self.target.exists())

    def test_changed_since_preview_or_apply_refused(self):
        prepared = self.prepare()
        self.target.write_text('{}')
        with self.assertRaises(ValueError):
            apply(prepared)
        result = apply(self.prepare())
        self.target.write_text('{"later":true}')
        with self.assertRaises(ValueError):
            rollback(result['backup'])
        self.assertEqual(json.loads(self.target.read_text()), {'later': True})

    def test_explicit_remove_and_conflicts(self):
        self.target.write_text('{"mcpServers":{"direct":{"command":"example"}}}')
        result = apply(self.prepare(remove=['direct']))
        self.assertEqual(set(json.loads(self.target.read_text())['mcpServers']), {'MCP-Sentry'})
        rollback(result['backup'])
        with self.assertRaises(ValueError):
            self.prepare(remove=['missing'])
        self.target.write_text('{"mcpServers":{"MCP-Sentry":{"command":"other"}}}')
        with self.assertRaises(ValueError):
            self.prepare()

    def test_invalid_json_symlink_and_missing_authorization(self):
        self.target.write_text('{/* comments are unsupported */}')
        with self.assertRaises(ValueError):
            self.prepare()
        self.target.unlink()
        self.target.symlink_to(self.config)
        with self.assertRaises(ValueError):
            self.prepare()
        with self.assertRaises(ValueError):
            plan('cursor', self.config, self.root / 'state', self.target)
        with self.assertRaises(ValueError):
            plan('cursor', self.config, self.root / 'state', self.config, allow_exec=True)

    def test_duplicate_json_and_network_authorization(self):
        self.target.write_text('{"mcpServers":{},"mcpServers":{}}')
        with self.assertRaises(ValueError):
            self.prepare()
        self.target.unlink()
        config = {'servers': {'remote': {'url': 'https://example.com/mcp'}}, 'policy': {'default': 'deny'}}
        self.config.write_text(json.dumps(config))
        with self.assertRaises(ValueError):
            self.prepare()
        prepared = self.prepare(allow_network=True)
        self.assertIn('--allow-network', prepared[0]['entry']['args'])

    def test_generated_launcher_runs_outside_checkout(self):
        entry = self.prepare()[0]['entry']
        process = subprocess.run([entry['command'], *entry['args']], input=b'', stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.root, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stdout, b'')

    def test_cli_preview_apply_and_rollback(self):
        command = [sys.executable, '-m', 'mcpsentry', 'setup', '--client', 'cursor', '--config', str(self.config), '--target', str(self.target), '--allow-exec']
        result = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.target.exists())
        result = subprocess.run([*command, '--apply'], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        backup = next(self.root.glob('client.json.mcpsentry-backup-*.json'))
        result = subprocess.run([sys.executable, '-m', 'mcpsentry', 'setup', '--rollback', str(backup)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.target.exists())


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.audit = Audit(self.temp.name)
        self.addCleanup(self.audit.close)
        self.audit.record('call_started', 'mail__send', 'allow', 'policy_passed')
        self.audit.record('call_finished', 'mail__send', 'allow', 'completed', 12)
        self.audit.record('call_blocked', 'mail__send', 'block', 'cross_call_sensitive_transfer')
        # Capture the HTTP handler without opening a socket; request parsing and
        # response serialization still use the actual BaseHTTPRequestHandler.
        with patch('mcpsentry.dashboard.HTTPServer') as server:
            make_server(self.temp.name, 8765, token='test-private-token')
            self.handler = server.call_args.args[1]

    def request(self, path='/api/activity', token='test-private-token', host='127.0.0.1:8765', origin=None):
        handler = self.handler.__new__(self.handler)
        headers = f'Host: {host}\r\nAuthorization: Bearer {token}\r\n'
        if origin:
            headers += 'Origin: ' + origin + '\r\n'
        handler.rfile = io.BytesIO(f'GET {path} HTTP/1.1\r\n{headers}\r\n'.encode())
        handler.wfile = io.BytesIO()
        handler.client_address = ('127.0.0.1', 1)
        handler.server = type('Server', (), {'server_port': 8765})()
        handler.handle_one_request()
        response = handler.wfile.getvalue()
        header, body = response.split(b'\r\n\r\n', 1)
        return int(header.split()[1]), header, body

    def test_auth_host_origin_and_no_cache(self):
        for kw in ({'token': 'wrong'}, {'host': 'evil.test:8765'}, {'origin': 'https://evil.test'}):
            self.assertIn(self.request(**kw)[0], (401, 403))
        status, headers, raw = self.request()
        self.assertEqual(status, 200)
        self.assertIn(b'Cache-Control: no-store', headers)
        data = json.loads(raw)
        self.assertEqual(data['report']['totals']['forwarded'], 1)
        self.assertEqual(data['report']['totals']['blocked_before_dispatch'], 1)
        self.assertEqual(len(data['events']), 3)

    def test_filters_bounds_and_missing_database(self):
        self.assertEqual(len(json.loads(self.request('/api/activity?decision=block')[2])['events']), 1)
        for path in ('?decision=typo', '?after=-1', '?after=9999999999999999999999', '?unknown=x', '?session=x&session=y'):
            self.assertEqual(self.request('/api/activity' + path)[0], 400)
        self.audit.record('call_blocked', 'other__tool', 'block', 'tool_denied')
        rows = json.loads(self.request('/api/activity?after=3')[2])['events']
        self.assertEqual(len(rows), 1)

    def test_readonly_and_assets_no_remote_dependencies(self):
        reader = Reader(self.audit.path)
        try:
            with self.assertRaises(sqlite3.OperationalError):
                reader.db.execute('DELETE FROM events')
        finally:
            reader.db.close()
        for path in ('/', '/style.css', '/app.js'):
            self.assertEqual(self.request(path)[0], 200)
        self.assertEqual(self.request('/../../setup.py')[0], 404)
        javascript = (ASSETS / 'app.js').read_text()
        self.assertNotIn('innerHTML', javascript)
        self.assertIn('textContent', javascript)
        self.assertIn('history.replaceState', javascript)

    def test_empty_state_and_payload_column_not_exposed(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch('mcpsentry.dashboard.HTTPServer') as server:
                make_server(directory, 8765, token='test-private-token')
                original = self.handler
                self.handler = server.call_args.args[1]
            try:
                self.assertTrue(json.loads(self.request()[2])['empty'])
                self.assertFalse((Path(directory) / 'audit.sqlite3').exists())
            finally:
                self.handler = original
        self.audit.db.execute('ALTER TABLE events ADD COLUMN unsafe_payload TEXT')
        self.audit.db.execute("UPDATE events SET unsafe_payload='private-fixture'")
        self.audit.db.commit()
        self.assertNotIn(b'private-fixture', self.request()[2])

    def test_bound_event_list(self):
        for _ in range(205):
            self.audit.record('catalog_change', 'db__read', 'alert', 'tool_changed:annotations')
        data = json.loads(self.request()[2])
        self.assertEqual(len(data['events']), 200)
        self.assertEqual(data['events'][0]['id'], 208)
