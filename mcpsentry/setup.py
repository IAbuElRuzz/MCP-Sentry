"""Preview-first client setup, private backups and change-aware rollback."""
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import uuid
from .config import load
from .gateway import read_baseline

MAX_CONFIG = 1_000_000


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate JSON keys are not supported')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('Non-finite JSON is not supported')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def target_path(client):
    home = Path.home()
    if client == 'cursor':
        return home / '.cursor/mcp.json'
    if sys.platform == 'darwin':
        return home / 'Library/Application Support/Claude/claude_desktop_config.json'
    if sys.platform == 'win32':
        return Path(os.environ['APPDATA']) / 'Claude/claude_desktop_config.json'
    return home / '.config/Claude/claude_desktop_config.json'


def read(path, limit=MAX_CONFIG):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Setup refuses symbolic-link files')
    if not path.exists():
        return None
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('Client configuration exceeds size limit')
    return raw


def atomic(path, raw):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(prefix='.mcpsentry-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def plan(client, config_path, state_dir, target=None, allow_exec=False, allow_network=False, baseline=None, remove=()):
    config_path = Path(config_path).expanduser().resolve()
    config = load(config_path)
    if any('url' not in s for s in config['servers'].values()) and not allow_exec:
        raise ValueError('Review server commands and pass --allow-exec to authorize future client launches')
    if any('url' in s for s in config['servers'].values()) and not allow_network:
        raise ValueError('Review server URLs and pass --allow-network to authorize future client launches')
    state = Path(state_dir).expanduser().resolve()
    args = ['-m', 'mcpsentry', 'run', '--config', str(config_path), '--state-dir', str(state)]
    # An absolute packaged launcher works even when the client changes cwd.
    launcher = Path(__file__).resolve().with_name('client_launcher.py')
    args = [str(launcher), *args[2:]]
    if allow_exec:
        args.append('--allow-exec')
    if allow_network:
        args.append('--allow-network')
    if baseline:
        baseline = str(Path(baseline).expanduser().resolve())
        read_baseline(baseline)
        args.extend(['--baseline', baseline])
    entry = {'command': sys.executable, 'args': args}
    target = Path(target).expanduser().absolute() if target else target_path(client)
    if target.resolve() == config_path:
        raise ValueError('Client target cannot overwrite the gateway configuration')
    original = read(target)
    try:
        document = strict_json(original) if original is not None else {}
    except (ValueError, UnicodeError):
        raise ValueError('Client configuration must be strict JSON; no changes made') from None
    if not isinstance(document, dict) or not isinstance(document.get('mcpServers', {}), dict):
        raise ValueError('Client configuration requires an mcpServers object')
    servers = document.setdefault('mcpServers', {})
    if 'MCP-Sentry' in servers and servers['MCP-Sentry'] != entry:
        raise ValueError('MCP-Sentry entry already exists with different settings; roll back or edit it first')
    if any(name == 'MCP-Sentry' or name not in servers for name in remove):
        raise ValueError('Only existing direct server names can be removed')
    for name in remove:
        del servers[name]
    direct = [name for name in servers if name != 'MCP-Sentry']
    servers['MCP-Sentry'] = entry
    output = (json.dumps(document, ensure_ascii=True, indent=2, allow_nan=False) + '\n').encode()
    public = {'client': client, 'target': str(target), 'entry': entry, 'direct_servers_remaining': direct, 'removed_servers': list(remove), 'changed': original != output, 'notice': 'Remaining direct servers bypass MCP-Sentry. Restart the client after applying.'}
    return public, target, original, output


def apply(prepared):
    public, target, original, output = prepared
    if read(target) != original:
        raise ValueError('Client configuration changed since preview; generate a new plan')
    if not public['changed']:
        return dict(public, applied=False, backup=None)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup = target.with_name(target.name + '.mcpsentry-backup-' + uuid.uuid4().hex + '.json')
    record = {'version': 1, 'target': str(target), 'original': None if original is None else base64.b64encode(original).decode(), 'installed_sha256': digest(output)}
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(record, stream)
        stream.flush()
        os.fsync(stream.fileno())
    if read(target) != original:
        raise ValueError('Client configuration changed before writing; nothing applied')
    atomic(target, output)
    return dict(public, applied=True, backup=str(backup))


def rollback(backup):
    raw = read(backup, 2_000_000)
    if raw is None:
        raise ValueError('Backup not found')
    record = strict_json(raw)
    if not isinstance(record, dict) or set(record) != {'version', 'target', 'original', 'installed_sha256'} or record['version'] != 1 or not isinstance(record['target'], str) or not Path(record['target']).is_absolute():
        raise ValueError('Invalid setup backup')
    target = Path(record['target'])
    current = read(target)
    if current is None or digest(current) != record['installed_sha256']:
        raise ValueError('Client configuration changed after setup; automatic rollback refused')
    original = None if record['original'] is None else base64.b64decode(record['original'], validate=True)
    if original is None:
        target.unlink()
    else:
        atomic(target, original)
    return {'restored': True, 'target': str(target), 'notice': 'Restart the client to reload its configuration.'}
