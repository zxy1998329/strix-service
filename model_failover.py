"""Primary/backup model circuit breaker and per-request routing.

The breaker state is shared by the worker (which probes the primary model) and
the Strix subprocess (which routes individual model requests).  It contains no
credentials; keys live only in the encrypted settings and in the ephemeral
per-task failover file under /dev/shm.
"""
import fcntl
import json
import os
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import runtime_config

PROBE_INTERVAL = 60
PROBE_TIMEOUT = 10
FAILURE_STATUSES = {401, 403, 404, 408, 429, 432, 433}


def state_path(data_dir):
    return Path(data_dir) / 'model_health.json'


def _lock_path(data_dir):
    return Path(data_dir) / 'model_health.lock'


def default_state(revision=''):
    return {'revision': revision, 'active': 'primary', 'changed_at': time.time(),
            'opened_at': None, 'next_probe_at': None, 'last_probe_at': None,
            'last_probe_ok': None, 'last_probe_error': None,
            'last_error': None, 'last_error_at': None, 'switches': 0}


def _read_unlocked(data_dir):
    path = state_path(data_dir)
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def read_state(data_dir, revision=None):
    path = state_path(data_dir)
    lock = _lock_path(data_dir)
    try:
        with lock.open('a+b') as handle:
            fcntl.flock(handle, fcntl.LOCK_SH)
            value = _read_unlocked(data_dir)
    except OSError:
        value = None
    if not value:
        return default_state(revision or '')
    if revision and value.get('revision') != revision:
        return default_state(revision)
    result = default_state(value.get('revision', revision or ''))
    result.update(value)
    return result


def raw_state(data_dir):
    try:
        return _read_unlocked(data_dir)
    except OSError:
        return None


def _write_unlocked(data_dir, value):
    path = state_path(data_dir)
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex + '.tmp')
    with temporary.open('x', encoding='utf-8') as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, ensure_ascii=False)
    os.replace(temporary, path)


def write_state(data_dir, value):
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    with _lock_path(data_dir).open('a+b') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        _write_unlocked(data_dir, value)


def reset_state(data_dir, revision):
    write_state(data_dir, default_state(revision))


def mark_primary_failure(data_dir, revision, reason):
    """Open the breaker and schedule the first probe one minute later."""
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    now = time.time()
    with _lock_path(data_dir).open('a+b') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        value = _read_unlocked(data_dir) or default_state(revision)
        if value.get('revision') != revision:
            return None
        if value.get('active') != 'backup':
            value['switches'] = int(value.get('switches') or 0) + 1
            value['opened_at'] = now
            value['changed_at'] = now
        value['active'] = 'backup'
        value['next_probe_at'] = now + PROBE_INTERVAL
        value['last_error'] = str(reason)[:200]
        value['last_error_at'] = now
        _write_unlocked(data_dir, value)
        return value


def mark_probe_result(data_dir, revision, ok, error=None):
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    now = time.time()
    with _lock_path(data_dir).open('a+b') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        value = _read_unlocked(data_dir) or default_state(revision)
        if value.get('revision') != revision:
            return None
        value['last_probe_at'] = now
        value['last_probe_ok'] = bool(ok)
        if ok:
            value['active'] = 'primary'
            value['changed_at'] = now
            value['opened_at'] = None
            value['next_probe_at'] = None
            value['last_probe_error'] = None
            value['last_error'] = None
        else:
            value['active'] = 'backup'
            value['next_probe_at'] = now + PROBE_INTERVAL
            value['last_probe_error'] = str(error or 'probe failed')[:200]
        _write_unlocked(data_dir, value)
        return value


def failure_reason(status, value=None, error=None):
    """Return a short, non-secret reason for an availability/auth failure."""
    if error is not None:
        return type(error).__name__
    if status in FAILURE_STATUSES or (isinstance(status, int) and 500 <= status <= 599):
        return 'HTTP ' + str(status)
    if isinstance(value, dict):
        candidates = [value.get('code')]
        if isinstance(value.get('error'), dict):
            candidates.append(value['error'].get('code'))
        for candidate in candidates:
            if str(candidate) in ('429', '432', '433'):
                return 'HTTP ' + str(candidate)
    return None


def _endpoint(target):
    base = (target.get('api_base') or '').rstrip('/')
    if target.get('protocol') == 'anthropic':
        base = base or 'https://api.anthropic.com'
        if base.endswith('/messages'):
            return base
        return base.removesuffix('/v1') + '/v1/messages'
    base = base or 'https://api.openai.com/v1'
    if base.endswith('/chat/completions'):
        return base
    return base + '/chat/completions'


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args):
        return None


def probe_primary(value):
    """Send the user-requested ``hi`` probe to the primary model.

    This is run by the worker's background thread, never by the scan process.
    """
    try:
        targets = runtime_config.model_targets(value)
        target = targets['primary'] if targets else None
        if not target:
            return False, 'missing primary target'
        body = {'model': target['model_name'], 'messages': [{'role': 'user', 'content': 'hi'}],
                'max_tokens': 16}
        headers = {'Content-Type': 'application/json'}
        headers.update(target.get('extra_headers') or {})
        if target.get('protocol') == 'anthropic':
            headers['anthropic-version'] = '2023-06-01'
            if target.get('api_key'):
                headers['x-api-key'] = target['api_key']
        elif target.get('api_key'):
            headers['Authorization'] = 'Bearer ' + target['api_key']
        body.update(target.get('extra_body') or {})
        request = urllib.request.Request(_endpoint(target), data=json.dumps(body).encode(), headers=headers)
        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(request, timeout=PROBE_TIMEOUT) as response:
            raw = response.read(1024 * 1024)
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            return False, 'invalid response'
        return True, None
    except urllib.error.HTTPError as error:
        return False, 'HTTP ' + str(error.code)
    except Exception as error:  # noqa: BLE001 - health probe must never crash the worker
        return False, type(error).__name__


def probe_due(value, data_dir):
    targets = runtime_config.model_targets(value) if value else None
    if not targets or not targets.get('backup'):
        return False
    state = read_state(data_dir, value.get('revision', ''))
    return state.get('active') == 'backup' and bool(state.get('next_probe_at')) and state['next_probe_at'] <= time.time()


def _write_route(path, role, target, state, reason=None):
    if not path:
        return
    value = {'active': role, 'model': target.get('model_name', target.get('model', '')),
             'switches': int((state or {}).get('switches') or 0),
             'changed_at': (state or {}).get('changed_at') or time.time(),
             'reason': reason}
    path = Path(path)
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('x', encoding='utf-8') as stream:
            os.chmod(temporary, 0o600)
            json.dump(value, stream, ensure_ascii=False)
        os.replace(temporary, path)
    except OSError:
        try:
            temporary.unlink()
        except OSError:
            pass


class Router:
    """Per-scan request router backed by the worker-wide breaker state."""

    def __init__(self, config, data_dir, route_path=None):
        self.primary = config.get('primary') or {}
        self.backup = config.get('backup') or None
        self.revision = config.get('revision', '')
        self.data_dir = data_dir
        self.route_path = route_path
        self.local_active = 'primary'
        self.local_reason = None
        self.lock = threading.Lock()
        self._write_route(self.primary)

    def _write_route(self, target, reason=None):
        state = read_state(self.data_dir, self.revision)
        _write_route(self.route_path, target.get('role', 'primary'), target, state, reason)

    def active(self):
        with self.lock:
            if self.backup:
                raw = raw_state(self.data_dir)
                if raw and raw.get('revision') == self.revision and raw.get('active') == 'backup':
                    self.local_active = 'backup'
                elif raw and raw.get('revision') == self.revision:
                    self.local_active = 'primary'
            target = self.backup if self.local_active == 'backup' and self.backup else self.primary
            if target.get('role') == 'primary':
                self.local_reason = None
            self._write_route(target, self.local_reason)
            return target

    def note_failure(self, reason):
        with self.lock:
            self.local_active = 'backup' if self.backup else 'primary'
            self.local_reason = reason if self.backup else None
            if self.backup:
                try:
                    current = raw_state(self.data_dir)
                    if current is None or current.get('revision') == self.revision:
                        mark_primary_failure(self.data_dir, self.revision, reason)
                    # A stale job snapshot must not overwrite a newly saved configuration.
                except OSError:
                    pass
                self._write_route(self.backup, reason)
            return self.backup

    def rewrite(self, request, target):
        """Clone an httpx request for the backup target (same protocol only)."""
        import httpx
        body = None
        try:
            body = json.loads(request.content)
        except (ValueError, TypeError):
            body = None
        if not isinstance(body, dict):
            return request
        headers = dict(request.headers)
        for name in list(headers):
            if name.lower() in ('host', 'content-length', 'authorization', 'x-api-key', 'anthropic-version',
                                'openai-organization', 'openai-project', 'openai-beta'):
                headers.pop(name, None)
        primary_headers = {name.lower() for name in (self.primary.get('extra_headers') or {})}
        backup_headers = {name.lower() for name in (target.get('extra_headers') or {})}
        for name in primary_headers - backup_headers:
            headers.pop(name, None)
        headers.update(target.get('extra_headers') or {})
        headers['Content-Type'] = 'application/json'
        if target.get('protocol') == 'anthropic':
            headers['anthropic-version'] = '2023-06-01'
            if target.get('api_key'):
                headers['x-api-key'] = target['api_key']
        elif target.get('api_key'):
            headers['Authorization'] = 'Bearer ' + target['api_key']
        body['model'] = target['model_name']
        for key in self.primary.get('extra_body') or {}:
            if key not in (target.get('extra_body') or {}):
                body.pop(key, None)
        body.update(target.get('extra_body') or {})
        return httpx.Request(request.method, _endpoint(target), headers=headers,
                             content=json.dumps(body).encode())
