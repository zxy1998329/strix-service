"""Cooperative pause after the primary and backup models both keep failing.

The Strix process writes this state; the worker reads it to mark the job paused,
and the web API reads it to explain the pause and to resume.  It never contains
credentials: only model roles, models, status codes and already-redacted
provider error text.
"""
import fcntl
import json
import os
import time
import uuid
from pathlib import Path

MAX_FAILURES = 20
POLL_SECONDS = 1


def state_path(root):
    return Path(root) / 'model_guard.json'


def _lock_path(root):
    return Path(root) / 'model_guard.lock'


def default_state(threshold=0):
    return {'threshold': int(threshold or 0), 'count': 0, 'paused': False,
            'paused_at': None, 'reason': None, 'resume_epoch': 0, 'failures': []}


def _read_unlocked(root):
    try:
        value = json.loads(state_path(root).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def read(root):
    try:
        with _lock_path(root).open('a+b') as handle:
            fcntl.flock(handle, fcntl.LOCK_SH)
            value = _read_unlocked(root)
    except OSError:
        value = None
    result = default_state()
    if value:
        result.update(value)
    result['failures'] = [item for item in result.get('failures', []) if isinstance(item, dict)][-MAX_FAILURES:]
    return result


def _write_unlocked(root, value):
    path = state_path(root)
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex + '.tmp')
    with temporary.open('x', encoding='utf-8') as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, ensure_ascii=False)
    os.replace(temporary, path)


def write(root, value):
    Path(root).mkdir(parents=True, exist_ok=True)
    with _lock_path(root).open('a+b') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        _write_unlocked(root, value)


def snapshot(root):
    return read(root)


def resume(root):
    """Lift a pause and clear the failure streak so the next request starts fresh."""
    Path(root).mkdir(parents=True, exist_ok=True)
    with _lock_path(root).open('a+b') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        value = _read_unlocked(root) or default_state()
        value['paused'] = False
        value['paused_at'] = None
        value['reason'] = None
        value['count'] = 0
        value['failures'] = []
        value['resume_epoch'] = int(value.get('resume_epoch') or 0) + 1
        _write_unlocked(root, value)
        return value


class Guard:
    """Per-scan guard shared by the model hook and the worker."""

    def __init__(self, root, threshold):
        self.root = Path(root)
        self.threshold = int(threshold or 0)
        if self.threshold > 0:
            write(self.root, default_state(self.threshold))

    @property
    def enabled(self):
        return self.threshold > 0

    def note_attempt(self, identifier, role, model, status, error, message, started, finished):
        if not self.enabled:
            return
        Path(self.root).mkdir(parents=True, exist_ok=True)
        with _lock_path(self.root).open('a+b') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            value = _read_unlocked(self.root) or default_state(self.threshold)
            value['threshold'] = self.threshold
            failures = value.get('failures') if isinstance(value.get('failures'), list) else []
            failures.append({'id': identifier, 'role': role, 'model': model, 'status': status,
                             'error': error, 'message': str(message or '')[:1000],
                             'started': started, 'finished': finished})
            value['failures'] = failures[-MAX_FAILURES:]
            _write_unlocked(self.root, value)

    def note_logical_failure(self, reason):
        if not self.enabled:
            return 0
        Path(self.root).mkdir(parents=True, exist_ok=True)
        with _lock_path(self.root).open('a+b') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            value = _read_unlocked(self.root) or default_state(self.threshold)
            value['threshold'] = self.threshold
            value['count'] = int(value.get('count') or 0) + 1
            value['reason'] = str(reason or '模型调用失败')[:300]
            _write_unlocked(self.root, value)
            return value['count']

    def note_success(self):
        if not self.enabled:
            return
        Path(self.root).mkdir(parents=True, exist_ok=True)
        with _lock_path(self.root).open('a+b') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            value = _read_unlocked(self.root) or default_state(self.threshold)
            value['count'] = 0
            value['failures'] = []
            value['reason'] = None
            _write_unlocked(self.root, value)

    def pause(self, reason):
        if not self.enabled:
            return
        Path(self.root).mkdir(parents=True, exist_ok=True)
        with _lock_path(self.root).open('a+b') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            value = _read_unlocked(self.root) or default_state(self.threshold)
            value['threshold'] = self.threshold
            value['paused'] = True
            value['paused_at'] = time.time()
            value['reason'] = str(reason or '模型连续失败')[:300]
            _write_unlocked(self.root, value)

    def wait(self):
        """Block the model call until the API resumes the job or the process dies."""
        while True:
            if not read(self.root).get('paused'):
                return
            time.sleep(POLL_SECONDS)
