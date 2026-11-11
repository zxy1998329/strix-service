"""Internal Strix job API. One Linux worker, one shared local SQLite database."""
import hashlib
import hmac
import ipaddress
import json
import os
import re
import shutil
import socket
import sqlite3
import stat
import time
import uuid
import zipfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit, urlunsplit

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile, Request
from fastapi.responses import FileResponse
from starlette.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field


DATA = Path(os.environ.get('STRIX_DATA_DIR', '/srv/strix-data'))
UPLOAD_LIMIT = int(os.environ.get('UPLOAD_MAX_BYTES', 50 * 1024 * 1024))
EXPANDED_LIMIT = int(os.environ.get('EXPANDED_MAX_BYTES', 500 * 1024 * 1024))
MAX_FILES = 10000
app = FastAPI(title='Strix 安全检测平台', version='0.2.1')
bearer = HTTPBearer(auto_error=False)


@app.middleware('http')
async def upload_length_guard(request, call_next):
    if request.method == 'POST' and request.url.path == '/v1/scans/whitebox':
        value = request.headers.get('content-length')
        if value is None:
            return JSONResponse({'detail': 'Content-Length is required for ZIP uploads'}, status_code=411)
        try:
            size = int(value)
        except ValueError:
            return JSONResponse({'detail': 'Invalid Content-Length'}, status_code=400)
        if size < 0 or size > UPLOAD_LIMIT + 1024 * 1024:
            return JSONResponse({'detail': 'Multipart request is too large'}, status_code=413)
    return await call_next(request)


@contextmanager
def database():
    DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    conn = sqlite3.connect(DATA / 'jobs.sqlite3', timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('''CREATE TABLE IF NOT EXISTS jobs (
        id TEXT PRIMARY KEY, owner TEXT NOT NULL, kind TEXT NOT NULL,
        name TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL,
        created REAL NOT NULL, updated REAL NOT NULL, detail TEXT NOT NULL DEFAULT '{}')''')
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def authenticate(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
    from portal import session_identity, api_token_identity
    if credentials:
        identity = api_token_identity(credentials.credentials)
        if identity:
            return identity
    else:
        identity = session_identity(request)
        if identity:
            return identity
    filename = os.environ.get('SERVICE_TOKENS_FILE')
    if not filename:
        raise HTTPException(401, '请登录，或使用有效的 Bearer API 令牌')
    try:
        tokens = json.loads(Path(filename).read_text())
        if not isinstance(tokens, dict) or not tokens or any(
            not isinstance(k, str) or not isinstance(v, str) or len(v) < 32
            for k, v in tokens.items()
        ):
            raise ValueError('invalid credentials file')
    except (OSError, ValueError):
        raise HTTPException(503, 'Invalid service credentials configuration')
    if credentials:
        supplied = hashlib.sha256(credentials.credentials.encode()).digest()
        for owner, token in tokens.items():
            if hmac.compare_digest(supplied, hashlib.sha256(token.encode()).digest()):
                return owner
    raise HTTPException(401, 'Invalid bearer token', headers={'WWW-Authenticate': 'Bearer'})


def job_dir(job_id):
    if not re.fullmatch(r'[0-9a-f]{32}', job_id):
        raise HTTPException(404, 'Job not found')
    return DATA / 'jobs' / job_id


def owned_job(job_id, owner):
    job_dir(job_id)
    with database() as conn:
        row = conn.execute('SELECT * FROM jobs WHERE id=?' + ('' if owner == '__admin__' else ' AND owner=?'),
                           (job_id,) if owner == '__admin__' else (job_id, owner)).fetchone()
    if row is None:
        raise HTTPException(404, 'Job not found')
    return dict(row)


def update_job(job_id, status, detail):
    with database() as conn:
        conn.execute('UPDATE jobs SET status=?,detail=?,updated=? WHERE id=?',
                     (status, json.dumps(detail, ensure_ascii=False), time.time(), job_id))


def enqueue(job_id, owner, kind, name, target, instructions=''):
    import runtime_config
    if instructions:
        (job_dir(job_id) / 'requirements.json').write_text(json.dumps({'instructions':instructions},ensure_ascii=False),encoding='utf-8')
    config = runtime_config.snapshot(job_dir(job_id))
    with database() as conn:
        conn.execute('BEGIN IMMEDIATE')
        active = conn.execute("SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running','cancel_requested')").fetchone()[0]
        personal = conn.execute("SELECT COUNT(*) FROM jobs WHERE owner=? AND status IN ('queued','running','cancel_requested')", (owner,)).fetchone()[0]
        if active >= int(os.environ.get('QUEUE_LIMIT', '20')) or personal >= 3:
            raise HTTPException(429, 'Queue limit reached')
        now = time.time()
        conn.execute('INSERT INTO jobs (id,owner,kind,name,target,status,created,updated) VALUES (?,?,?,?,?,?,?,?)',
                     (job_id, owner, kind, name, target, 'queued', now, now))
        if config:
            conn.execute('UPDATE jobs SET detail=? WHERE id=?',
                         (json.dumps({'config_revision': config['revision'], 'model': config['model']}), job_id))


def safe_extract(archive, destination):
    """Validate all entries first, then extract regular files only with bounded reads."""
    with zipfile.ZipFile(archive) as zf:
        entries = zf.infolist()
        if not entries or len(entries) > MAX_FILES:
            raise ValueError('Empty archive or too many entries')
        total = 0
        seen = set()
        checked = []
        for entry in entries:
            name = entry.filename
            parts = PurePosixPath(name).parts
            mode = entry.external_attr >> 16
            if (not parts or name.startswith('/') or '\\' in name or ':' in name
                    or any(p in ('.', '..') for p in name.rstrip('/').split('/'))
                    or any(ord(c) < 32 for c in name) or len(name) > 500
                    or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))
                    or entry.flag_bits & 1):
                raise ValueError('Unsafe, special or encrypted ZIP entry')
            key = '/'.join(parts).casefold()
            if key in seen:
                raise ValueError('Duplicate archive path')
            seen.add(key)
            total += entry.file_size
            if (entry.file_size > UPLOAD_LIMIT or total > EXPANDED_LIMIT
                    or entry.file_size > max(entry.compress_size, 1) * 1000):
                raise ValueError('Archive expansion limit exceeded')
            checked.append((entry, parts))
        destination.mkdir(parents=True, mode=0o700)
        actual_total = 0
        for entry, parts in checked:
            output = destination.joinpath(*parts)
            if entry.is_dir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(entry) as source, output.open('xb') as target:
                actual_file = 0
                while chunk := source.read(1024 * 1024):
                    actual_file += len(chunk)
                    actual_total += len(chunk)
                    if actual_file > UPLOAD_LIMIT or actual_total > EXPANDED_LIMIT:
                        raise ValueError('Archive read limit exceeded')
                    target.write(chunk)


def validate_target(url, config=None):
    """Exact hostname/port allowlist + resolved IP allowlist. Network ACL still required."""
    try:
        parsed = urlsplit(url)
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.fragment or parsed.query or parsed.path not in ('', '/')
                or any(c.isspace() or ord(c) < 32 for c in url) or '\\' in url or '%' in parsed.netloc):
            raise ValueError('Use an HTTP(S) origin without credentials, query or path')
        host = parsed.hostname.encode('idna').decode().lower().rstrip('.')
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        if config is None:
            import runtime_config
            config = runtime_config.get_settings()
        restricted = config.get('scope_restrictions_enabled', False) if config else os.environ.get('SCAN_SCOPE_RESTRICTIONS_ENABLED', 'false').lower() == 'true'
        networks = []
        if restricted:
            hosts_raw = config['allowed_hosts'] if config else os.environ.get('ALLOWED_TARGET_HOSTS', '')
            ports_raw = config['allowed_ports'] if config else os.environ.get('ALLOWED_TARGET_PORTS', '80,443')
            hosts = {x.strip().lower() for x in hosts_raw.split(',') if x.strip()}
            ports = {int(x) for x in ports_raw.split(',')}
            if host not in hosts or port not in ports:
                raise ValueError('Target host or port is not registered')
            ranges_raw = config['allowed_cidrs'] if config else os.environ.get('ALLOWED_TARGET_CIDRS', '')
            networks = [ipaddress.ip_network(x.strip()) for x in ranges_raw.split(',') if x.strip()]
            if not networks:
                raise ValueError('Target IP ranges are not configured')
        addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
        for addr in addresses:
            if (addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified
                    or addr.is_reserved or getattr(addr, 'ipv4_mapped', None)
                    or (restricted and not any(addr in network for network in networks))):
                raise ValueError('Target resolves to a prohibited or unregistered IP')
        authority = f'[{host}]' if ':' in host else host
        if port != (443 if parsed.scheme == 'https' else 80):
            authority += f':{port}'
        return urlunsplit((parsed.scheme, authority, '/', '', ''))
    except (ValueError, OSError, UnicodeError) as error:
        raise ValueError(str(error)) from error


def acceptance(authorized):
    if not authorized:
        raise HTTPException(400, 'Explicit test authorization is required')
    import runtime_config
    config = runtime_config.get_settings()
    if not (config['enabled'] if config else os.environ.get('WEB_CONFIG_REQUIRED', 'false') != 'true' and os.environ.get('ENABLE_SCANS', 'false').lower() == 'true'):
        raise HTTPException(503, 'Scans are disabled by the administrator')


@app.get('/healthz')
def health():
    return {'status': 'ok', 'service_version': '0.2.1'}


@app.post('/v1/scans/whitebox', status_code=202)
async def whitebox(project: UploadFile | None = File(None), name: str = Form('project', max_length=100),
                   instructions: str = Form('', max_length=4000),
                   source_job_id: str = Form('',max_length=32),
                   authorized: bool = Form(False), owner: str = Depends(authenticate)):
    acceptance(authorized)
    if project is not None and (not project.filename or not project.filename.lower().endswith('.zip')):
        raise HTTPException(400, 'Only ZIP projects are supported')
    if project is None and not source_job_id:
        raise HTTPException(400,'请上传项目 ZIP 或选择复用原任务项目')
    if source_job_id:
        old=owned_job(source_job_id,owner)
        if old['kind']!='whitebox':raise HTTPException(400,'原任务不是白盒任务')
    job_id = uuid.uuid4().hex
    root = job_dir(job_id)
    root.mkdir(parents=True, mode=0o700)
    archive = root / 'upload.zip'
    try:
        from starlette.concurrency import run_in_threadpool
        if project is None:
            from task_reuse import copy_project
            await run_in_threadpool(copy_project,source_job_id,owner,root/'source')
            enqueue(job_id,owner,'whitebox',name,str(root/'source'),instructions)
            return {'id':job_id,'status':'queued','status_url':f'/v1/scans/{job_id}'}
        size = 0
        with archive.open('xb') as stream:
            while chunk := await project.read(1024 * 1024):
                size += len(chunk)
                if size > UPLOAD_LIMIT:
                    raise HTTPException(413, 'Upload is too large')
                stream.write(chunk)
        # CPU/disk extraction happens in a thread; large uploads cannot block status requests.
        from starlette.concurrency import run_in_threadpool
        await run_in_threadpool(safe_extract, archive, root / 'source')
        archive.unlink()
        enqueue(job_id, owner, 'whitebox', name, str(root / 'source'), instructions)
    except HTTPException:
        shutil.rmtree(root)
        raise
    except (ValueError, OSError, zipfile.BadZipFile, RuntimeError):
        shutil.rmtree(root)
        raise HTTPException(400, 'Invalid ZIP or unsafe archive content')
    finally:
        if project is not None:await project.close()
    return {'id': job_id, 'status': 'queued', 'status_url': f'/v1/scans/{job_id}'}


class BlackboxRequest(BaseModel):
    target: str = Field(max_length=2048)
    name: str = Field(default='system', max_length=100)
    authorized: bool = False
    instructions: str = Field(default='',max_length=4000)


@app.post('/v1/scans/blackbox', status_code=202)
def blackbox(request: BlackboxRequest, owner: str = Depends(authenticate)):
    acceptance(request.authorized)
    try:
        target = validate_target(request.target)
    except ValueError as error:
        raise HTTPException(400, str(error))
    job_id = uuid.uuid4().hex
    root = job_dir(job_id)
    root.mkdir(parents=True, mode=0o700)
    try:
        enqueue(job_id, owner, 'blackbox', request.name, target, request.instructions)
    except Exception:
        shutil.rmtree(root)
        raise
    return {'id': job_id, 'status': 'queued', 'status_url': f'/v1/scans/{job_id}'}


def read_json(path, fallback):
    try:
        if path.is_symlink() or path.stat().st_size > 20 * 1024 * 1024:
            return fallback
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return fallback


def latest_run(root):
    candidates = [p for p in (root / 'strix_runs').glob('*/run.json') if not p.is_symlink()]
    return max(candidates, key=lambda p: p.stat().st_mtime).parent if candidates else None


def execution_progress(run, row):
    from datetime import datetime
    raw = read_json(run / 'run.json', {}) if run else {}
    coverage = read_json(run / 'coverage.json', {}) if run else {}
    if not isinstance(raw, dict):
        raw = {}
    if not isinstance(coverage, dict):
        coverage = {}
    tools = [v for v in raw.get('tool_calls', []) if isinstance(v, dict)]
    requests = [v for v in raw.get('llm_requests', []) if isinstance(v, dict)]
    entries = [v for v in coverage.get('entries', []) if isinstance(v, dict)]
    events = []
    for item in tools:
        events.append({'kind': 'tool', 'time': item.get('started_at'), 'name': item.get('tool', '工具'),
                       'duration_ms': item.get('duration_ms')})
    for item in requests:
        events.append({'kind': 'model', 'time': item.get('started_at'), 'name': '模型请求',
                       'outcome': item.get('outcome'), 'status': item.get('status'),
                       'duration_ms': item.get('duration_ms'), 'retry_attempt': item.get('retry_attempt', 0)})
    trace = run / '.state/agents.db' if run else None
    if trace and trace.is_file() and not trace.is_symlink():
        try:
            conn = sqlite3.connect('file:' + str(trace) + '?mode=ro', uri=True, timeout=0.2)
            try:
                rows = conn.execute('SELECT message_data,created_at FROM agent_messages ORDER BY id DESC LIMIT 200').fetchall()
            finally:
                conn.close()
            outputs, traced = set(), []
            import portal
            import runtime_config
            config = runtime_config.get_settings() or runtime_config.defaults()
            for data, stamp in rows:
                if len(data) > 256000:
                    continue
                item = json.loads(data)
                if item.get('type') == 'function_call_output':
                    outputs.add(item.get('call_id'))
                elif item.get('type') == 'function_call':
                    args = item.get('arguments', '{}')
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except ValueError:
                            args = {}
                    command = args.get('cmd') or args.get('command') or args.get('url') or '' if isinstance(args, dict) else ''
                    traced.append({'kind':'tool','time':str(stamp).replace(' ', 'T')+'Z',
                                   'name':item.get('name','工具'), 'state':'已返回' if item.get('call_id') in outputs else '等待工具返回',
                                   'command':portal.probe_error_detail(str(command)[:2000],config)})
            if traced:
                events = [e for e in events if e['kind'] != 'tool'] + traced
                tools = traced
        except (sqlite3.Error, OSError, ValueError, TypeError):
            pass
    def event_time(event):
        try:
            return datetime.fromisoformat(str(event.get('time')).replace('Z', '+00:00')).timestamp()
        except (ValueError, TypeError):
            return 0
    events.sort(key=event_time)
    last_recorded = max((event_time(e) + (e.get('duration_ms') or 0) / 1000 for e in events), default=0)
    now = time.time()
    active = row['status'] in ('running', 'cancel_requested')
    silence = max(0, int(now-last_recorded)) if last_recorded else None
    headline = {'queued':'等待扫描进程领取任务', 'running':'引擎运行中，等待首条执行记录',
                'cancel_requested':'已请求停止，等待引擎退出', 'completed':'扫描执行结束，报告待人工复核',
                'failed':'扫描失败，请查看结束说明', 'timed_out':'已达到任务时限', 'cancelled':'任务已停止'}.get(row['status'], row['status'])
    if active and events and row['status'] != 'cancel_requested':
        last = events[-1]
        headline = ('最近记录的工具：' + str(last['name'])) if last['kind']=='tool' else '最近一次模型请求已返回；等待后续执行记录'
    end_time = now if row['status'] in ('queued','running','cancel_requested') else row['updated']
    return {'headline':headline, 'elapsed_seconds':max(0,int(end_time-row['created'])),
            'tool_calls_count':len(tools), 'coverage_count':len(entries),
            'checklist_percent': round(100 * sum(e.get('outcome') in ('reported', 'no_issue_found', 'ruled_out', 'not_applicable') for e in entries) / len(entries)) if entries else 0,
            'last_activity_at':last_recorded or None, 'silence_seconds':silence,
            'activity_warning': bool(active and silence is not None and silence > 120),
            'events':events[-40:][::-1], 'coverage':entries[-100:], 'coverage_gaps':coverage.get('gaps', [])[:50],
            'truncated_events':max(0,len(events)-40), 'source':'Strix 已落盘执行记录；记录可能滞后，不表示工具一定成功或完整覆盖。'}


def model_metrics(root, run=None):
    """Expose numeric counters only; old tasks have totals but no inferred peaks."""
    keys = ('total_input_tokens', 'total_output_tokens', 'peak_minute_input_tokens',
            'peak_minute_output_tokens', 'max_input_tokens', 'max_output_tokens',
            'max_concurrency', 'requests', 'rate_limit_retries', 'unknown_usage_requests')
    path = root / 'model_metrics.json'
    if path.is_file() and not path.is_symlink():
        raw = read_json(path, {})
        if isinstance(raw, dict):
            metrics = {key: raw[key] for key in keys
                       if type(raw.get(key)) is int and raw[key] >= 0}
            if metrics:
                return metrics
    if run:
        raw = read_json(run / 'run.json', {})
        usage = raw.get('llm_usage', {}) if isinstance(raw, dict) else {}
        if isinstance(usage, dict):
            metrics = {new: usage[old] for old, new in
                       (('input_tokens', 'total_input_tokens'), ('output_tokens', 'total_output_tokens'))
                       if type(usage.get(old)) is int and usage[old] >= 0}
            if metrics:
                return {**metrics, 'source': 'engine_totals'}
    return None


@app.get('/v1/scans/{job_id}')
def status(job_id: str, owner: str = Depends(authenticate)):
    row = owned_job(job_id, owner)
    detail = json.loads(row.pop('detail'))
    row.pop('owner')
    row['detail'] = detail
    row['instructions'] = read_json(job_dir(job_id) / 'requirements.json', {}).get('instructions','')
    row['findings'] = []
    run = latest_run(job_dir(job_id))
    if run:
        findings = read_json(run / 'vulnerabilities.json', [])
        if isinstance(findings, dict):
            findings = findings.get('vulnerabilities', [])
        if isinstance(findings, list):
            row['findings'] = [item for item in findings if isinstance(item, dict)]
        raw = read_json(run / 'run.json', {})
        usage = raw.get('llm_usage', {})
        row['progress'] = {'phase': raw.get('status'), 'model_responses': usage.get('requests', 0),
                           'input_tokens': usage.get('input_tokens', 0), 'output_tokens': usage.get('output_tokens', 0)}
    row['report_ready'] = (job_dir(job_id) / 'report.md').is_file()
    if not row['findings'] and row['report_ready']:
        saved = read_json(job_dir(job_id) / 'report.json', {})
        if isinstance(saved, dict) and isinstance(saved.get('findings'), list):
            row['findings'] = [item for item in saved['findings'] if isinstance(item, dict)]
    row['findings_count'] = len(row['findings'])
    row['execution'] = execution_progress(run, row)
    row['model_metrics'] = model_metrics(job_dir(job_id), run)
    row['report_url'] = f'/v1/scans/{job_id}/report' if row['report_ready'] else None
    if row['kind'].startswith('greybox'):
        import greybox
        row = greybox.redact(row,greybox.load(job_dir(job_id)))
    return row


def model_call_access(job_id, owner):
    owned_job(job_id, owner)
    if owner != '__admin__':
        raise HTTPException(403, '模型调用明细仅管理员可查看')
    directory = job_dir(job_id) / 'model_call_details'
    if directory.is_symlink():
        raise HTTPException(400, '模型调用记录不可读取')
    return directory


def safe_model_record(job_id, path):
    import runtime_config
    from call_details import sanitize
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 9*1024*1024:
        raise HTTPException(400, '模型调用记录不可读取')
    value = read_json(path, {})
    secrets = []
    for config in (runtime_config.for_job(job_dir(job_id)), runtime_config.get_settings()):
        if config:
            secrets += [config.get('api_key', '')]
            secrets += list(config.get('extra_headers', {}).values())
            secrets += list(config.get('provider_env', {}).values())
    return sanitize(value, [secret for secret in secrets if isinstance(secret,str) and secret])


@app.get('/v1/scans/{job_id}/model-calls')
def model_call_list(job_id: str, page: int = 1, owner: str = Depends(authenticate)):
    directory = model_call_access(job_id, owner)
    if not 1 <= page <= 100000:
        raise HTTPException(400, '页码不正确')
    paths = sorted(directory.glob('*.meta'), reverse=True)
    items = []
    for path in paths[(page-1)*20:page*20]:
        value = safe_model_record(job_id, path)
        items.append({key:value.get(key) for key in ('id','model','started','finished','status','state')})
    return JSONResponse({'items':items,'page':page,'total':len(paths)},headers={'Cache-Control':'no-store'})


@app.get('/v1/scans/{job_id}/model-calls/{call_id}')
def model_call_detail(job_id: str, call_id: str, owner: str = Depends(authenticate)):
    directory = model_call_access(job_id, owner)
    if not re.fullmatch('[a-f0-9]{32}', call_id):
        raise HTTPException(400, '调用 ID 不正确')
    paths = list(directory.glob('*-'+call_id+'.json'))
    if len(paths) != 1:
        raise HTTPException(404, '此任务没有对应调用记录')
    return JSONResponse(safe_model_record(job_id,paths[0]),headers={'Cache-Control':'no-store'})


@app.get('/v1/scans/{job_id}/logs')
def task_logs(job_id: str, owner: str = Depends(authenticate)):
    import re
    import portal
    import runtime_config
    owned_job(job_id, owner)
    if owner != '__admin__':
        raise HTTPException(403, '运行日志仅管理员可查看')
    root = job_dir(job_id)
    path = root / 'worker.log'
    if path.is_symlink():
        raise HTTPException(400, '日志不可读取')
    if not path.exists():
        return JSONResponse({'text': '尚未产生运行日志。', 'truncated': False}, headers={'Cache-Control': 'no-store'})
    if path.is_symlink() or not path.is_file():
        raise HTTPException(400, '日志不可读取')
    with path.open('rb') as stream:
        stream.seek(0, 2)
        size = stream.tell()
        stream.seek(max(0, size - 16000))
        text = stream.read(16000).decode('utf-8', errors='replace')
    text = re.sub(r'\x1b\][^\x07]*(?:\x07|\x1b\\)', '', text)
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    for config in (runtime_config.for_job(root), runtime_config.get_settings()):
        if config:
            text = portal.probe_error_detail(text, config)
    if (root / 'auth.enc').exists():
        import greybox
        text = greybox.redact(text, greybox.load(root))
    text = re.sub(r'(?im)((?:set-cookie|cookie)\s*:\s*)[^\r\n]+', r'\1[已脱敏]', text)
    return JSONResponse({'text': text, 'truncated': size > 16000}, headers={'Cache-Control': 'no-store'})


@app.get('/v1/scans/{job_id}/report')
def report(job_id: str, format: str = 'markdown', owner: str = Depends(authenticate)):
    owned_job(job_id, owner)
    filename = {'markdown': 'report.md', 'json': 'report.json'}.get(format)
    if filename is None:
        raise HTTPException(400, 'format must be markdown or json')
    path = job_dir(job_id) / filename
    if not path.is_file() or path.is_symlink():
        raise HTTPException(409, 'Report is not ready')
    return FileResponse(path, media_type='application/json' if format == 'json' else 'text/markdown',
                        filename=f'{job_id}.{ "json" if format == "json" else "md"}')


@app.post('/v1/scans/{job_id}/cancel', status_code=202)
def cancel(job_id: str, owner: str = Depends(authenticate)):
    owned_job(job_id, owner)
    with database() as conn:
        conn.execute("UPDATE jobs SET status=CASE WHEN status='queued' THEN 'cancelled' ELSE 'cancel_requested' END,updated=? WHERE id=? AND status IN ('queued','running')", (time.time(), job_id))
    return {'id': job_id, 'status': owned_job(job_id, owner)['status']}


from portal import install as install_portal
install_portal(app)
from greybox import install as install_greybox
install_greybox(app)
from task_reuse import install as install_task_reuse
install_task_reuse(app)

from task_submission import install as install_task_submission
install_task_submission(app)
