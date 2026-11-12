"""Browser sessions, employee login, administrator settings and job history."""
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import urllib.error
import urllib.request
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

import model_failover
import runtime_config
import service

COOKIE = 'strix_session'


def schema(conn):
    conn.execute('CREATE TABLE IF NOT EXISTS portal_admin (id INTEGER PRIMARY KEY, salt TEXT, digest TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS portal_users (employee TEXT PRIMARY KEY, created REAL, last_seen REAL, disabled INTEGER DEFAULT 0)')
    conn.execute('CREATE TABLE IF NOT EXISTS portal_sessions (digest TEXT PRIMARY KEY, owner TEXT, role TEXT, csrf TEXT, expires REAL)')
    conn.execute('CREATE TABLE IF NOT EXISTS portal_attempts (ip TEXT, created REAL)')
    conn.execute('CREATE TABLE IF NOT EXISTS portal_audit (created REAL, actor TEXT, action TEXT, detail TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS portal_api_tokens (id TEXT PRIMARY KEY, digest TEXT UNIQUE, owner TEXT, name TEXT, created REAL, expires REAL, last_used REAL, revoked INTEGER DEFAULT 0)')
    conn.execute('CREATE TABLE IF NOT EXISTS portal_personal_tokens (owner TEXT PRIMARY KEY, token_id TEXT UNIQUE, encrypted TEXT NOT NULL)')
    if not conn.execute('SELECT 1 FROM portal_admin WHERE id=1').fetchone():
        salt = secrets.token_hex(16)
        digest = password_digest(os.environ.get('ADMIN_INITIAL_PASSWORD', '296419'), salt)
        conn.execute('INSERT OR IGNORE INTO portal_admin VALUES (1,?,?)', (salt, digest))


def password_digest(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 250000).hex()


def session_record(request):
    token = request.cookies.get(COOKIE)
    if not token or len(token) > 200:
        return None
    digest = hashlib.sha256(token.encode()).hexdigest()
    with service.database() as conn:
        schema(conn)
        row = conn.execute('SELECT * FROM portal_sessions WHERE digest=? AND expires>?', (digest, time.time())).fetchone()
        if row and row['role'] == 'user':
            user = conn.execute('SELECT disabled FROM portal_users WHERE employee=?', (row['owner'],)).fetchone()
            if not user or user['disabled']:
                return None
    return dict(row) if row else None


def session_identity(request):
    session = session_record(request)
    return ('__admin__' if session['role'] == 'admin' else session['owner']) if session else None


def api_token_identity(token):
    if not token or len(token) > 200:
        return None
    with service.database() as conn:
        schema(conn)
        digest = hashlib.sha256(token.encode()).hexdigest()
        row = conn.execute('SELECT * FROM portal_api_tokens WHERE digest=? AND revoked=0 AND expires>?',
                           (digest, time.time())).fetchone()
        if not row:
            return None
        if row['owner'] != '__admin__':
            user = conn.execute('SELECT disabled FROM portal_users WHERE employee=?', (row['owner'],)).fetchone()
            if not user or user['disabled']:
                return None
        conn.execute('UPDATE portal_api_tokens SET last_used=? WHERE id=?', (time.time(), row['id']))
        return row['owner']


def require_session(request, admin=False):
    session = session_record(request)
    if not session:
        raise HTTPException(401, '请先登录')
    if admin and session['role'] != 'admin':
        raise HTTPException(403, '仅管理员可访问')
    return session


def audit(actor, action, detail=''):
    with service.database() as conn:
        schema(conn)
        conn.execute('INSERT INTO portal_audit VALUES (?,?,?,?)', (time.time(), actor, action, detail[:500]))


class Login(BaseModel):
    role: str
    employee: str = Field(default='', max_length=6)
    password: str = Field(default='', max_length=256)


def install(app):
    @app.middleware('http')
    async def browser_security(request, call_next):
        if request.method not in ('GET', 'HEAD', 'OPTIONS'):
            origin = request.headers.get('origin')
            expected = str(request.base_url).rstrip('/')
            if origin and origin.rstrip('/') != expected:
                return JSONResponse({'detail': '来源地址不匹配，请从本站页面操作'}, 403)
            bearer_api = request.url.path.startswith('/v1/') and request.headers.get('authorization', '').lower().startswith('bearer ')
            if request.cookies.get(COOKIE) and request.url.path != '/web/login' and not bearer_api:
                record = session_record(request)
                if not record or not hmac.compare_digest(request.headers.get('x-csrf-token', ''), record['csrf']):
                    return JSONResponse({'detail': '页面凭据已过期，请刷新或重新登录'}, 403)
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" if request.url.path not in ('/docs', '/redoc') else "frame-ancestors 'none'"
        if request.url.path.startswith(('/web/', '/v1/')):
            response.headers['Cache-Control'] = 'no-store'
        return response

    @app.get('/', include_in_schema=False)
    @app.get('/admin', include_in_schema=False)
    @app.get('/api-guide', include_in_schema=False)
    def index():
        return FileResponse('/app/static/index.html')

    app.mount('/static', StaticFiles(directory='/app/static'), name='static')

    @app.post('/web/login')
    def login(payload: Login, request: Request):
        ip = request.client.host if request.client else 'local'
        now = time.time()
        with service.database() as conn:
            schema(conn)
            conn.execute('DELETE FROM portal_attempts WHERE created<?', (now - 300,))
            if conn.execute('SELECT COUNT(*) FROM portal_attempts WHERE ip=?', (ip,)).fetchone()[0] >= 15:
                raise HTTPException(429, '登录尝试过多，请 5 分钟后重试')
        error = None
        if payload.role == 'admin':
            with service.database() as conn:
                schema(conn)
                admin = conn.execute('SELECT * FROM portal_admin WHERE id=1').fetchone()
            if not hmac.compare_digest(password_digest(payload.password, admin['salt']), admin['digest']):
                error = '管理员密码不正确'
            owner = '__admin__'
        elif payload.role == 'user':
            if not re.fullmatch(r'[0-9]{6}', payload.employee):
                error = '请输入 6 位数字工号，保留开头的 0'
            owner = payload.employee
            if not error:
                with service.database() as conn:
                    schema(conn)
                    row = conn.execute('SELECT disabled FROM portal_users WHERE employee=?', (owner,)).fetchone()
                    if row and row['disabled']:
                        error = '该工号已停用，请联系管理员'
        else:
            error, owner = '请选择登录身份', ''
        if error:
            with service.database() as conn:
                conn.execute('INSERT INTO portal_attempts VALUES (?,?)', (ip, now))
            raise HTTPException(401, error)
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        with service.database() as conn:
            schema(conn)
            conn.execute('DELETE FROM portal_sessions WHERE expires<?', (now,))
            if payload.role == 'user':
                conn.execute('INSERT INTO portal_users(employee,created,last_seen) VALUES (?,?,?) ON CONFLICT(employee) DO UPDATE SET last_seen=excluded.last_seen', (owner, now, now))
            conn.execute('INSERT INTO portal_sessions VALUES (?,?,?,?,?)',
                         (hashlib.sha256(token.encode()).hexdigest(), owner, payload.role, csrf, now + 43200))
        audit(owner, 'login')
        response = JSONResponse({'owner': owner, 'role': payload.role, 'csrf': csrf})
        response.set_cookie(COOKIE, token, httponly=True, samesite='strict', max_age=43200,
                            secure=os.environ.get('COOKIE_SECURE', 'false').lower() == 'true')
        return response

    @app.post('/web/logout')
    def logout(request: Request):
        session = require_session(request)
        with service.database() as conn:
            conn.execute('DELETE FROM portal_sessions WHERE digest=?', (session['digest'],))
        response = JSONResponse({'ok': True})
        response.delete_cookie(COOKIE)
        return response

    @app.get('/web/me')
    def me(request: Request):
        session = require_session(request)
        config = runtime_config.get_settings()
        return {'owner': session['owner'], 'role': session['role'], 'csrf': session['csrf'],
                'scan_enabled': bool(config and config['enabled']),
                'model': config.get('model') if config else None,
                'authorized_targets': config.get('allowed_hosts', '') if config else '',
                'limits': {'upload_mib': service.UPLOAD_LIMIT // 1024 // 1024,
                           'timeout_minutes': int(config['timeout']) // 60 if config else 30}}

    @app.get('/web/api-tokens')
    def tokens_list(request: Request):
        session = require_session(request)
        with service.database() as conn:
            schema(conn)
            rows = conn.execute('SELECT id,name,created,expires,last_used,revoked FROM portal_api_tokens WHERE owner=? ORDER BY created DESC LIMIT 100',
                                (session['owner'],)).fetchall()
        return {'items': [dict(row) for row in rows]}

    @app.post('/web/api-tokens', status_code=201)
    async def token_create(request: Request):
        session = require_session(request)
        payload = await request.json()
        name = payload.get('name', 'Postman 调试')
        days = payload.get('days', 7)
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 60 or isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 90:
            raise HTTPException(400, '令牌名称应为 1—60 字符，有效期为 1—90 天')
        now = time.time()
        token_id, token = secrets.token_hex(16), 'stx_' + secrets.token_urlsafe(32)
        with service.database() as conn:
            schema(conn)
            conn.execute('BEGIN IMMEDIATE')
            active = conn.execute('SELECT COUNT(*) FROM portal_api_tokens WHERE owner=? AND revoked=0 AND expires>?', (session['owner'], now)).fetchone()[0]
            if active >= 10:
                raise HTTPException(429, '最多保留 10 个有效令牌，请先撤销不再使用的令牌')
            conn.execute('INSERT INTO portal_api_tokens(id,digest,owner,name,created,expires) VALUES (?,?,?,?,?,?)',
                         (token_id, hashlib.sha256(token.encode()).hexdigest(), session['owner'], name.strip(), now, now + days * 86400))
        audit(session['owner'], 'api_token_created', token_id)
        return {'id': token_id, 'token': token, 'expires': now + days * 86400,
                'message': '令牌只显示一次，权限与当前账号相同；复制的 cURL 可能包含令牌，请勿分享。'}

    @app.post('/web/api-tokens/personal')
    def personal_token(request: Request):
        session = require_session(request)
        now = time.time()
        created = False
        with service.database() as conn:
            schema(conn)
            conn.execute('BEGIN IMMEDIATE')
            saved = conn.execute('SELECT p.encrypted,t.id,t.expires,t.revoked FROM portal_personal_tokens p JOIN portal_api_tokens t ON t.id=p.token_id AND t.owner=p.owner WHERE p.owner=?', (session['owner'],)).fetchone()
            if saved and not saved['revoked'] and saved['expires'] > now:
                token = runtime_config.cipher().decrypt(saved['encrypted'].encode()).decode()
                token_id, expires = saved['id'], saved['expires']
            else:
                token_id, token = secrets.token_hex(16), 'stx_' + secrets.token_urlsafe(32)
                expires = now + 7 * 86400
                encrypted = runtime_config.cipher().encrypt(token.encode()).decode()
                conn.execute('INSERT INTO portal_api_tokens(id,digest,owner,name,created,expires) VALUES (?,?,?,?,?,?)',
                             (token_id, hashlib.sha256(token.encode()).hexdigest(), session['owner'], '个人接口 Token', now, expires))
                conn.execute('INSERT OR REPLACE INTO portal_personal_tokens(owner,token_id,encrypted) VALUES (?,?,?)',
                             (session['owner'], token_id, encrypted))
                created = True
        if created:
            audit(session['owner'], 'personal_api_token_created', token_id)
        return JSONResponse({'token':token,'expires':expires}, headers={'Cache-Control':'no-store'})

    @app.delete('/web/api-tokens/{token_id}')
    def token_revoke(token_id: str, request: Request):
        session = require_session(request)
        with service.database() as conn:
            schema(conn)
            result = conn.execute('UPDATE portal_api_tokens SET revoked=1 WHERE id=? AND owner=?', (token_id, session['owner']))
            if result.rowcount == 0:
                raise HTTPException(404, '令牌不存在')
        audit(session['owner'], 'api_token_revoked', token_id)
        return {'ok': True}

    @app.get('/web/tasks')
    def tasks(request: Request, q: str = '', page: int = 1):
        session = require_session(request)
        page = max(1, min(page, 100000))
        where, params = [], []
        if session['role'] != 'admin':
            where.append('owner=?')
            params.append(session['owner'])
        if q:
            where.append('(name LIKE ? OR owner LIKE ? OR id LIKE ?)')
            params.extend(['%' + q[:100] + '%'] * 3)
        condition = ' WHERE ' + ' AND '.join(where) if where else ''
        with service.database() as conn:
            total = conn.execute('SELECT COUNT(*) FROM jobs' + condition, params).fetchone()[0]
            rows = conn.execute('SELECT * FROM jobs' + condition + ' ORDER BY created DESC LIMIT 30 OFFSET ?', [*params, (page - 1) * 30]).fetchall()
            summary_where = ' WHERE owner=?' if session['role'] != 'admin' else ''
            summary_params = [session['owner']] if session['role'] != 'admin' else []
            counts = dict(conn.execute('SELECT status,COUNT(*) FROM jobs' + summary_where + ' GROUP BY status', summary_params).fetchall())
        result = []
        for row in rows:
            value = dict(row)
            value['detail'] = json.loads(value['detail'])
            value['report_ready'] = (service.job_dir(value['id']) / 'report.md').is_file()
            if value['kind'] == 'whitebox':
                value['target'] = '已上传项目代码'
            result.append(value)
        return {'items': result, 'total': total, 'page': page, 'counts': counts}

    @app.get('/web/report/{job_id}')
    def report_json(job_id: str, request: Request):
        session = require_session(request)
        service.owned_job(job_id, '__admin__' if session['role'] == 'admin' else session['owner'])
        path = service.job_dir(job_id) / 'report.json'
        if not path.is_file():
            raise HTTPException(409, '报告还未生成，请稍后刷新')
        return service.read_json(path, {'warnings': ['报告无法解析，请联系管理员']})

    @app.get('/web/admin/config')
    def config_get(request: Request):
        require_session(request, True)
        return runtime_config.public_settings()

    @app.put('/web/admin/config')
    async def config_put(request: Request):
        require_session(request, True)
        payload = await request.json()
        if not isinstance(payload, dict):
            raise HTTPException(400, '配置必须是对象')
        resolve_form_key(payload)
        try:
            saved = runtime_config.save_settings(payload)
        except (ValueError, TypeError, KeyError) as error:
            raise HTTPException(400, str(error))
        try:
            model_failover.reset_state(service.DATA, saved.get('revision', ''))
        except OSError:
            pass
        audit('__admin__', 'configuration_updated')
        return runtime_config.public_settings()

    @app.get('/web/admin/model-health')
    def model_health(request: Request):
        require_session(request, True)
        settings = runtime_config.get_settings() or runtime_config.defaults()
        revision = settings.get('revision', '')
        try:
            targets = runtime_config.model_targets(settings)
        except ValueError:
            targets = None
        backup = targets.get('backup') if targets else None
        state = model_failover.read_state(service.DATA, revision) if backup else model_failover.default_state(revision)
        if not backup:
            state['active'] = 'primary'
        active = state.get('active') if state.get('active') in ('primary', 'backup') else 'primary'
        target = (targets.get(active) if targets else None) or (targets.get('primary') if targets else None)
        return {'revision': revision, 'active': active,
                'active_role': '主模型' if active == 'primary' else '备用模型',
                'active_model': (target or {}).get('model_name', ''),
                'primary_model': ((targets or {}).get('primary') or {}).get('model_name', ''),
                'backup_enabled': bool(backup), 'backup_model': (backup or {}).get('model_name', ''),
                'changed_at': state.get('changed_at'), 'opened_at': state.get('opened_at'),
                'next_probe_at': state.get('next_probe_at'), 'last_probe_at': state.get('last_probe_at'),
                'last_probe_ok': state.get('last_probe_ok'), 'last_probe_error': state.get('last_probe_error'),
                'last_error': state.get('last_error'), 'switches': state.get('switches', 0),
                'server_time': time.time(), 'network_ready': os.environ.get('EGRESS_POLICY_ACK', '').lower() == 'true'}

    @app.post('/web/admin/test-model')
    async def test_model(request: Request):
        require_session(request, True)
        payload = await request.json()
        if not isinstance(payload, dict):
            raise HTTPException(400, '测试参数必须是对象')
        resolve_form_key(payload)
        role = payload.get('role', 'primary')
        if role not in ('primary', 'backup'):
            raise HTTPException(400, '测试角色不正确')
        config = dict(runtime_config.get_settings() or runtime_config.defaults())
        if role == 'backup':
            if not isinstance(payload.get('backup_api_type'), str) or not isinstance(payload.get('backup_api_base'), str) \
                    or not isinstance(payload.get('backup_model'), str) or not isinstance(payload.get('backup_api_key'), str):
                raise HTTPException(400, '请提交备用模型的接口格式、地址、模型和 Key')
            config['api_type'] = payload['backup_api_type'].strip()
            config['api_base'] = payload['backup_api_base'].strip()
            config['model'] = payload['backup_model'].strip()
            config['api_key'] = payload['backup_api_key'].strip()
            config['extra_headers'] = config.get('backup_extra_headers') or {}
            config['extra_body'] = config.get('backup_extra_body') or {}
            try:
                runtime_config.validate_model_connection(
                    {'api_type': config['api_type'], 'api_base': config['api_base'],
                     'extra_headers': config['extra_headers'], 'extra_body': config['extra_body']}, '备用模型')
            except (ValueError, TypeError) as error:
                raise HTTPException(400, str(error))
        else:
            for key in ('api_type', 'api_base', 'model', 'api_key'):
                if key not in payload or not isinstance(payload[key], str):
                    raise HTTPException(400, '请提交当前页面的接口格式、地址、模型和 Key')
                config[key] = payload[key].strip()
        # Test connection only: do not enable scans or persist this configuration.
        config['enabled'] = False
        if role == 'primary':
            try:
                runtime_config.validate_settings(config)
            except (ValueError, TypeError, KeyError) as error:
                raise HTTPException(400, str(error))
        question = payload.get('question', '')
        if not isinstance(question, str) or not question.strip() or len(question) > 4000:
            raise HTTPException(400, '请填写测试问题，最多 4000 个字符')
        result = await run_in_threadpool(probe_model, config, question.strip())
        result['role'] = role
        audit('__admin__', 'model_probe', role + ':' + ('success' if result['ok'] else 'failed'))
        return result

    @app.get('/web/admin/users')
    def users(request: Request):
        require_session(request, True)
        with service.database() as conn:
            schema(conn)
            rows = conn.execute('SELECT u.*, (SELECT COUNT(*) FROM jobs j WHERE j.owner=u.employee) AS task_count FROM portal_users u ORDER BY last_seen DESC LIMIT 1000').fetchall()
        return {'items': [dict(row) for row in rows]}

    @app.post('/web/admin/users/{employee}/toggle')
    def toggle_user(employee: str, request: Request):
        require_session(request, True)
        with service.database() as conn:
            schema(conn)
            conn.execute('UPDATE portal_users SET disabled=1-disabled WHERE employee=?', (employee,))
            conn.execute('DELETE FROM portal_sessions WHERE owner=?', (employee,))
            conn.execute('UPDATE portal_api_tokens SET revoked=1 WHERE owner=?', (employee,))
        audit('__admin__', 'user_toggled', employee)
        return {'ok': True}

    @app.post('/web/admin/password')
    async def password(request: Request):
        require_session(request, True)
        value = await request.json()
        new_password = value.get('new_password', '')
        if not isinstance(new_password, str) or not 6 <= len(new_password) <= 128:
            raise HTTPException(400, '新密码应为 6—128 个字符')
        with service.database() as conn:
            schema(conn)
            row = conn.execute('SELECT * FROM portal_admin WHERE id=1').fetchone()
            if not hmac.compare_digest(password_digest(str(value.get('current_password', '')), row['salt']), row['digest']):
                raise HTTPException(400, '当前密码不正确')
            salt = secrets.token_hex(16)
            conn.execute('UPDATE portal_admin SET salt=?,digest=? WHERE id=1', (salt, password_digest(new_password, salt)))
            conn.execute("DELETE FROM portal_sessions WHERE role='admin'")
            conn.execute("UPDATE portal_api_tokens SET revoked=1 WHERE owner='__admin__'")
        audit('__admin__', 'password_changed')
        return {'ok': True, 'relogin': True}


def resolve_form_key(payload):
    saved = None
    if payload.get('api_key_reference') or payload.get('backup_api_key_reference'):
        saved = runtime_config.get_settings() or {}
    if payload.get('api_key_reference'):
        if payload['api_key_reference'] != saved.get('revision'):
            raise HTTPException(409, '已保存的主模型 Key 已变化，请刷新页面后重试')
        payload['api_key'] = saved.get('api_key', '')
    elif 'api_key' in payload and payload['api_key'] == '':
        payload['clear_api_key'] = True
    if payload.get('backup_api_key_reference'):
        if payload['backup_api_key_reference'] != saved.get('revision'):
            raise HTTPException(409, '已保存的备用模型 Key 已变化，请刷新页面后重试')
        payload['backup_api_key'] = saved.get('backup_api_key', '')
    elif 'backup_api_key' in payload and payload['backup_api_key'] == '':
        payload['clear_backup_api_key'] = True


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args):
        return None


def probe_error_detail(text, config, *, truncate=True):
    """Keep useful upstream diagnostics while removing configured credentials."""
    text = str(text)
    secrets_to_hide = [config.get('api_key', '')]
    secrets_to_hide.extend(str(v) for v in config.get('extra_headers', {}).values())
    secrets_to_hide.extend(str(v) for v in config.get('provider_env', {}).values())
    for secret in sorted(filter(None, secrets_to_hide), key=len, reverse=True):
        text = text.replace(secret, '[已脱敏]')
    text = re.sub(r'(?i)(Bearer\s+)[^\s"\'<>]+', r'\1[已脱敏]', text)
    text = re.sub(r'(?i)(["\']?(?:api[_-]?key|access[_-]?token|authorization|password|secret)["\']?\s*[:=]\s*)("[^"\n]*"|\'[^\'\n]*\'|[^\s,;}]+)', r'\1"[已脱敏]"', text)
    if truncate and len(text) > 16000:
        return text[:16000] + '\n[内容过长，已截断]'
    return text


def _probe_model_basic(config, question=''):
    """Explicit admin-triggered paid probe. Does not run any returned tools."""
    config = runtime_config.connection_config(config)
    mode, model = config['api_type'], config['model']
    base = config['api_base'].rstrip('/')
    native_anthropic = model.startswith('anthropic/') and mode in ('auto', 'native')
    compatible = model.startswith('openai/') or mode in ('chat_completions', 'responses')
    if not compatible and not native_anthropic:
        return {'ok': False, 'message': '此供应商原生路由由 Strix/LiteLLM 处理，网页探测尚不支持。可使用 OpenAI 兼容网关或用授权演示任务验证；不代表该路由不能扫描。'}
    if not base:
        base = 'https://api.anthropic.com' if native_anthropic else 'https://api.openai.com/v1'
    name = model.split('/', 1)[1] if model.startswith(('openai/', 'anthropic/')) else model
    description = question or 'Connectivity check only. Call connectivity_probe with ok=true. Do not perform other work.'
    parameters = {'type': 'object', 'properties': {'ok': {'type': 'boolean'}}, 'required': ['ok'], 'additionalProperties': False}
    headers = {'Content-Type': 'application/json', **config['extra_headers']}
    if native_anthropic:
        endpoint = base if base.endswith('/messages') else base.removesuffix('/v1') + '/v1/messages'
        headers.update({'x-api-key': config['api_key'], 'anthropic-version': '2023-06-01'})
        body = {'model': name, 'max_tokens': 128, 'messages': [{'role': 'user', 'content': description}],
                'tools': [{'name': 'connectivity_probe', 'description': 'Connection test', 'input_schema': parameters}]}
    elif mode == 'responses':
        endpoint = base if base.endswith('/responses') else base + '/responses'
        body = {'model': name, 'input': description, 'tools': [{'type': 'function', 'name': 'connectivity_probe',
                'description': 'Connection test', 'parameters': parameters}], 'max_output_tokens': 128}
    else:
        endpoint = base if base.endswith('/chat/completions') else base + '/chat/completions'
        body = {'model': name, 'messages': [{'role': 'user', 'content': description}], 'max_tokens': 128,
                'tools': [{'type': 'function', 'function': {'name': 'connectivity_probe', 'description': 'Connection test', 'parameters': parameters}}]}
    if not native_anthropic and config['api_key']:
        headers['Authorization'] = 'Bearer ' + config['api_key']
    body.update(config['extra_body'])
    if question:
        body.pop('tools', None)
        body.pop('tool_choice', None)
        body.pop('parallel_tool_calls', None)
        body['max_output_tokens' if mode == 'responses' else 'max_tokens'] = 1024
    try:
        request = urllib.request.Request(endpoint, data=json.dumps(body).encode(), headers=headers)
        import model_calls
        value = model_calls.read_json(request, config, opener=urllib.request.build_opener(NoRedirect), timeout=25)
        calls = bool(value.get('choices', [{}])[0].get('message', {}).get('tool_calls'))
        calls = calls or any(item.get('type') in ('function_call', 'tool_use') for item in value.get('output', []) + value.get('content', []) if isinstance(item, dict))
        if question:
            content = value.get('choices', [{}])[0].get('message', {}).get('content')
            if isinstance(content, str):
                answer = content
            else:
                blocks = value.get('content', [])
                if isinstance(content, list):
                    blocks = content
                for item in value.get('output', []):
                    if isinstance(item, dict):
                        blocks += item.get('content', [])
                answer = '\n'.join(item.get('text', '') for item in blocks if isinstance(item, dict) and isinstance(item.get('text'), str))
            return {'ok': True, 'custom_question': True, 'message': '连接成功。自定义问答未检查工具调用能力。',
                    'answer': probe_error_detail(answer or '接口未返回文本回答。', config)}
        return {'ok': True, 'tool_calls': calls, 'message': '连接成功，已返回结构化工具调用。' if calls else '连接成功，但未返回结构化工具调用；Strix 可能无法正常执行扫描，请核对模型能力。'}
    except urllib.error.HTTPError as error:
        raw = error.read(65536).decode('utf-8', errors='replace')
        return {'ok': False, 'message': f'模型接口返回 HTTP {error.code}。',
                'detail': probe_error_detail(raw or str(error.reason), config), 'status_code': error.code}
    except Exception as error:
        return {'ok': False, 'message': f'连接未成功（{type(error).__name__}）。',
                'detail': probe_error_detail(str(error), config)}


def probe_model(config, question='你好，请简短介绍你能如何协助进行代码与系统安全分析。'):
    """Test a normal answer, then a harmless structured tool/result round trip."""
    answer = _probe_model_basic(config, question)
    result = {'ok':False, 'question_ok':bool(answer.get('ok') and answer.get('answer') and answer['answer']!='接口未返回文本回答。'),
              'tool_calls':False, 'tool_roundtrip':False, 'answer':answer.get('answer','')}
    if not result['question_ok']:
        return {**answer, **result, 'message':answer.get('message','问答测试失败'),
                'tool_message':'未执行：先完成问答测试'}
    value = runtime_config.connection_config(config)
    mode, model = value['api_type'], value['model']
    anthropic = model.startswith('anthropic/') and mode in ('auto','native')
    base = value['api_base'].rstrip('/') or ('https://api.anthropic.com' if anthropic else 'https://api.openai.com/v1')
    name = model.split('/',1)[1] if model.startswith(('openai/','anthropic/')) else model
    prompt = 'Call connectivity_probe with ok=true exactly once. After receiving its tool result, reply with the exact verification_code from that result. Do not invent a code.'
    schema = {'type':'object','properties':{'ok':{'type':'boolean'}},'required':['ok'],'additionalProperties':False}
    headers = {'Content-Type':'application/json',**value['extra_headers']}
    if anthropic:
        endpoint = base if base.endswith('/messages') else base.removesuffix('/v1')+'/v1/messages'
        headers.update({'x-api-key':value['api_key'],'anthropic-version':'2023-06-01'})
        body = {'model':name,'max_tokens':512,'messages':[{'role':'user','content':prompt}],
                'tools':[{'name':'connectivity_probe','description':'Harmless connection probe','input_schema':schema}]}
    elif mode == 'responses':
        endpoint = base if base.endswith('/responses') else base+'/responses'
        body = {'model':name,'input':[{'role':'user','content':prompt}],'max_output_tokens':512,
                'tools':[{'type':'function','name':'connectivity_probe','description':'Harmless connection probe','parameters':schema}]}
    else:
        endpoint = base if base.endswith('/chat/completions') else base+'/chat/completions'
        body = {'model':name,'messages':[{'role':'user','content':prompt}],'max_tokens':512,
                'tools':[{'type':'function','function':{'name':'connectivity_probe','description':'Harmless connection probe','parameters':schema}}]}
    if not anthropic and value['api_key']:
        headers['Authorization']='Bearer '+value['api_key']
    body = {**value['extra_body'],**body,'stream':False}
    # Provider extras must not force an unrelated tool choice or output format.
    for key in ('tool_choice','parallel_tool_calls','response_format'):
        body.pop(key,None)
    def call(payload):
        request = urllib.request.Request(endpoint,data=json.dumps(payload).encode(),headers=headers)
        import model_calls
        return model_calls.read_json(request, value, opener=urllib.request.build_opener(NoRedirect), timeout=25)
    try:
        first = call(body)
        message = first.get('choices',[{}])[0].get('message',{}) if not anthropic and mode!='responses' else {}
        if anthropic:
            calls = [v for v in first.get('content',[]) if v.get('type')=='tool_use']
        elif mode=='responses':
            calls = [v for v in first.get('output',[]) if v.get('type')=='function_call']
        else:
            calls = message.get('tool_calls') or []
        if not calls:
            result.update(message='问答成功，工具调用测试未通过。',tool_message='未收到结构化工具调用，不能仅凭聊天成功认定可用于 Strix。')
            return result
        if len(calls)!=1:
            raise ValueError('测试工具必须恰好调用一次')
        tool = calls[0]
        function = tool if anthropic or mode=='responses' else tool.get('function',{})
        args = function.get('input',{}) if anthropic else function.get('arguments','')
        args = json.loads(args) if isinstance(args,str) else args
        identifier = tool.get('call_id') if mode=='responses' else tool.get('id')
        if function.get('name')!='connectivity_probe' or not isinstance(args,dict) or set(args)!={'ok'} or args.get('ok') is not True or not isinstance(identifier,str) or not identifier:
            raise ValueError('工具名称、参数或调用 ID 不符合协议')
        result['tool_calls']=True
        code='probe-'+secrets.token_hex(8)
        output=json.dumps({'ok':True,'verification_code':code})
        if anthropic:
            body['messages'] += [{'role':'assistant','content':first['content']},
                                 {'role':'user','content':[{'type':'tool_result','tool_use_id':identifier,'content':output}]}]
        elif mode=='responses':
            body['input'] += first['output'] + [{'type':'function_call_output','call_id':identifier,'output':output}]
        else:
            assistant={'role':'assistant','content':message.get('content'),'tool_calls':calls}
            body['messages'] += [assistant,{'role':'tool','tool_call_id':identifier,'content':output}]
        final = call(body)
        if anthropic:
            text='\n'.join(v.get('text','') for v in final.get('content',[]) if v.get('type')=='text')
        elif mode=='responses':
            text='\n'.join(c.get('text','') for v in final.get('output',[]) for c in v.get('content',[]) if isinstance(c,dict))
        else:
            text=final.get('choices',[{}])[0].get('message',{}).get('content') or ''
        result['tool_roundtrip']=isinstance(text,str) and code in text
        result['ok']=result['tool_roundtrip']
        result['message']='问答与工具调用验证通过。' if result['ok'] else '问答成功，但工具结果回传测试未通过。'
        result['tool_message']='结构化调用、参数、调用 ID 和工具结果回传均通过。' if result['ok'] else '接口未能在后续回答中正确使用工具返回的校验码。'
    except urllib.error.HTTPError as error:
        result.update(message=f'问答成功，工具调用测试返回 HTTP {error.code}。',
                      tool_message='工具接口或结果回传未通过',status_code=error.code,
                      detail=probe_error_detail(error.read(65536).decode('utf-8','replace') or str(error.reason),value))
    except Exception as error:
        result.update(message='问答成功，工具调用验证未通过。',tool_message='工具协议或网络异常',
                      detail=probe_error_detail(str(error),value))
    return result

