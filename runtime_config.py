"""Encrypted settings and per-job snapshots shared by the web process and worker."""
import ipaddress
import json
import os
import re
import secrets
import time
import fcntl
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet

PROVIDER_ENV = {'AZURE_API_KEY', 'AZURE_API_BASE', 'AZURE_API_VERSION', 'AWS_ACCESS_KEY_ID',
                'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_REGION_NAME', 'AWS_REGION',
                'GEMINI_API_KEY', 'GOOGLE_API_KEY', 'VERTEXAI_PROJECT', 'VERTEXAI_LOCATION',
                'ANTHROPIC_API_KEY', 'OPENROUTER_API_KEY'}


def tables(conn):
    conn.execute('CREATE TABLE IF NOT EXISTS portal_settings (id INTEGER PRIMARY KEY, encrypted TEXT NOT NULL)')


def cipher():
    import service
    path = service.DATA / '.settings-key'
    path.parent.mkdir(parents=True, exist_ok=True)
    with (service.DATA / '.settings-key.lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not path.exists():
            with path.open('xb') as file:
                file.write(Fernet.generate_key())
            path.chmod(0o600)
        return Fernet(path.read_bytes())


def get_settings():
    import service
    with service.database() as conn:
        tables(conn)
        row = conn.execute('SELECT encrypted FROM portal_settings WHERE id=1').fetchone()
    return json.loads(cipher().decrypt(row[0].encode())) if row else None


def defaults():
    return {'model': os.environ.get('STRIX_LLM', 'openai/deepseek-ai/DeepSeek-V3.2'),
            'api_base': os.environ.get('LLM_API_BASE', 'https://api.siliconflow.cn/v1'),
            'api_type': 'auto', 'api_key': '', 'extra_headers': {},
            'extra_body': {}, 'provider_env': {}, 'streaming': False, 'reasoning_effort': 'high',
            'backup_enabled': False, 'backup_model': '', 'backup_api_base': '',
            'backup_api_type': 'openai', 'backup_api_key': '',
            'backup_extra_headers': {}, 'backup_extra_body': {},
            'scope_restrictions_enabled': False, 'enabled': False, 'allowed_hosts': os.environ.get('ALLOWED_TARGET_HOSTS', ''),
            'allowed_cidrs': os.environ.get('ALLOWED_TARGET_CIDRS', ''),
            'allowed_ports': os.environ.get('ALLOWED_TARGET_PORTS', '80,443'),
            'timeout': 0, 'max_turns': 0, 'budget': 0, 'revision': '', 'updated': None}


def backup_config(value):
    """Map the optional backup fields onto the same shape as the primary model."""
    return {'model': value.get('backup_model', ''), 'api_base': value.get('backup_api_base', ''),
            'api_type': value.get('backup_api_type', 'openai'), 'api_key': value.get('backup_api_key', ''),
            'extra_headers': value.get('backup_extra_headers', {}),
            'extra_body': value.get('backup_extra_body', {}), 'provider_env': {},
            'streaming': value.get('streaming', False), 'reasoning_effort': value.get('reasoning_effort', 'high')}


def backup_configured(value):
    return bool(value.get('backup_enabled') or str(value.get('backup_model', '')).strip()
                or str(value.get('backup_api_base', '')).strip())


def backup_active(value):
    return bool(value.get('backup_enabled') and str(value.get('backup_model', '')).strip())


def protocol(value):
    """Resolve the user-facing protocol for a primary/backup configuration."""
    api_type = str(value.get('api_type', 'auto')).lower()
    model = str(value.get('model', '')).strip()
    if api_type in ('anthropic', 'native') or (api_type not in ('openai', 'chat_completions', 'responses') and model.startswith('anthropic/')):
        return 'anthropic'
    return 'openai'


def validate_model_connection(value, label):
    base = value.get('api_base', '')
    if base:
        parsed = urlsplit(base)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query:
            raise ValueError(f'{label}接口地址应为 HTTP(S) 地址，不要在地址中填写密码或查询参数')
    if value.get('api_type') not in ('openai', 'anthropic', 'auto', 'chat_completions', 'responses', 'native'):
        raise ValueError(f'不支持的{label}接口格式')
    for key in ('extra_headers', 'extra_body'):
        if not isinstance(value.get(key), dict):
            raise ValueError(f'{label}{key} 必须为 JSON 对象')
        if len(json.dumps(value[key])) > 32000:
            raise ValueError(f'{label}{key} 内容过长')
    if any(not isinstance(k, str) or not isinstance(v, str) or '\n' in k + v or '\r' in k + v
           for k, v in value['extra_headers'].items()):
        raise ValueError(f'{label}自定义请求头必须为字符串，且不能包含换行')
    if set(value['extra_body']) & {'model', 'messages', 'input', 'tools', 'stream'}:
        raise ValueError(f'{label}自定义请求体不能覆盖 model/messages/input/tools/stream')


def validate_settings(value):
    if not isinstance(value.get('model'), str) or not 1 <= len(value['model']) <= 200:
        raise ValueError('请填写模型名称（包含 Strix 提供商前缀）')
    if value.get('reasoning_effort') not in ('none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max'):
        raise ValueError('推理强度不正确')
    validate_model_connection(value, '')
    if not isinstance(value.get('provider_env'), dict):
        raise ValueError('provider_env 必须为 JSON 对象')
    if len(json.dumps(value['provider_env'])) > 32000:
        raise ValueError('provider_env 内容过长')
    if any(k not in PROVIDER_ENV or not isinstance(v, str) for k, v in value['provider_env'].items()):
        raise ValueError('供应商环境变量名称不受支持，请查看页面支持列表')
    if type(value.get('backup_enabled', False)) is not bool:
        raise ValueError('备用模型开关必须为布尔值')
    if backup_configured(value):
        backup = backup_config(value)
        if not isinstance(backup['model'], str) or not 1 <= len(backup['model'].strip()) <= 200:
            raise ValueError('请填写备用模型名称')
        validate_model_connection(backup, '备用模型')
        if protocol(value) != protocol(backup):
            raise ValueError('备用模型必须与主模型使用相同的接口格式（OpenAI 或 Anthropic）')
    if not ((int(value['timeout']) == 0 or 30 <= int(value['timeout']) <= 14400) and 0 <= int(value['max_turns']) <= 2147483647 and 0 <= float(value['budget']) <= 100):
        raise ValueError('限制设为 0 表示不限制；非零时限范围 30—14400 秒，预算最多 100 美元')
    if type(value.get('scope_restrictions_enabled', False)) is not bool:
        raise ValueError('扫描范围限制必须为开关值')
    if value.get('scope_restrictions_enabled', False):
        for host in value['allowed_hosts'].split(','):
            if host.strip() and (any(c in host for c in '/\\@*?#') or any(c.isspace() for c in host.strip())):
                raise ValueError('目标域名填写精确域名或 IP，多个以逗号分隔，不包含协议或通配符')
        for cidr in value['allowed_cidrs'].split(','):
            if cidr.strip():
                ipaddress.ip_network(cidr.strip())
        ports = [int(x.strip()) for x in value['allowed_ports'].split(',') if x.strip()]
        if not ports or any(not 1 <= port <= 65535 for port in ports):
            raise ValueError('目标端口不正确')
    if value.get('enabled') and os.environ.get('EGRESS_POLICY_ACK', '').lower() != 'true':
        raise ValueError('部署环境尚未确认扫描网络策略，需部署管理员设置 EGRESS_POLICY_ACK')
    return value


def save_settings(incoming):
    import service
    current = get_settings() or defaults()
    # Blank secret inputs retain saved values; explicit reset requires {} or clear_api_key.
    for key in defaults():
        if key in incoming and key not in ('revision', 'updated'):
            if key in ('api_key', 'backup_api_key', 'extra_headers', 'backup_extra_headers', 'provider_env') and incoming[key] in ('', None):
                continue
            current[key] = incoming[key]
    if incoming.get('clear_api_key'):
        current['api_key'] = ''
    if incoming.get('clear_backup_api_key'):
        current['backup_api_key'] = ''
    validate_settings(current)
    current['revision'] = secrets.token_hex(8)
    current['updated'] = time.time()
    encrypted = cipher().encrypt(json.dumps(current).encode()).decode()
    with service.database() as conn:
        tables(conn)
        conn.execute('INSERT OR REPLACE INTO portal_settings (id,encrypted) VALUES (1,?)', (encrypted,))
    return current


def public_settings():
    value = dict(get_settings() or defaults())
    for key in ('rate_requests', 'rate_input_tokens', 'rate_output_tokens'):
        value.pop(key, None)
    value.setdefault('scope_restrictions_enabled', False)
    key = value.pop('api_key', '')
    value['api_key_present'] = bool(key)
    value['api_key_masked'] = (key[:4] + '••••••••' + key[-4:]) if len(key) > 10 else ('••••••••' if key else '')
    backup_key = value.pop('backup_api_key', '')
    value['backup_api_key_present'] = bool(backup_key)
    value['backup_api_key_masked'] = (backup_key[:4] + '••••••••' + backup_key[-4:]) if len(backup_key) > 10 else ('••••••••' if backup_key else '')
    value['saved_header_names'] = list(value.pop('extra_headers', {}))
    value['saved_backup_header_names'] = list(value.pop('backup_extra_headers', {}))
    value['saved_provider_names'] = list(value.pop('provider_env', {}))
    value['provider_env_supported'] = sorted(PROVIDER_ENV)
    value['network_ready'] = os.environ.get('EGRESS_POLICY_ACK', '').lower() == 'true'
    value['sandbox_network'] = os.environ.get('STRIX_DOCKER_SANDBOX_NETWORK', '')
    return value


def snapshot(root):
    value = get_settings()
    if value:
        (root / 'settings.enc').write_bytes(cipher().encrypt(json.dumps(value).encode()))
    return value


def for_job(root):
    path = root / 'settings.enc'
    return json.loads(cipher().decrypt(path.read_bytes())) if path.exists() else get_settings()


def connection_config(value):
    """Map the two user-facing protocol choices to Strix's internal provider routing."""
    value = dict(value)
    api_type = value.get('api_type')
    if api_type in ('openai', 'anthropic'):
        model = value['model'].strip()
        for prefix in ('openai/', 'anthropic/'):
            if model.startswith(prefix):
                model = model[len(prefix):]
                break
        if not model:
            raise ValueError('请填写有效模型名称')
        value['model'] = api_type + '/' + model
        value['api_type'] = 'chat_completions' if api_type == 'openai' else 'native'
    return value


def _model_target(config, role):
    value = connection_config(config)
    model = value['model']
    return {'role': role, 'api_type': value['api_type'], 'protocol': protocol(value),
            'api_base': value.get('api_base') or '', 'model': model,
            'model_name': model.split('/', 1)[1] if model.startswith(('openai/', 'anthropic/')) else model,
            'api_key': value.get('api_key') or '',
            'extra_headers': value.get('extra_headers') or {},
            'extra_body': value.get('extra_body') or {}}


def model_targets(value):
    """Return the primary/backup connection targets used by the request router."""
    if not value:
        return None
    primary = _model_target(value, 'primary')
    if not backup_active(value):
        return {'revision': value.get('revision', ''), 'primary': primary, 'backup': None}
    backup = _model_target(backup_config(value), 'backup')
    if primary['protocol'] != backup['protocol']:
        raise ValueError('备用模型必须与主模型使用相同的接口格式')
    return {'revision': value.get('revision', ''), 'primary': primary, 'backup': backup}


def model_environment(value):
    if not value:
        return {}
    value = connection_config(value)
    env = {'STRIX_LLM': value['model'], 'LLM_DISABLE_STREAMING': 'false' if value['streaming'] else 'true',
           'STRIX_REASONING_EFFORT': value['reasoning_effort']}
    if value['api_base']:
        env['LLM_API_BASE'] = value['api_base']
    if value['api_key']:
        env['LLM_API_KEY'] = value['api_key']
    if value['api_type'] in ('chat_completions', 'responses'):
        env['STRIX_API_TYPE'] = value['api_type']
    for field, alias in [('extra_headers', 'LLM_EXTRA_HEADERS'), ('extra_body', 'LLM_EXTRA_BODY')]:
        if value[field]:
            env[alias] = json.dumps(value[field])
    env.update(value['provider_env'])
    return env
