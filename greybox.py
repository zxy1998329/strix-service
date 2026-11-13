"""Task-scoped encrypted credentials and conservative authenticated HTTP probes."""
import json
import re
from urllib.parse import urlsplit
from fastapi import HTTPException
import runtime_config


def validate(payload, target):
    accounts = payload.get('accounts', [])
    if not isinstance(accounts, list) or not 1 <= len(accounts) <= 5:
        raise ValueError('请提供 1—5 个测试账号')
    result = {'accounts': [], 'instructions': str(payload.get('instructions', ''))[:4000]}
    for index, account in enumerate(accounts):
        if not isinstance(account, dict):
            raise ValueError('账号格式不正确')
        a = {k: str(account.get(k, '')).strip() for k in ('label','role','method','username','password','cookie','token','login_path','verify_path','success_text','steps')}
        a['password'] = str(account.get('password',''))
        if not a['label']:
            raise ValueError(f'请填写账号 {index+1} 的账号名称')
        if any(len(v) > 8000 or '\x00' in v for v in a.values()):
            raise ValueError('账号字段过长或包含非法字符')
        if a['method'] not in ('password','cookie','bearer','headers'):
            raise ValueError('不支持的登录方式')
        required = {'password':('username','password'), 'cookie':('cookie',), 'bearer':('token',), 'headers':()}[a['method']]
        if any(not a[k] for k in required):
            raise ValueError(f"{a['label']} 的登录凭据不完整")
        if '\r' in a['cookie']+a['token'] or '\n' in a['cookie']+a['token']:
            raise ValueError('Cookie / Token 不得包含换行')
        if a['method'] == 'headers':
            entries = account.get('auth', [])
            if not isinstance(entries,list) or len(entries)>30:
                raise ValueError('最多添加 30 条 Cookie / Header')
            a['auth'] = []
            seen = set()
            for entry in entries:
                if not isinstance(entry,dict):
                    raise ValueError('Cookie / Header 格式不正确')
                kind,name,value = entry.get('type'),str(entry.get('name','')).strip(),str(entry.get('value',''))
                if kind not in ('cookie','header') or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",name) or not value or len(value)>8000 or any(ord(c)<32 or ord(c)==127 for c in value):
                    raise ValueError('Cookie / Header 名称和值必填，且不能包含控制字符')
                if kind=='cookie' and ';' in value:
                    raise ValueError('每条 Cookie 只填写一个值，不包含分号')
                if kind=='header' and name.lower() in ('host','content-length','transfer-encoding','connection','proxy-authorization','proxy-connection','upgrade','cookie'):
                    raise ValueError('此请求头不能自定义；Cookie 请通过 Cookie 条目添加')
                identity=(kind,name.lower() if kind=='header' else name)
                if identity in seen:
                    raise ValueError('Cookie / Header 名称不能重复')
                seen.add(identity)
                a['auth'].append({'type':kind,'name':name,'value':value})
        for k in ('login_path','verify_path'):
            p = a[k]
            if p and (not p.startswith('/') or p.startswith('//') or '\\' in p or urlsplit(p).netloc or '#' in p):
                raise ValueError('登录与验证路径必须是本站相对路径，例如 /login')
        result['accounts'].append(a)
    return result


def store(root, value):
    path = root / 'auth.enc'
    path.write_bytes(runtime_config.cipher().encrypt(json.dumps(value, ensure_ascii=False).encode()))
    path.chmod(0o600)


def load(root):
    path = root / 'auth.enc'
    return json.loads(runtime_config.cipher().decrypt(path.read_bytes())) if path.is_file() else {}


def redact(value, auth, *, truncate=True):
    from portal import probe_error_detail
    secrets = [a.get(k,'') for a in auth.get('accounts',[]) for k in ('username','password','cookie','token') if a.get(k)]
    secrets += [entry['value'] for a in auth.get('accounts',[]) for entry in a.get('auth',[]) if entry.get('value')]
    if isinstance(value, dict):
        return {k: redact(v, auth, truncate=truncate) for k,v in value.items()}
    if isinstance(value, list):
        return [redact(v, auth, truncate=truncate) for v in value]
    if isinstance(value,str):
        return probe_error_detail(value, {'extra_headers': {str(i):v for i,v in enumerate(secrets)}}, truncate=truncate)
    return value


# Runs only inside the configured sandbox network. No redirects or cross-origin login.
PROBE_SCRIPT = r'''
import sys,json,urllib.request,urllib.error
value=json.load(sys.stdin)
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args): return None
results=[]
for a in value['accounts']:
 r={'label':a['label'],'state':'unknown','message':'无法确认登录状态'}
 if True:
  try:
   headers={'Cookie':a['cookie']} if a['method']=='cookie' else ({'Authorization':'Bearer '+a['token']} if a['method']=='bearer' else {})
   if a['method']=='headers':
    headers={e['name']:e['value'] for e in a.get('auth',[]) if e['type']=='header'}
    cookies=[e['name']+'='+e['value'] for e in a.get('auth',[]) if e['type']=='cookie']
    if cookies: headers['Cookie']='; '.join(cookies)
   path=a['verify_path'] or (a['login_path'] if a['method']=='password' else '') or '/'
   url=value['target'].rstrip('/')+path
   r['url']=url
   req=urllib.request.Request(url,headers=headers)
   with urllib.request.build_opener(NoRedirect).open(req,timeout=15) as resp:
    text=resp.read(1024*1024).decode('utf-8','replace');code=resp.status
   r.update(state='success' if code==200 else 'failed',message='接口调用成功（HTTP 200）' if code==200 else '接口未返回 HTTP 200',http_status=code)
   if a['method']=='password': r['message']+='；仅验证登录页可访问，账号密码登录将在扫描中执行'
  except urllib.error.HTTPError as e:
   r.update(state='failed',http_status=e.code,message='接口未返回 HTTP 200；未跟随跳转')
  except Exception as e: r.update(message='验证请求异常：'+type(e).__name__)
 results.append(r)
print(json.dumps(results,ensure_ascii=False))
'''


def verify(job, root, settings):
    import os, subprocess, uuid
    from service import validate_target
    if os.environ.get('EGRESS_POLICY_ACK','').lower() != 'true':
        raise RuntimeError('Sandbox network policy not acknowledged')
    auth = load(root)
    target = validate_target(job['target'], settings)
    name = 'strix-auth-' + uuid.uuid4().hex[:16]
    command = ['docker','run','--rm','--name',name,'--network',os.environ.get('STRIX_DOCKER_SANDBOX_NETWORK','bridge'),
               '--cap-drop=ALL','--security-opt=no-new-privileges','--memory=256m','--cpus=1',
               '--entrypoint','python3','-i',os.environ.get('STRIX_IMAGE','ghcr.io/usestrix/strix-sandbox:1.3.0'),'-c',PROBE_SCRIPT]
    try:
        process = subprocess.run(command,input=json.dumps({**auth,'target':target}),text=True,capture_output=True,timeout=170)
        if process.returncode:
            raise RuntimeError('登录验证沙箱执行失败')
        result = json.loads(process.stdout)
    finally:
        subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=15)
    return redact(result,auth)


def install(app):
    import service
    from fastapi import Depends
    from pydantic import BaseModel, Field
    class RequestModel(BaseModel):
        target: str = Field(max_length=2048)
        name: str = Field(default='灰盒测试',max_length=100)
        accounts: list[dict] = Field(min_length=1,max_length=5)
        instructions: str = Field(default='',max_length=4000)
        authorized: bool = False
        source_job_id: str = Field(default='',max_length=32)
    def submit(request, owner, kind):
        import uuid, shutil
        service.acceptance(request.authorized)
        try:
            target = service.validate_target(request.target)
            from task_reuse import resolve_accounts
            payload=request.model_dump()
            payload['accounts']=resolve_accounts(payload['accounts'],request.source_job_id,owner)
            auth = validate(payload,target)
        except ValueError as error:
            raise HTTPException(400,str(error))
        job_id = uuid.uuid4().hex
        root = service.job_dir(job_id)
        root.mkdir(parents=True,mode=0o700)
        try:
            store(root,auth)
            service.enqueue(job_id,owner,kind,request.name,target)
        except Exception:
            shutil.rmtree(root)
            raise
        return {'id':job_id,'status':'queued','status_url':f'/v1/scans/{job_id}'}
    @app.post('/v1/scans/greybox',status_code=202)
    def scan(request: RequestModel,owner: str=Depends(service.authenticate)):
        return submit(request,owner,'greybox')
    @app.post('/v1/scans/greybox/verify',status_code=202)
    def check(request: RequestModel,owner: str=Depends(service.authenticate)):
        return submit(request,owner,'greybox_verify')
