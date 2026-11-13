"""Administrator-only, credential-redacted model request and response records."""
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import urlsplit, urlunsplit
import uuid

MAX_RECORD_BYTES = 8 * 1024 * 1024


def sanitize(value, secrets=()):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if re.fullmatch(r'(?i)(authorization|api[_-]?key|password|cookie|set-cookie|access[_-]?token|refresh[_-]?token)', key):
                result[key] = '[已脱敏]'
            elif key in ('data', 'url') and isinstance(item, str) and (item.startswith('data:image/') or len(item) > 50000 and value.get('type') in ('base64','image')):
                result[key] = '[图片数据省略]'
            else:
                result[key] = sanitize(item, secrets)
        return result
    if isinstance(value, list):
        return [sanitize(item, secrets) for item in value]
    if not isinstance(value, str):
        return value
    for secret in sorted(set(filter(None, secrets)),key=len,reverse=True):
        value = value.replace(secret, '[已脱敏]')
    value = re.sub(r'(?i)(Bearer\s+)[^\s"\'<>]+', r'\1[已脱敏]', value)
    value = re.sub(r'(?im)((?:Cookie|Set-Cookie)\s*:\s*)[^\r\n]+', r'\1[已脱敏]', value)
    return value


class CallDetails:
    def __init__(self, root):
        self.root = Path(root) / 'model_call_details'
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.secrets = [os.environ.get('LLM_API_KEY','')]
        path = os.environ.get('STRIX_MODEL_REDACTION_FILE')
        if path:
            self.secrets.extend(json.loads(Path(path).read_text()))

    def _save(self, path, record):
        safe = sanitize(record, self.secrets)
        data = json.dumps(safe, ensure_ascii=False, indent=2)
        if len(data.encode('utf-8')) > MAX_RECORD_BYTES:
            safe = {key:value for key,value in safe.items() if key not in ('request','response')}
            safe['detail_truncated'] = True
            safe['detail_preview'] = data.encode('utf-8')[:MAX_RECORD_BYTES//2].decode('utf-8',errors='ignore')
            safe['notice'] = '单次记录超过 8 MiB，仅保存脱敏预览。模型实际请求未被截断。'
            data = json.dumps(safe,ensure_ascii=False,indent=2)
        temporary = path.with_suffix('.'+uuid.uuid4().hex+'.tmp')
        with temporary.open('x',encoding='utf-8') as stream:
            os.chmod(temporary,0o600)
            stream.write(data)
        os.replace(temporary,path)
        summary = {key:safe.get(key) for key in ('id','model','model_role','started','finished','status','state')}
        index = path.with_suffix('.meta')
        temporary_index = index.with_suffix('.'+uuid.uuid4().hex+'.tmp')
        with temporary_index.open('x',encoding='utf-8') as stream:
            os.chmod(temporary_index,0o600)
            json.dump(summary,stream,ensure_ascii=False)
        os.replace(temporary_index,index)

    def start(self, identifier, request, role=None):
        parsed = urlsplit(str(request.url))
        url = urlunsplit((parsed.scheme, parsed.netloc.rsplit('@',1)[-1], parsed.path, '', ''))
        for name,value in request.headers.items():
            if re.search('(?i)authorization|cookie|token|key|password',name) and value:
                self.secrets.append(value)
                if value.lower().startswith('bearer '):self.secrets.append(value[7:])
        record = {'id':identifier,'started':time.time(),'finished':None,'status':None,
                  'url':url,'model':json.loads(request.content).get('model'),'model_role':role,
                  'request':json.loads(request.content),'response':None,'state':'running'}
        filename = f'{time.time_ns():020d}-{identifier}.json'
        path = self.root / filename
        self._save(path,record)
        return path,record

    def finish(self, handle, response=None, status=None, error=None):
        path, record = handle
        record.update(finished=time.time(),status=status,response=response,state='finished')
        if error:record['error']=error
        if status in (429,432,433):record['state']='rate_limited'
        self._save(path,record)
