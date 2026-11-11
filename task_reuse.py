"""Reuse task inputs, never the previous task's model configuration."""
import copy
import os
import stat
from pathlib import Path
from fastapi import Depends, HTTPException


def mask(value):
    return value[:4]+'••••••••'+value[-4:] if len(value)>10 else ('••••••••' if value else '')


def auth_references(auth):
    references={}
    for i, account in enumerate(auth.get('accounts',[])):
        for key in ('password','cookie','token'):
            if account.get(key):references[f'{i}.{key}']=account[key]
        for j, entry in enumerate(account.get('auth',[])):
            references[f'{i}.auth.{j}']=entry['value']
    return references


def public_accounts(auth):
    result=copy.deepcopy(auth.get('accounts',[]))
    for i, account in enumerate(result):
        refs={}
        for key in ('password','cookie','token'):
            if account.get(key):
                refs[key]=f'{i}.{key}'
                account[key]=mask(account[key])
        if refs:account['secret_refs']=refs
        for j, entry in enumerate(account.get('auth',[])):
            entry['value_reference']=f'{i}.auth.{j}'
            entry['value']=mask(entry['value'])
    return result


def resolve_accounts(accounts, source_job_id, owner):
    import service,greybox
    result=copy.deepcopy(accounts)
    references={}
    if source_job_id:
        old=service.owned_job(source_job_id,owner)
        if old['kind'] not in ('greybox','greybox_verify'):
            raise ValueError('原任务不是灰盒任务')
        references=auth_references(greybox.load(service.job_dir(source_job_id)))
    def resolve(reference, shown):
        if not isinstance(reference,str) or reference not in references:
            raise ValueError('复用凭据已不可用，请重新填写')
        value=references[reference]
        if shown!=mask(value):
            raise ValueError('凭据已修改，请移除旧凭据引用后提交新值')
        return value
    for account in result:
        secret_refs=account.pop('secret_refs',{})
        if not isinstance(secret_refs,dict):raise ValueError('无效的凭据引用')
        for key, reference in secret_refs.items():
            if key not in ('password','cookie','token'):
                raise ValueError('无效的凭据字段')
            account[key]=resolve(reference,account.get(key))
        entries=account.get('auth',[])
        if not isinstance(entries,list) or any(not isinstance(entry,dict) for entry in entries):
            raise ValueError('无效的 Cookie / Header 配置')
        for entry in entries:
            if 'value_reference' in entry:
                entry['value']=resolve(entry.pop('value_reference'),entry.get('value'))
    return result


def copy_project(source_job_id, owner, destination):
    import service
    old=service.owned_job(source_job_id,owner)
    if old['kind']!='whitebox':
        raise HTTPException(400,'原任务不是白盒任务')
    source=service.job_dir(source_job_id)/'source'
    if source.is_symlink() or not source.is_dir():
        raise HTTPException(409,'原任务项目文件已不可用，请重新上传 ZIP')
    files=[];total=0
    for current,dirs,names in os.walk(source,followlinks=False):
        for name in dirs:
            if (Path(current)/name).is_symlink():
                raise HTTPException(400,'原项目包含不安全的符号链接，请重新上传')
        for name in names:
            path=Path(current)/name
            info=path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise HTTPException(400,'原项目包含不安全的文件类型，请重新上传')
            total+=info.st_size;files.append((path,path.relative_to(source)))
            if total>service.EXPANDED_LIMIT or len(files)>service.MAX_FILES:
                raise HTTPException(413,'原项目超过当前文件限制，请重新上传')
    if not files:
        raise HTTPException(409,'原项目为空，请重新上传 ZIP')
    destination.mkdir(parents=True,mode=0o700)
    copied=0
    for source_file,relative in files:
        target=destination/relative
        target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with source_file.open('rb') as src,target.open('xb') as dst:
            while chunk:=src.read(1024*1024):
                copied+=len(chunk)
                if copied>service.EXPANDED_LIMIT:
                    raise HTTPException(413,'原项目读取大小超过限制')
                dst.write(chunk)


def install(app):
    import service,greybox
    @app.get('/v1/scans/{job_id}/reuse')
    def inputs(job_id: str,owner: str=Depends(service.authenticate)):
        old=service.owned_job(job_id,owner)
        kind='greybox' if old['kind']=='greybox_verify' else old['kind']
        if kind not in ('whitebox','blackbox','greybox'):
            raise HTTPException(400,'此任务类型不支持再次检测')
        root=service.job_dir(job_id)
        auth=greybox.load(root) if kind=='greybox' else {}
        source=root/'source'
        return {'source_job_id':job_id,'kind':kind,'name':old['name'],'target':old['target'] if kind!='whitebox' else '',
                'instructions':auth.get('instructions','') if kind=='greybox' else service.read_json(root/'requirements.json',{}).get('instructions',''),
                'project_available':kind=='whitebox' and source.is_dir() and not source.is_symlink(),
                'accounts':public_accounts(auth) if kind=='greybox' else [],
                'model_policy':'latest_at_submission'}
