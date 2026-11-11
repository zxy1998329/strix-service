"""Owner-scoped, read-only view of the inputs saved for an existing task."""
import copy
from fastapi import Depends


def mask(value):
    return value[:4]+'••••••••'+value[-4:] if len(value)>10 else ('••••••••' if value else '')


def install(app):
    import service, greybox

    @app.get('/v1/scans/{job_id}/submission')
    def submission(job_id: str, owner: str=Depends(service.authenticate)):
        old=service.owned_job(job_id,owner)
        root=service.job_dir(job_id)
        is_grey=old['kind'] in ('greybox','greybox_verify')
        auth=greybox.load(root) if is_grey else {}
        accounts=copy.deepcopy(auth.get('accounts',[]))
        for account in accounts:
            account.pop('secret_refs',None)
            for key in ('password','cookie','token'):
                if account.get(key):account[key]=mask(account[key])
            for entry in account.get('auth',[]):
                entry['value']=mask(entry.get('value',''))
                entry.pop('value_reference',None)
        source=root/'source'
        return {'kind':old['kind'],'name':old['name'],'created':old['created'],
                'target':'' if old['kind']=='whitebox' else old['target'],
                'instructions':auth.get('instructions','') if is_grey else service.read_json(root/'requirements.json',{}).get('instructions',''),
                'accounts':accounts,
                'project_available':old['kind']=='whitebox' and source.is_dir() and not source.is_symlink()}
