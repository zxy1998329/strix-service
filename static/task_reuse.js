'use strict';
const reuseDrafts={};
function clearReuseDrafts(){for(const key of Object.keys(reuseDrafts))delete reuseDrafts[key]}
async function repeatTask(id){
 try{
  const draft=await api('/v1/scans/'+encodeURIComponent(id)+'/reuse');
  mode=draft.kind;reuseDrafts[mode]={...draft,pending:true};delete scanForms[mode];
  if(dialog.open){dialog.close();clearInterval(detailPoll)}
  go('new');
 }catch(error){toast(error.message)}
}
function retainCredentialReference(input,reference){
 if(!reference)return;
 input.dataset.valueReference=reference;
 input.addEventListener('input',()=>{delete input.dataset.valueReference});
}
function hydrateReuseForm(form){
 const draft=reuseDrafts[mode];if(!draft||!draft.pending)return;
 draft.pending=false;form.dataset.sourceJob=draft.source_job_id;
 form.elements.name.value=draft.name;
 if(form.elements.target)form.elements.target.value=draft.target;
 form.elements.instructions.value=draft.instructions||'';
 const notice=document.createElement('div');notice.className='note';notice.style.marginBottom='20px';notice.dataset.reuseNotice='';
 notice.textContent='已载入「'+draft.name+'」的任务参数，可修改后提交。新任务使用提交时最新保存的模型配置。';
 form.prepend(notice);
 if(mode==='whitebox'){
  const input=form.elements.project;
  input.required=!draft.project_available;
  const hint=document.createElement('p');hint.className=draft.project_available?'note':'note warn';
  hint.textContent=draft.project_available?'已沿用原任务项目代码，无需重新上传；选择新 ZIP 可替换。':'原任务项目文件已不可用，请重新选择 ZIP。';
  input.parentElement.append(hint);
  input.onchange=()=>{input.required=!draft.project_available;hint.textContent=input.files.length?'将使用新选择的 ZIP 替换原项目。':(draft.project_available?'已沿用原任务项目代码，无需重新上传；选择新 ZIP 可替换。':'原任务项目文件已不可用，请重新选择 ZIP。')};
 }
 if(mode==='greybox'){
  const list=form.querySelector('#grey-accounts');list.innerHTML='';
  for(const [index,account] of (draft.accounts||[]).entries()){
   list.insertAdjacentHTML('beforeend',greyAccount(index));const box=list.lastElementChild;
   box.dataset.method=account.method||'headers';
   box.querySelector('[name=label]').value=account.label||'';
   box.querySelector('[name=role]').value=account.role||'';
   const entries=box.querySelector('[data-auth-entries]');
   if(account.method==='headers'){
    for(const entry of account.auth||[]){
     entries.insertAdjacentHTML('beforeend',greyAuthEntry(entry.type));const row=entries.lastElementChild;
     row.querySelector('[name=auth_name]').value=entry.name;
     const input=row.querySelector('[name=auth_value]');input.value=entry.value;
     retainCredentialReference(input,entry.value_reference);
    }
   }else{
    box.querySelectorAll('[data-add-auth]').forEach(b=>b.hidden=true);
    const hint=box.querySelector('p.muted');if(hint)hint.hidden=true;
    const labels={password:'账号密码',cookie:'Cookie',bearer:'Bearer Token'};
    entries.innerHTML='<p class="muted">沿用原任务登录方式：'+esc(labels[account.method]||account.method)+'</p>';
    const fields=account.method==='password'?[['username','用户名','text'],['password','密码','password']]:account.method==='cookie'?[['cookie','Cookie','password']]:[['token','Token','password']];
    for(const [key,label,type] of fields){
     entries.insertAdjacentHTML('beforeend',field(key,label,account[key]||'','',type));
     const input=entries.querySelector('[name='+key+']');input.required=true;
     retainCredentialReference(input,(account.secret_refs||{})[key]);
    }
   }
   for(const [key,label] of [['login_path','登录页路径'],['verify_path','验证接口路径'],['steps','登录步骤']]){
    if(account[key])entries.insertAdjacentHTML('beforeend',field(key,label,account[key]));
   }
  }
  if(!list.children.length)list.innerHTML=greyAccount(0);
 }
}
function greyAccountPayload(box){
 const result={label:box.querySelector('[name=label]').value,role:box.querySelector('[name=role]').value,method:box.dataset.method||'headers'};
 if(result.method==='headers')result.auth=[...box.querySelectorAll('[data-auth-entry]')].map(row=>{
  const input=row.querySelector('[name=auth_value]');
  return {type:row.dataset.authEntry,name:row.querySelector('[name=auth_name]').value,value:input.value,
          ...(input.dataset.valueReference?{value_reference:input.dataset.valueReference}:{})};
 });
 for(const key of ['username','password','cookie','token','login_path','verify_path','steps']){
  const input=box.querySelector('[name='+key+']');if(!input)continue;
  result[key]=input.value;
  if(input.dataset.valueReference){result.secret_refs||={};result.secret_refs[key]=input.dataset.valueReference}
 }
 return result;
}
