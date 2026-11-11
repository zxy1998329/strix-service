'use strict';
const root=document.querySelector('#app'),dialog=document.querySelector('#detail');
let me=null,view=location.pathname==='/api-guide'?'api-docs':'tasks',page=1,query='',mode='whitebox',poll=null,detailPoll=null;
const scanForms={};
const labels={queued:'等待执行',running:'检测中',completed:'检测完成',failed:'检测失败',timed_out:'已超时',cancel_requested:'正在停止',cancelled:'已取消'};
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const date=v=>v?new Date(v*1000).toLocaleString('zh-CN',{hour12:false}):'—';
const statusTag=s=>`<span class="tag ${esc(s)}">${esc(labels[s]||s)}</span>`;
function toast(message){const e=document.querySelector('#toast');e.textContent=message;e.classList.add('show');setTimeout(()=>e.classList.remove('show'),4500)}
async function api(path,options={}){const headers={...(options.body instanceof FormData?{}:{'Content-Type':'application/json'}),...(me?{'x-csrf-token':me.csrf}:{}),...options.headers};let response;try{response=await fetch(path,{...options,headers})}catch{throw Error('无法连接服务，请检查网络或联系管理员')}const value=await response.json().catch(()=>({}));if(!response.ok){let message=value.detail||'操作未成功';if(Array.isArray(message))message=message.map(x=>x.msg).join('；');throw Error(message)}return value}
function loginScreen(role=location.pathname==='/admin'?'admin':'user'){
 delete scanForms.whitebox;delete scanForms.blackbox;delete scanForms.greybox;clearReuseDrafts();
 if(typeof resetDocCredentials==='function')resetDocCredentials();
 clearInterval(poll);root.innerHTML=`<main class="login"><section class="login-art"><div class="brand"><b>S</b> STRIX</div><div><div class="eyebrow">APPLICATION SECURITY</div><h1>让每一次检测，<br>都有据可查。</h1><p>从项目源码到在线系统，以独立沙箱执行授权测试，集中管理漏洞证据与检测报告。</p><div class="feature"><span>◇</span> 白盒代码审计与黑盒系统检测</div><div class="feature"><span>◇</span> 任务进度与历史结果统一留存</div><div class="feature"><span>◇</span> AI 驱动，结果由人工复核</div></div><small>STRIX SECURITY WORKSPACE · 内部授权测试</small></section><section class="login-side"><div class="login-card"><div class="eyebrow">WELCOME BACK</div><h2>${role==='admin'?'管理后台':'欢迎使用安全检测平台'}</h2><p class="muted">${role==='admin'?'配置检测引擎，管理全平台任务。':'输入工号即可进入，无需单独注册。'}</p><div class="tabs"><button data-role="user" class="${role==='user'?'active':''}">员工登录</button><button data-role="admin" class="${role==='admin'?'active':''}">管理员登录</button></div><form id="login-form"><label class="field"><span>${role==='admin'?'管理员密码':'6 位工号'}</span><input id="credential" name="credential" type="${role==='admin'?'password':'text'}" ${role==='user'?'inputmode="numeric" maxlength="6" pattern="[0-9]{6}"':''} placeholder="${role==='admin'?'请输入管理员密码':'例如 012345'}" required autocomplete="${role==='admin'?'current-password':'username'}"><small>${role==='user'?'首次登录会自动建立个人账号，历史任务与工号关联。':'请使用部署管理员提供的密码。'}</small></label><div id="login-error" class="errtext" role="alert"></div><button class="primary full" type="submit">${role==='admin'?'进入管理后台':'进入工作台'} <span>→</span></button></form><p class="login-foot">仅限已授权的内部安全测试。工号登录用于区分工作记录，不校验真实员工身份；请在受控内网使用。</p></div></section></main>`;
 document.querySelectorAll('[data-role]').forEach(b=>b.onclick=()=>loginScreen(b.dataset.role));
 document.querySelector('#login-form').onsubmit=async e=>{e.preventDefault();const button=e.target.querySelector('button');button.disabled=true;try{const credential=document.querySelector('#credential').value;await api('/web/login',{method:'POST',body:JSON.stringify({role,employee:role==='user'?credential:'',password:role==='admin'?credential:''})});me=await api('/web/me');view=location.pathname==='/api-guide'?'api-docs':'tasks';shell()}catch(error){document.querySelector('#login-error').textContent=error.message}finally{button.disabled=false}};
}
function shell(){clearInterval(poll);root.innerHTML=`<div class="shell"><aside class="sidebar"><div class="brand"><b>S</b><span>STRIX</span></div><div class="navlabel">WORKSPACE</div><button class="navitem" data-view="tasks"><span>▦</span><b>${me.role==='admin'?'全平台任务':'我的检测任务'}</b></button><button class="navitem" data-view="new"><span>＋</span><b>新建检测</b></button><button class="navitem" data-view="api-docs" aria-label="接口文档"><span>⇄</span><b>接口文档</b></button>${me.role==='admin'?'<div class="navlabel">ADMINISTRATION</div><button class="navitem" data-view="config"><span>⚙</span><b>模型配置</b></button><button class="navitem" data-view="scope"><span>◎</span><b>扫描范围</b></button><button class="navitem" data-view="users"><span>♙</span><b>员工账号</b></button><button class="navitem" data-view="security"><span>◇</span><b>密码设置</b></button>':''}<div class="sidebar-foot">Strix 1.7.0 · 平台 v0.2.1<br>授权范围内测试 · 结果人工复核</div></aside><main class="main"><header class="topbar"><span class="crumb">安全检测平台 / <span id="crumb-current">工作台</span></span><div class="account"><span class="avatar">${me.role==='admin'?'管':esc(me.owner.slice(-2))}</span><span>${me.role==='admin'?'管理员':'工号 '+esc(me.owner)}</span><button class="linkbtn" id="logout">退出</button></div></header><div class="content" id="content"></div></main></div>`;document.querySelector('#logout').onclick=async()=>{try{await api('/web/logout',{method:'POST'})}catch{}me=null;loginScreen()};document.querySelectorAll('[data-view]').forEach(b=>b.onclick=()=>go(b.dataset.view));go(view)}
function go(next){clearInterval(poll);view=next;document.querySelectorAll('[data-view]').forEach(b=>b.classList.toggle('active',b.dataset.view===view));document.querySelector('#crumb-current').textContent=({tasks:'检测任务',new:'新建检测',config:'模型配置',scope:'扫描范围',users:'员工账号',security:'密码设置','api-docs':'接口文档'})[view];({tasks:tasksPage,new:newPage,config:configPage,scope:scanScopePage,users:usersPage,security:securityPage,'api-docs':apiDocsPage})[view]()}
function head(title,subtitle,extra=''){return `<div class="pagehead"><div><div class="eyebrow">SECURITY WORKSPACE</div><h1>${title}</h1><p>${subtitle}</p></div>${extra}</div>`}
function tasksPage(){document.querySelector('#content').innerHTML=head(me.role==='admin'?'全平台检测任务':'我的检测任务',me.role==='admin'?'查看所有工号提交的检测任务与结果。':'提交项目、跟踪进度，查看每一次检测的证据与结果。','<button class="primary" id="new-task">＋ 新建检测</button>')+`<div class="stats" id="stats"></div><div class="card"><div class="cardhead"><h2>任务记录</h2><div class="actions"><span class="poll-indicator"><i class="dot"></i>自动更新</span><input class="search" id="search" aria-label="搜索任务" placeholder="搜索名称、任务 ID${me.role==='admin'?'或工号':''}" value="${esc(query)}"></div></div><div id="task-table"><div class="empty">正在读取任务…</div></div></div><p class="footnote">检测完成表示引擎已结束执行，不代表系统不存在漏洞。请结合证据、覆盖范围和报告提示复核。</p>`;document.querySelector('#new-task').onclick=()=>go('new');let debounce;document.querySelector('#search').oninput=e=>{clearTimeout(debounce);query=e.target.value;page=1;debounce=setTimeout(loadTasks,300)};loadTasks();poll=setInterval(loadTasks,5000)}
async function loadTasks(){try{const value=await api('/web/tasks?page='+page+'&q='+encodeURIComponent(query));if(view!=='tasks')return;const c=value.counts,total=Object.values(c).reduce((a,b)=>a+b,0);document.querySelector('#stats').innerHTML=[['全部任务',total,'已保留的检测记录','▦'],['检测中',(c.running||0)+(c.cancel_requested||0),'正在执行或停止','◷'],['已完成',c.completed||0,'报告仍需人工复核','✓'],['等待执行',c.queued||0,'按提交顺序处理','⋯']].map(([label,n,hint,icon])=>`<div class="stat"><i>${icon}</i><span>${label}</span><strong>${n}</strong><small>${hint}</small></div>`).join('');const table=document.querySelector('#task-table');if(!value.items.length){table.innerHTML='<div class="empty"><span class="symbol">◇</span><h3>还没有检测任务</h3><p>点击「新建检测」，上传项目或提交授权系统地址。</p></div>';return}table.innerHTML=`<div class="tablewrap"><table><thead><tr><th>任务名称</th>${me.role==='admin'?'<th>提交工号</th>':''}<th>类型</th><th>状态</th><th>提交时间</th><th>操作</th></tr></thead><tbody>${value.items.map(task=>`<tr><td><strong>${esc(task.name)}</strong></td>${me.role==='admin'?`<td>${task.owner==='__admin__'?'管理员':esc(task.owner)}</td>`:''}<td><span class="tag kind">${kindLabel(task.kind)}</span></td><td>${statusTag(task.status)}</td><td>${date(task.created)}</td><td><button class="linkbtn" data-job="${task.id}">${task.report_ready?'查看报告':'查看进度'} →</button><button class="linkbtn" data-submission="${task.id}">查看提交信息</button><button class="linkbtn" data-repeat="${task.id}">再次检测</button></td></tr>`).join('')}</tbody></table></div><div class="pagination"><span>共 ${value.total} 条 · 第 ${value.page} 页</span><div class="actions"><button class="secondary" id="prev" ${page<=1?'disabled':''}>上一页</button><button class="secondary" id="next" ${page*30>=value.total?'disabled':''}>下一页</button></div></div>`;table.querySelectorAll('[data-job]').forEach(b=>b.onclick=()=>openJob(b.dataset.job));table.querySelectorAll('[data-submission]').forEach(b=>b.onclick=()=>openSubmission(b.dataset.submission));table.querySelectorAll('[data-repeat]').forEach(b=>b.onclick=()=>repeatTask(b.dataset.repeat));document.querySelector('#prev').onclick=()=>{page--;loadTasks()};document.querySelector('#next').onclick=()=>{page++;loadTasks()}}catch(error){toast(error.message)}}
async function newPage(){try{me=await api('/web/me')}catch(error){toast(error.message);return}if(mode==='greybox'){greyPage();return}document.querySelector('#content').innerHTML=head('新建安全检测','选择检测方式，填写任务信息后提交，平台将自动执行授权范围内的安全检测。')+scanTabs()+`<div><div>${!me.scan_enabled?'<div class="note warn" style="margin-bottom:20px">管理员尚未启用检测。可以查看历史任务，请联系管理员在 AI 配置中完成设置并开启扫描。</div>':''}<div class="card"><div class="cardhead"><h2>${mode==='whitebox'?'项目文件':'系统信息'}</h2><span class="badge">${mode==='whitebox'?'WHITE BOX':'BLACK BOX'}</span></div><form class="cardbody" id="scan-form"><label class="field"><span>任务名称</span><input name="name" maxlength="100" required><small>例如 客户平台 · 安全检测</small></label>${mode==='whitebox'?`<div class="dropzone"><h3>选择项目压缩包</h3><p class="muted">ZIP 格式，最大 ${me.limits.upload_mib} MiB</p><input type="file" name="project" accept=".zip" required><small>请移除生产密钥、个人数据与无关文件。</small></div>`:`<label class="field"><span>系统访问地址</span><input name="target" type="url" required><small>填写已授权 HTTP(S) 根地址。</small></label>`}${area('instructions','测试要求','','填写重点检测功能、排除范围和业务说明，最多 4000 字；留空按默认方式检测。')}<div id="scan-error" class="errtext"></div><button class="primary" type="submit" ${me.scan_enabled?'':'disabled'}>提交并开始检测 →</button></form></div></div></div>`;if(scanForms[mode])document.querySelector('#scan-form').replaceWith(scanForms[mode]);else scanForms[mode]=document.querySelector('#scan-form');hydrateReuseForm(document.querySelector('#scan-form'));document.querySelectorAll('[data-mode]').forEach(b=>b.onclick=()=>{if(mode===b.dataset.mode)return;mode=b.dataset.mode;newPage()});document.querySelector('#scan-form').onsubmit=async e=>{e.preventDefault();const button=e.target.querySelector('button[type=submit]');button.disabled=true;const data=new FormData(e.target);try{let value;if(mode==='whitebox'){const file=data.get('project');const source=e.target.dataset.sourceJob;if(source)data.set('source_job_id',source);if(!file||!file.size){if(source)data.delete('project');else throw Error('请选择项目 ZIP')}if(file&&file.size>me.limits.upload_mib*1024*1024)throw Error('文件超过大小限制');data.set('authorized','true');value=await api('/v1/scans/whitebox',{method:'POST',body:data})}else value=await api('/v1/scans/blackbox',{method:'POST',body:JSON.stringify({name:data.get('name'),target:data.get('target'),instructions:data.get('instructions'),authorized:true})});delete scanForms[mode];toast('任务已提交，可随时查看进度');go('tasks');openJob(value.id)}catch(error){document.querySelector('#scan-error').textContent=error.message;button.disabled=false}}}
async function openSubmission(id){
 clearInterval(detailPoll);if(!dialog.open)dialog.showModal();
 document.querySelector('#detail-content').innerHTML='<div class="modalbody">正在读取提交信息…</div>';
 try{
  const [input,task]=await Promise.all([api('/v1/scans/'+id+'/submission'),api('/v1/scans/'+id)]);
  if(!dialog.open)return;
  const row=(label,value)=>`<div style="margin:0 0 18px"><strong>${esc(label)}</strong><pre style="white-space:pre-wrap;overflow-wrap:anywhere;margin:6px 0;font:inherit;line-height:1.7">${esc(value==null||value===''?'未填写':value)}</pre></div>`;
  const methods={headers:'自定义 Cookie / Header',password:'账号密码',cookie:'Cookie',bearer:'Bearer Token'};
  const accounts=(input.accounts||[]).map((account,index)=>`<section class="note" style="margin:14px 0"><h3>${esc(account.label||'账号 '+(index+1))}</h3>${row('角色 / 权限说明',account.role)}${row('登录方式',methods[account.method]||account.method)}${['username','password','cookie','token'].filter(k=>account[k]).map(k=>row({username:'用户名',password:'密码',cookie:'Cookie',token:'Token'}[k],account[k])).join('')}${(account.auth||[]).map(entry=>row((entry.type==='cookie'?'Cookie':'Header')+' · '+entry.name,entry.value)).join('')}${['login_path','verify_path','steps'].filter(k=>account[k]).map(k=>row({login_path:'登录页路径',verify_path:'验证接口路径',steps:'登录步骤'}[k],account[k])).join('')}</section>`).join('');
  document.querySelector('#detail-content').innerHTML=`<div class="modalhead"><div><h2>查看提交信息</h2></div><button class="close" aria-label="关闭">×</button></div><div class="modalbody"><p class="muted">以下为创建此任务时保存的填写内容。凭据仅显示脱敏值。</p>${row('任务名称',input.name)}${row('检测方式',kindLabel(task.kind))}${row('提交时间',date(task.created))}${input.kind==='whitebox'?row('项目压缩包',input.project_available?'历史记录未保存原始 ZIP 文件名；项目代码仍可用。':'历史记录未保存原始 ZIP 文件名；项目代码已不可用。'):row('系统访问地址',input.target)}${row('测试要求',input.instructions)}${accounts?'<h3>测试账号</h3>'+accounts:''}</div>`;
  dialog.querySelector('.close').onclick=()=>dialog.close();
 }catch(error){document.querySelector('#detail-content').innerHTML=`<div class="modalhead"><h2>查看提交信息</h2><button class="close" aria-label="关闭">×</button></div><div class="modalbody"><div class="note warn">${esc(error.message)}</div></div>`;dialog.querySelector('.close').onclick=()=>dialog.close()}
}
async function openJob(id){taskLogState={id,open:false,paused:false,text:'',scroll:0};modelCallState={id,open:false,page:1,selected:null,cache:{}};clearInterval(detailPoll);dialog.showModal();document.querySelector('#detail-content').innerHTML='<div class="modalbody">正在读取任务…</div>';await refreshJob(id);detailPoll=setInterval(()=>{if(dialog.open)refreshJob(id);else clearInterval(detailPoll)},5000)}
async function refreshJob(id){try{const task=await api('/v1/scans/'+id);if(!dialog.open)return;const report=task.report_ready?await api('/web/report/'+id):null;const active=['queued','running','cancel_requested'].includes(task.status);captureTaskLog();const opened=new Set([...dialog.querySelectorAll('details[data-finding][open]')].map(e=>e.dataset.finding));document.querySelector('#detail-content').innerHTML=`<div class="modalhead"><div><h2>${esc(task.name)}</h2><small>${esc(task.id)}</small></div><button class="close" aria-label="关闭">×</button></div><div class="modalbody"><div class="actions" style="margin-bottom:20px">${statusTag(task.status)}<span class="tag kind">${kindLabel(task.kind)}</span><span class="muted">${date(task.created)}</span></div>${active?'<div class="progress-track"><div></div></div><p class="muted">任务正在后台处理，关闭此窗口不会停止检测。</p>':''}${task.detail.verification?verificationResult(task.detail.verification):executionPanel(task)}${modelMetricsPanel(task.model_metrics)}${task.instructions?`<details class="note" style="margin:16px 0"><summary>本次测试要求</summary><pre style="white-space:pre-wrap;overflow-wrap:anywhere">${esc(task.instructions)}</pre></details>`:''}${task.detail.reason?`<div class="note warn" style="margin-top:18px">${esc(task.detail.reason)}</div>`:''}<div class="actions" style="margin:20px 0">${task.report_ready?`<a class="primary" href="/v1/scans/${id}/report">下载 Markdown 报告</a><a class="secondary" href="/v1/scans/${id}/report?format=json">下载 JSON</a>`:''}${active?'<button class="danger" id="cancel-job">停止任务</button>':''}</div>${me.role==='admin'?modelCallPanel()+taskLogPanel():''}${task.kind==='greybox_verify'?'':findingList(task.findings||[],active)}${report?'<div class="note warn">'+(report.warnings||[]).map(esc).join('<br>')+'</div><h3 style="margin-top:25px">报告正文</h3><div class="report" id="report-body"></div>':(task.kind==='greybox_verify'?'<div class="note">此任务仅验证接口调用，不生成漏洞报告。</div>':'<div class="note">报告将在扫描结束后生成。</div>')}</div>`;dialog.querySelectorAll('details[data-finding]').forEach(e=>{e.open=opened.has(e.dataset.finding)});dialog.querySelector('.close').onclick=()=>{dialog.close();clearInterval(detailPoll)};if(report)renderReport(document.querySelector('#report-body'),report.raw_report||'本次没有生成原始报告，请查看上方运行说明。');const button=document.querySelector('#cancel-job');if(button)button.onclick=async()=>{if(!confirm('确认停止此任务？已经产生的模型费用不会退回。'))return;await api('/v1/scans/'+id+'/cancel',{method:'POST'});toast('已请求停止');refreshJob(id)};await updateTaskLog(id);await updateModelCalls(id);if(!active)clearInterval(detailPoll)}catch(error){toast(error.message)}}
function scanTabs(){return `<div class="scan-tabs" role="tablist" aria-label="扫描方式">${[['whitebox','白盒代码扫描'],['blackbox','黑盒系统扫描'],['greybox','灰盒登录扫描']].map(([id,label])=>`<button type="button" role="tab" aria-selected="${mode===id}" class="scan-tab ${mode===id?'active':''}" data-mode="${id}">${label}</button>`).join('')}</div>`}
function kindLabel(kind){return {whitebox:'白盒扫描',blackbox:'黑盒扫描',greybox:'灰盒扫描',greybox_verify:'灰盒接口验证'}[kind]||kind}
function verificationResult(items){return '<h3>接口验证结果</h3>'+items.map(r=>`<div class="note ${r.state==='success'?'':'warn'}" style="margin:10px 0"><strong>${esc(r.label)} · ${esc({success:'调用成功',failed:'调用失败',unknown:'无法确认'}[r.state]||r.state)}</strong><p>${esc(r.message)}${r.http_status?' · HTTP '+esc(r.http_status):''}</p></div>`).join('')}
function greyAuthEntry(type){return `<div data-auth-entry="${type}" class="note" style="margin:10px 0"><strong>${type==='cookie'?'Cookie':'Header'}</strong><div class="two">${field('auth_name','名称')}${field('auth_value','值','','','password')}</div><button type="button" class="linkbtn" data-remove-auth>移除此条</button></div>`}
function greyAccount(index){return `<fieldset data-account style="border:1px solid #d6e2e9;border-radius:12px;padding:18px;margin:16px 0"><legend>测试账号 ${index+1}</legend>${field('label','账号名称','账号 '+(index+1),'例如 普通用户 A')}<div data-auth-entries></div><div class="actions"><button type="button" class="secondary" data-add-auth="cookie">＋ 添加 Cookie</button><button type="button" class="secondary" data-add-auth="header">＋ 添加 Header</button></div><p class="muted">按需添加名称和值；Cookie 合并为 Cookie 请求头，Header 按原样加入请求。Authorization 请填写完整值，例如 Bearer xxx。未添加时不附加鉴权信息。</p>${field('role','角色 / 权限说明','','例如 只能读取本人订单')}<button type="button" class="linkbtn" data-remove-account>移除此账号</button></fieldset>`}
function greyPage(){
 document.querySelector('#content').innerHTML=head('新建安全检测','选择检测方式，填写任务信息后提交，平台将自动执行授权范围内的安全检测。')+scanTabs()+`<div class="card"><form id="scan-form" class="cardbody">${field('name','任务名称','','例如 客户平台 · 安全检测')}${field('target','系统访问地址','','填写已授权 HTTP(S) 根地址。','url')}<p class="muted">当前登记目标：${esc(me.authorized_targets||'尚未设置')}。验证接口必须属于该系统。</p><div id="grey-accounts">${greyAccount(0)}</div><button type="button" class="secondary" id="add-account">＋ 添加测试账号（最多 5 个）</button>${area('instructions','测试要求','','填写重点功能、禁止操作和业务背景，不要放生产凭据。')}<div class="note warn">凭据将提供给扫描代理及配置的模型服务，仅提交授权测试凭据。接口验证不调用模型，HTTP 200 表示调用成功，不证明已建立登录会话。</div><div class="actions" style="margin-top:20px"><button type="button" class="secondary" id="verify-auth">验证接口</button><button type="submit" class="primary">开始灰盒扫描</button></div><div id="grey-result" role="status" style="margin-top:16px"></div></form></div>`;
 if(scanForms.greybox)document.querySelector('#scan-form').replaceWith(scanForms.greybox);else scanForms.greybox=document.querySelector('#scan-form');
 const form=document.querySelector('#scan-form');hydrateReuseForm(form);form.elements.name.required=true;form.elements.target.required=true;
 const bind=()=>{form.querySelectorAll('[data-account]').forEach(box=>{box.querySelector('[name=label]').required=true;box.querySelectorAll('[data-add-auth]').forEach(button=>button.onclick=()=>{const list=box.querySelector('[data-auth-entries]');if(list.children.length>=30)return toast('最多30条 Cookie / Header');list.insertAdjacentHTML('beforeend',greyAuthEntry(button.dataset.addAuth));bind()});box.querySelectorAll('[data-auth-entry]').forEach(row=>{row.querySelectorAll('input').forEach(input=>input.required=true);row.querySelector('[data-remove-auth]').onclick=()=>row.remove()});box.querySelector('[data-remove-account]').onclick=()=>{if(form.querySelectorAll('[data-account]').length>1)box.remove();else toast('至少保留一个测试账号')}})};bind();
 form.querySelector('#add-account').onclick=()=>{const count=form.querySelectorAll('[data-account]').length;if(count>=5)return toast('最多 5 个账号');form.querySelector('#grey-accounts').insertAdjacentHTML('beforeend',greyAccount(count));bind()};
 document.querySelectorAll('[data-mode]').forEach(b=>b.onclick=()=>{if(mode===b.dataset.mode)return;mode=b.dataset.mode;newPage()});
 const payload=()=>({name:form.elements.name.value.trim(),target:form.elements.target.value.trim(),instructions:form.elements.instructions.value,authorized:true,source_job_id:form.dataset.sourceJob||'',accounts:[...form.querySelectorAll('[data-account]')].map(greyAccountPayload) });
 const submit=async verify=>{if(!form.reportValidity())return;if(!verify&&!confirm('将当前测试凭据提供给配置的模型服务并开始灰盒扫描，可能产生模型费用。继续？'))return;const buttons=form.querySelectorAll('#verify-auth,[type=submit]');buttons.forEach(b=>b.disabled=true);try{const job=await api('/v1/scans/greybox'+(verify?'/verify':''),{method:'POST',body:JSON.stringify(payload())});if(!verify){delete scanForms.greybox;go('tasks');openJob(job.id);return}const result=form.querySelector('#grey-result');result.textContent='验证已进入扫描队列；当前任务执行完后处理。你可以在任务列表查看。';const timer=setInterval(async()=>{try{const task=await api('/v1/scans/'+job.id);if(!['queued','running','cancel_requested'].includes(task.status)){clearInterval(timer);result.innerHTML=task.detail.verification?verificationResult(task.detail.verification):`<div class="note warn">${esc(task.detail.reason||'验证未完成')}</div>`}}catch(error){clearInterval(timer);result.textContent=error.message}},3000)}catch(error){form.querySelector('#grey-result').textContent=error.message}finally{buttons.forEach(b=>b.disabled=false)}};
 form.onsubmit=e=>{e.preventDefault();submit(false)};form.querySelector('#verify-auth').onclick=()=>submit(true);
}
function executionPanel(task){
 const x=task.execution||{}, minutes=Math.floor((x.elapsed_seconds||0)/60), seconds=(x.elapsed_seconds||0)%60;
 const toolNames={exec_command:'执行检查命令',terminal_execute:'执行终端检查',browser_action:'操作浏览器验证',python_action:'运行分析脚本',create_vulnerability_report:'记录漏洞',finish_scan:'生成最终报告',record_coverage:'记录检查范围',think:'规划下一步检查'};
 const outcomes={reported:'已记录漏洞',no_issue_found:'本次未发现问题',ruled_out:'已排除',not_applicable:'不适用',needs_follow_up:'待进一步验证'};
 const text=v=>typeof v==='object'?JSON.stringify(v,null,2):String(v??'');
 const checklistPercent=Math.max(0,Math.min(100,Number(x.checklist_percent??((x.coverage||[]).length?Math.round(100*(x.coverage||[]).filter(e=>['reported','no_issue_found','ruled_out','not_applicable'].includes(e.outcome)).length/(x.coverage_count||(x.coverage||[]).length)):0))||0));
 return `<section style="margin:20px 0"><div style="display:flex;align-items:center;gap:12px;margin-bottom:18px"><div role="progressbar" aria-label="清单完成率" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${checklistPercent}" style="height:10px;flex:1;background:#e4edf0;border-radius:10px;overflow:hidden"><div style="height:100%;width:${checklistPercent}%;background:#08988e;border-radius:10px;transition:width .3s"></div></div><strong>${checklistPercent}%</strong></div><div class="note"><strong>${esc(x.headline||'等待执行记录')}</strong><p>自提交已过 ${minutes} 分 ${seconds} 秒 · 最近活动：${x.last_activity_at?date(x.last_activity_at):'尚无执行记录'}</p>${x.activity_warning?'<p class="errtext">超过 2 分钟没有新的执行记录，可能仍在等待模型或工具；暂不能据此判断卡死。</p>':''}</div><div class="three" style="margin-top:12px"><div class="note">工具执行记录<br><strong>${x.tool_calls_count||0} 次</strong></div><div class="note">已登记检查项<br><strong>${x.coverage_count||0} 项</strong></div><div class="note">已记录漏洞<br><strong>${task.findings_count||0} 项</strong></div></div><h3 style="margin-top:24px">最近执行动态</h3><p class="muted">${esc(x.source||'等待引擎写入记录')} 每 5 秒刷新。</p>${(x.events||[]).length?`<div style="max-height:280px;overflow:auto">${x.events.map(e=>`<div class="note" style="margin:8px 0"><strong>${esc(e.kind==='tool'?(toolNames[e.name]||e.name):'模型请求返回')}</strong> <small>${esc(e.time||'')} · ${e.duration_ms!=null?(Number(e.duration_ms)/1000).toFixed(1)+' 秒':''}</small>${e.state?`<div>${esc(e.state)}</div>`:''}${e.command?`<pre style="white-space:pre-wrap;overflow-wrap:anywhere">${esc(e.command)}</pre>`:''}${e.kind==='model'?`<div>结果：${esc(e.outcome||'未标注')}${e.status?' · HTTP '+esc(e.status):''}${e.retry_attempt?' · 重试 '+esc(e.retry_attempt):''}</div>`:''}</div>`).join('')}</div>`:'<div class="note">尚无工具或模型返回记录。任务可能处于初始化或首轮模型等待中。</div>'}${x.truncated_events?'<p class="muted">这里只显示最近 40 条执行动态。</p>':''}<h3 style="margin-top:24px">已登记的检查范围</h3><p class="muted">由扫描代理主动登记，未登记的检查不会凭空显示；不代表全部覆盖。</p>${(x.coverage||[]).length?x.coverage.map(c=>`<details class="note" style="margin:8px 0"><summary>${esc(text(c.surface))} · ${esc(text(c.risk_area))} · ${esc(outcomes[c.outcome]||c.outcome||'未标注')}</summary><pre style="white-space:pre-wrap;overflow-wrap:anywhere">${esc(text(c.evidence||'未提供证据'))}</pre></details>`).join(''):'<div class="note">引擎尚未登记检查范围。</div>'}${(x.coverage_gaps||[]).length?'<h4>覆盖缺口 / 待验证项</h4><pre style="white-space:pre-wrap;overflow-wrap:anywhere">'+esc(text(x.coverage_gaps))+'</pre>':''}</section>`;
}
function findingList(items,active){
 const names={critical:'严重',high:'高危',medium:'中危',low:'低危',info:'提示',informational:'提示'};
 const fields={description:'漏洞描述',target:'目标',endpoint:'接口 / 路径',method:'请求方法',impact:'影响范围',technical_analysis:'技术分析',evidence:'验证证据',poc_description:'复现步骤',poc_script_code:'复现代码',code_locations:'代码位置',remediation_steps:'修复建议',cvss:'CVSS 评分',cwe:'CWE',cve:'CVE',timestamp:'发现时间'};
 return `<section style="margin:24px 0"><h3>已发现漏洞 · ${items.length}</h3><p class="muted">${active?'每 5 秒更新引擎已记录的漏洞，无需等任务结束。':'以下为引擎记录的漏洞。'}结果需人工复核，数量为 0 不代表系统安全。</p>${items.length?items.map((v,i)=>`<details data-finding="${esc(v.id||i)}" class="note" style="margin-top:12px"><summary style="cursor:pointer"><span class="tag">${esc(names[String(v.severity).toLowerCase()]||v.severity||'未评级')}</span> <strong>${esc(v.title||'未命名漏洞')}</strong> <small>点击查看详情</small></summary><div style="margin-top:16px">${Object.entries(fields).filter(([key])=>v[key]!=null&&v[key]!=='').map(([key,label])=>`<h4>${label}</h4><pre style="white-space:pre-wrap;overflow-wrap:anywhere;max-height:400px;overflow:auto;user-select:text">${esc(typeof v[key]==='object'?JSON.stringify(v[key],null,2):v[key])}</pre>`).join('')||'<p>引擎尚未提供详情。</p>'}</div></details>`).join(''):'<div class="note">暂未记录结构化漏洞。发现并记录后会显示在这里。</div>'}</section>`;
}
function renderReport(element,text){for(const line of text.split('\n')){const match=line.match(/^(#{1,3})\s+(.*)/);const node=document.createElement(match?'h'+match[1].length:'p');node.textContent=match?match[2]:line;element.append(node)}}
const field=(name,label,value='',hint='',type='text')=>`<label class="field"><span>${label}</span><input name="${name}" type="${type}" value="${esc(value)}" ${['model','current_password','new_password','confirm_password'].includes(name)?'required':' '} ${type==='number'?'step="any"':''}>${hint&&hint!=='password'?'<small>'+esc(hint)+'</small>':''}</label>`;
const area=(name,label,value='',hint='')=>`<label class="field"><span>${label}</span><textarea name="${name}">${esc(value)}</textarea>${hint?'<small>'+esc(hint)+'</small>':''}</label>`;
async function configPage(saveNotice=''){
 document.querySelector('#content').innerHTML=head('模型配置','填写模型连接信息，保存后即可使用。')+'<div class="card"><div class="cardbody">正在读取配置…</div></div>';
 try{
  const c=await api('/web/admin/config');if(view!=='config')return;
  document.querySelector('#content').innerHTML=head('模型配置','填写模型连接信息，保存后即可使用。')+`<div class="card" style="max-width:760px"><form class="cardbody" id="config-form">
   <label class="field"><span>接口格式</span><select name="api_type"><option value="openai">OpenAI</option><option value="anthropic">Anthropic</option></select></label>
   ${field('api_base','接口地址',c.api_base,'例如 https://api.siliconflow.cn/v1')}
   ${field('model','模型名称',c.model.replace(/^(openai|anthropic)\//,''),'填写服务商提供的模型名称，无需添加协议前缀。')}
   ${field('api_key','API Key',c.api_key_masked||'','','text')}
   <p class="muted" style="font-size:12px">${c.api_key_present?'当前显示已保存 Key 的首尾，中间已脱敏。修改即替换，清空即使用空值；保存时清空会删除旧 Key。':'当前 Key 为空。输入后用于本次测试，点击保存才会保存。'}</p>
   ${area('test_question','测试问题','你好，请简短介绍你能如何协助进行代码与系统安全分析。','回答测试问题，并验证工具调用及结果回传。最多 4000 字。')}
   <div class="actions"><button type="submit" class="primary">${c.network_ready?'保存并启用':'保存配置'}</button><button type="button" class="secondary" id="test-model">测试连接</button></div>
   ${saveNotice?`<div class="note" role="status" style="margin-top:18px">${esc(saveNotice)}</div>`:''}
   <div id="probe-result" style="margin-top:18px"></div>
  </form></div>`;
  const form=document.querySelector('#config-form');form.api_type.value=(c.api_type==='anthropic'||(['auto','native'].includes(c.api_type)&&c.model.startsWith('anthropic/')))?'anthropic':'openai';
  form.test_question.required=true;form.test_question.maxLength=4000;form.test_question.oninput=()=>form.test_question.setCustomValidity('');
  let keyEdited=false,keyRaw='';
  form.api_key.onfocus=()=>{if(form.api_key.value.includes('••••••••'))form.api_key.select()};
  form.api_key.oninput=()=>{keyEdited=true;keyRaw=form.api_key.value.replace(/••••••••/g,'').trim()};
  form.api_key.onblur=()=>{if(keyEdited)form.api_key.value=keyRaw.length>10?keyRaw.slice(0,4)+'••••••••'+keyRaw.slice(-4):(keyRaw?'••••••••':'')};
  const keyFields=()=>!keyEdited&&c.api_key_present?{api_key:'',api_key_reference:c.revision}:{api_key:keyRaw};
  form.onsubmit=async e=>{
   e.preventDefault();const button=form.querySelector('[type=submit]');button.disabled=true;
   try{
    const data={api_type:form.api_type.value,api_base:form.api_base.value.trim(),model:form.model.value.trim(),...keyFields()};
    if(c.network_ready)data.enabled=true;
    await api('/web/admin/config',{method:'PUT',body:JSON.stringify(data)});
    toast(c.network_ready?'模型配置已保存，扫描服务已启用':'模型配置已保存');await configPage('新配置仅对新提交的任务生效，进行中和排队任务继续使用提交时的原配置。');
   }catch(error){toast(error.message)}finally{button.disabled=false}
  };
  document.querySelector('#test-model').onclick=async e=>{
   if(!form.test_question.value.trim()){form.test_question.setCustomValidity('请填写测试问题');form.test_question.reportValidity();return}form.test_question.setCustomValidity('');
   const button=e.currentTarget;button.disabled=true;
   document.querySelector('#probe-result').innerHTML='<div class="note">正在测试连接，请稍候…</div>';
   try{const value=await api('/web/admin/test-model',{method:'POST',body:JSON.stringify({api_type:form.api_type.value,api_base:form.api_base.value.trim(),model:form.model.value.trim(),...keyFields(),question:form.test_question.value.trim()})});document.querySelector('#probe-result').innerHTML=`<div class="note ${value.ok?'':'warn'}" role="status">${esc(value.message)}${value.question_ok!==undefined?`<div style="margin-top:10px">问答：${value.question_ok?'通过':'未通过'}<br>工具调用：${value.tool_calls?'通过':'未通过'}<br>工具结果回传：${value.tool_roundtrip?'通过':'未通过'}</div>`:''}${value.tool_message?`<p>${esc(value.tool_message)}</p>`:''}${value.answer?`<pre style="white-space:pre-wrap;overflow-wrap:anywhere;max-height:360px;overflow:auto;margin-top:12px;user-select:text">${esc(value.answer)}</pre>`:''}${value.detail?`<pre style="white-space:pre-wrap;overflow-wrap:anywhere;max-height:360px;overflow:auto;margin-top:12px;user-select:text">${esc(value.detail)}</pre>`:''}</div>`}catch(error){document.querySelector('#probe-result').innerHTML=`<div class="note warn" role="alert">${esc(error.message)}</div>`}finally{button.disabled=false}
  };
 }catch(error){toast(error.message)}
}
async function usersPage(){document.querySelector('#content').innerHTML=head('员工账号','6 位工号首次登录自动建档，管理员可查看任务或停用账号。')+'<div class="card" id="users-table"><div class="empty">正在读取账号…</div></div>';try{const data=await api('/web/admin/users');const box=document.querySelector('#users-table');if(!data.items.length){box.innerHTML='<div class="empty"><span class="symbol">♙</span><h3>还没有员工登录</h3><p>员工首次使用工号登录后，将自动出现在这里。</p></div>';return}box.innerHTML=`<div class="tablewrap"><table><thead><tr><th>工号</th><th>首次登录</th><th>最近登录</th><th>任务数</th><th>状态</th><th>操作</th></tr></thead><tbody>${data.items.map(u=>`<tr><td><strong>${esc(u.employee)}</strong></td><td>${date(u.created)}</td><td>${date(u.last_seen)}</td><td>${u.task_count}</td><td><span class="tag ${u.disabled?'cancelled':'completed'}">${u.disabled?'已停用':'正常'}</span></td><td><button class="linkbtn" data-owner="${u.employee}">查看任务</button><button class="linkbtn" data-toggle="${u.employee}">${u.disabled?'启用':'停用'}</button></td></tr>`).join('')}</tbody></table></div>`;box.querySelectorAll('[data-owner]').forEach(b=>b.onclick=()=>{query=b.dataset.owner;page=1;go('tasks')});box.querySelectorAll('[data-toggle]').forEach(b=>b.onclick=async()=>{if(!confirm('确认切换工号 '+b.dataset.toggle+' 的启用状态？现有登录会话将失效。'))return;await api('/web/admin/users/'+b.dataset.toggle+'/toggle',{method:'POST'});usersPage()})}catch(error){toast(error.message)}}
function securityPage(){document.querySelector('#content').innerHTML=head('管理员密码','修改后所有管理员会话失效，需要使用新密码重新登录。')+`<div class="card" style="max-width:650px"><form id="password-form" class="cardbody">${field('current_password','当前密码','','','password')}${field('new_password','新密码','','6—128 个字符','password')}${field('confirm_password','再次输入新密码','','','password')}<button class="primary" type="submit">更新密码</button></form></div><div class="note warn" style="max-width:650px">员工仅凭工号登录，不验证真实身份。上线行内环境时，应通过受控内网或统一认证入口限制访问。</div>`;document.querySelector('#password-form').onsubmit=async e=>{e.preventDefault();const form=e.target;if(form.new_password.value!==form.confirm_password.value){toast('两次输入的新密码不一致');return}try{await api('/web/admin/password',{method:'POST',body:JSON.stringify({current_password:form.current_password.value,new_password:form.new_password.value})});me=null;toast('密码已更新，请重新登录');loginScreen('admin')}catch(error){toast(error.message)}}}
dialog.addEventListener('close',()=>clearInterval(detailPoll));
(async()=>{try{me=await api('/web/me');if(location.pathname==='/admin'&&me.role!=='admin')loginScreen('admin');else shell()}catch{loginScreen()}})();





























let taskLogState={};
function captureTaskLog(){
 const calls=document.querySelector('#model-calls-panel');if(calls)modelCallState.open=calls.open;
 const panel=document.querySelector('#task-log-panel');
 if(panel){taskLogState.open=panel.open;taskLogState.scroll=panel.querySelector('pre').scrollTop}
}
function taskLogPanel(){
 return `<details id="task-log-panel" class="note" style="margin:20px 0" ${taskLogState.open?'open':''}><summary>运行日志（管理员）</summary><div class="actions" style="margin:12px 0"><button type="button" id="log-pause" class="secondary">${taskLogState.paused?'恢复刷新':'暂停刷新'}</button><button type="button" id="log-refresh" class="secondary">刷新</button><button type="button" id="log-copy" class="secondary">复制日志</button></div><small id="log-hint">显示最近约 16 KB，展开后每 5 秒刷新，凭据已过滤。</small><pre style="max-height:360px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;user-select:text"></pre></details>`;
}
async function updateTaskLog(id,force=false){
 const panel=document.querySelector('#task-log-panel');if(!panel)return;
 const pre=panel.querySelector('pre');pre.textContent=taskLogState.text||'展开后加载运行日志。';pre.scrollTop=taskLogState.scroll||0;
 panel.ontoggle=()=>{taskLogState.open=panel.open;if(panel.open)updateTaskLog(id,true)};
 panel.querySelector('#log-pause').onclick=()=>{taskLogState.paused=!taskLogState.paused;panel.querySelector('#log-pause').textContent=taskLogState.paused?'恢复刷新':'暂停刷新';if(!taskLogState.paused)updateTaskLog(id,true)};
 panel.querySelector('#log-refresh').onclick=()=>updateTaskLog(id,true);
 panel.querySelector('#log-copy').onclick=async()=>{try{await navigator.clipboard.writeText(taskLogState.text||'');toast('日志已复制')}catch{toast('请选中日志文字手动复制')}};
 if(!panel.open||(!force&&taskLogState.paused))return;
 try{
  const value=await api('/v1/scans/'+id+'/logs');
  if(!panel.isConnected||taskLogState.id!==id)return;
  const atBottom=pre.scrollTop+pre.clientHeight>=pre.scrollHeight-24;
  taskLogState.text=value.text;pre.textContent=value.text;
  if(atBottom)pre.scrollTop=pre.scrollHeight;
  panel.querySelector('#log-hint').textContent=(value.truncated?'仅显示日志末尾约 16 KB。':'')+' 更新于 '+new Date().toLocaleTimeString();
 }catch(error){if(panel.isConnected)panel.querySelector('#log-hint').textContent=error.message}
}


function modelMetricsPanel(metrics){
 if(!metrics)return '<section class="note" style="margin:20px 0"><h3>模型调用统计</h3><p class="muted">暂无调用统计。新任务开始调用模型后会在这里自动更新，历史任务可能没有保存这些数据。</p></section>';
 const count=key=>Number.isSafeInteger(metrics[key])&&metrics[key]>=0?metrics[key].toLocaleString('zh-CN'):'—';
 const row=(label,input,output)=>`<tr><th scope="row">${label}</th><td>${count(input)}</td><td>${count(output)}</td></tr>`;
 const legacy=metrics.source==='engine_totals';
 return `<section class="note" style="margin:20px 0"><h3>模型调用统计</h3><div class="tablewrap"><table><thead><tr><th>统计维度</th><th>输入 Token</th><th>输出 Token</th></tr></thead><tbody>${row('任务累计','total_input_tokens','total_output_tokens')}${row('最高连续 60 秒','peak_minute_input_tokens','peak_minute_output_tokens')}${row('最高单次','max_input_tokens','max_output_tokens')}</tbody></table></div><p>最高模型调用并发数 <strong>${count('max_concurrency')}</strong>　调用次数 <strong>${count('requests')}</strong>　限流重试次数 <strong>${count('rate_limit_retries')}</strong></p><p class="muted">${legacy?'此历史任务仅保存了引擎汇总用量，峰值和并发数暂无记录。':'分钟峰值按调用完成时间的连续 60 秒滚动窗口计算。用量仅取模型响应 usage，未返回的用量不计入 Token 总量。用量未知的调用数 '+count('unknown_usage_requests')+'。'}</p></section>`;
}

let modelCallState={};
function modelCallPanel(){
 return `<details class="note" id="model-calls-panel" style="margin:20px 0" ${modelCallState.open?'open':''}><summary>模型调用明细（管理员）</summary><p class="muted">查看每次实际请求的 messages / input、工具定义、模型参数和返回文字。凭据已脱敏，图片数据省略。仅新版本执行的调用有记录。</p><div class="model-call-list">展开后读取调用记录。</div></details>`;
}
function modelRecordText(value){return JSON.stringify(value,null,2)}
async function updateModelCalls(id){
 const panel=document.querySelector('#model-calls-panel');if(!panel)return;
 panel.ontoggle=()=>{modelCallState.open=panel.open;if(panel.open)updateModelCalls(id)};
 if(!panel.open)return;
 const list=panel.querySelector('.model-call-list');
 try{
  const value=await api('/v1/scans/'+id+'/model-calls?page='+modelCallState.page);
  if(!panel.isConnected||modelCallState.id!==id)return;
  list.innerHTML=value.items.map(call=>`<details class="note" data-call="${esc(call.id)}" style="margin:10px 0" ${modelCallState.selected===call.id?'open':''}><summary>${date(call.started)} · ${esc(call.model||'未标注模型')} · ${call.status?'HTTP '+esc(call.status):'请求中'}</summary><div data-call-content>正在读取…</div></details>`).join('')||'<p>暂无模型调用明细。旧任务无法补录当时的完整请求。</p>';
  list.innerHTML+=`<div class="actions"><span>共 ${value.total} 次 · 第 ${value.page} 页</span><button class="secondary" id="calls-prev" ${value.page<=1?'disabled':''}>上一页</button><button class="secondary" id="calls-next" ${value.page*20>=value.total?'disabled':''}>下一页</button></div>`;
  list.querySelector('#calls-prev').onclick=()=>{modelCallState.page--;updateModelCalls(id)};
  list.querySelector('#calls-next').onclick=()=>{modelCallState.page++;updateModelCalls(id)};
  const load=async(element,call)=>{
   const slot=element.querySelector('[data-call-content]');
   try{
    let record=modelCallState.cache[call.id];
    if(!record||record.finished!==call.finished){record=await api('/v1/scans/'+id+'/model-calls/'+call.id);modelCallState.cache[call.id]=record}
    if(!element.isConnected)return;
    const usage=record.response?.usage;
    slot.innerHTML=`<p>${esc(record.url||'')}<br>输入 Token：${esc(usage?.prompt_tokens??usage?.input_tokens??'未知')}　输出 Token：${esc(usage?.completion_tokens??usage?.output_tokens??'未知')}</p>${record.notice?`<p class="note warn">${esc(record.notice)}</p>`:''}<h4>实际请求参数与输入文字</h4><pre style="white-space:pre-wrap;overflow-wrap:anywhere;max-height:420px;overflow:auto;user-select:text">${esc(modelRecordText(record.request??record.detail_preview??null))}</pre><h4>模型返回内容</h4><pre style="white-space:pre-wrap;overflow-wrap:anywhere;max-height:420px;overflow:auto;user-select:text">${esc(modelRecordText(record.response))}</pre>${record.error?`<p class="note warn">${esc(record.error)}</p>`:''}`;
   }catch(error){slot.textContent=error.message}
  };
  for(const element of list.querySelectorAll('[data-call]')){
   const call=value.items.find(item=>item.id===element.dataset.call);
   element.ontoggle=()=>{if(element.open){modelCallState.selected=call.id;load(element,call)}else if(modelCallState.selected===call.id)modelCallState.selected=null};
   if(element.open)await load(element,call);
  }
 }catch(error){if(panel.isConnected)list.textContent=error.message}
}
