'use strict';
let docsToken='',docsExpires=0,docsEndpoint='whitebox';
function resetDocCredentials(){docsToken='';docsExpires=0}
const scanContracts=[
 {id:'whitebox',title:'白盒扫描',path:'/v1/scans/whitebox',type:'multipart/form-data',description:'上传项目代码 ZIP，创建白盒扫描任务。',fields:[
  ['project','file','是','项目 ZIP，最大 50 MiB'],['name','string','否','任务名称，最多 100 字'],['instructions','string','否','测试要求，最多 4000 字'],['authorized','boolean','是','填写 true，确认已获得测试授权']]},
 {id:'blackbox',title:'黑盒扫描',path:'/v1/scans/blackbox',type:'application/json',description:'提交已授权的系统根地址，创建黑盒扫描任务。',fields:[
  ['target','string','是','已登记的 HTTP(S) 根地址'],['name','string','否','任务名称，最多 100 字'],['instructions','string','否','测试要求，最多 4000 字'],['authorized','boolean','是','填写 true，确认已获得测试授权']]},
 {id:'greybox',title:'灰盒扫描',path:'/v1/scans/greybox',type:'application/json',description:'提交系统地址和测试账号凭据，创建登录后扫描任务。',fields:[
  ['target','string','是','已登记的 HTTP(S) 根地址'],['name','string','否','任务名称，最多 100 字'],['instructions','string','否','测试要求，最多 4000 字'],['accounts','array','是','1—5 个测试账号，结构见下方示例'],['accounts[].label','string','是','账号名称，如普通用户 A'],['accounts[].role','string','否','账号角色或权限说明'],['accounts[].method','string','是','示例使用 headers；也支持 password、cookie、bearer'],['accounts[].auth','array','按方式','headers 方式的凭据列表：type 为 header / cookie，name 和 value 为名称和值'],['accounts[].username / password','string','按方式','password 方式填写，login_path 可填写本站登录页路径'],['accounts[].cookie / token','string','按方式','cookie / bearer 方式对应填写 Cookie 值或 Token'],['accounts[].verify_path','string','否','验证接口相对路径，如 /api/me；留空时密码方式验证登录页，其他方式验证根路径'],['authorized','boolean','是','填写 true，确认已获得测试授权']]}
];
const shellQuote=value=>"'"+String(value).replace(/'/g,"'\\''")+"'";
function docsBody(kind){
 const value={name:kind==='greybox'?'灰盒接口测试':'黑盒接口测试',target:'https://test.example.com/',instructions:'重点检测越权漏洞，仅执行非破坏性验证',authorized:true};
 if(kind==='greybox')value.accounts=[{label:'普通用户 A',role:'只允许访问本人数据',method:'headers',auth:[{type:'header',name:'Authorization',value:'Bearer TARGET_SYSTEM_TOKEN'}]}];
 return value;
}
function curlText(endpoint,token='YOUR_TOKEN'){
 const parts=[`curl --request POST ${shellQuote(location.origin+endpoint.path)}`,`  --header ${shellQuote('Authorization: Bearer '+token)}`];
 if(endpoint.id==='whitebox')parts.push("  --form 'project=@/path/to/project.zip'","  --form 'name=白盒接口测试'","  --form 'instructions=重点检测越权漏洞'","  --form 'authorized=true'");
 else parts.push("  --header 'Content-Type: application/json'",`  --data-raw ${shellQuote(JSON.stringify(docsBody(endpoint.id),null,2))}`);
 return parts.join(' \\\n');
}
function docsTable(rows){return `<div class="tablewrap"><table><thead><tr><th>字段</th><th>类型</th><th>必填</th><th>说明</th></tr></thead><tbody>${rows.map(row=>'<tr>'+row.map(v=>'<td>'+esc(v)+'</td>').join('')+'</tr>').join('')}</tbody></table></div>`}
function updateDocsExpiry(){const node=document.querySelector('#docs-token-expiry');if(node)node.textContent=docsExpires>Date.now()/1000?'有效期至 '+date(docsExpires):'首次复制时生成，7 天后自动过期。'}
async function ensureDocsToken(){
 if(docsToken&&docsExpires>Date.now()/1000)return docsToken;
 const owner=me?.owner;
 const value=await api('/web/api-tokens/personal',{method:'POST'});
 if(!me||me.owner!==owner)throw Error('登录账号已变化，请重新操作');
 docsToken=value.token;docsExpires=value.expires;updateDocsExpiry();return docsToken;
}
async function copyDocs(text,message){
 const buffer=document.createElement('textarea');buffer.value=text;buffer.readOnly=true;buffer.style.cssText='position:fixed;left:-9999px;top:0';document.body.append(buffer);buffer.select();let copied=false;
 try{copied=document.execCommand('copy')}catch{}buffer.remove();
 if(!copied){try{await navigator.clipboard.writeText(text);copied=true}catch{}}
 if(copied){toast(message);return}
 const fallback=document.querySelector('#docs-manual-copy');if(fallback){fallback.hidden=false;fallback.style.display='block';fallback.value=text;fallback.focus();fallback.select()}
 toast('浏览器限制自动复制，内容已选中，请按 Ctrl+C');
}
async function copyPersonalDocs(button,isCurl){
 button.disabled=true;
 try{const endpoint=scanContracts.find(e=>e.id===docsEndpoint),token=await ensureDocsToken();await copyDocs(isCurl?curlText(endpoint,token):token,isCurl?'已复制 cURL，可导入 Postman':'已复制你的 Token，7 天有效')}
 catch(error){toast(error.message)}finally{button.disabled=false}
}
async function apiDocsPage(){
 document.querySelector('#content').innerHTML=head('接口文档','使用个人 Token 调用扫描接口，复制 cURL 即可导入 Postman。')+`<div class="card"><div class="cardbody"><h2>接口鉴权</h2><div class="actions"><code>Authorization: Bearer &lt;TOKEN&gt;</code><button class="primary" id="docs-copy-token">复制我的 Token（7 天有效）</button></div><p class="muted" id="docs-token-expiry" style="margin:14px 0 0"></p></div></div><div class="card"><div class="cardbody"><div class="scan-tabs" role="tablist" aria-label="扫描接口">${scanContracts.map(e=>`<button type="button" role="tab" aria-selected="${docsEndpoint===e.id}" data-doc-tab="${e.id}" class="scan-tab ${docsEndpoint===e.id?'active':''}">${e.title}</button>`).join('')}</div><div id="docs-contract"></div></div></div><textarea id="docs-manual-copy" class="api-code" aria-label="手动复制内容" readonly hidden style="display:none"></textarea>`;
 updateDocsExpiry();document.querySelector('#docs-copy-token').onclick=e=>copyPersonalDocs(e.currentTarget,false);
 document.querySelectorAll('[data-doc-tab]').forEach(button=>button.onclick=()=>{docsEndpoint=button.dataset.docTab;document.querySelectorAll('[data-doc-tab]').forEach(tab=>{const selected=tab.dataset.docTab===docsEndpoint;tab.classList.toggle('active',selected);tab.setAttribute('aria-selected',String(selected))});const fallback=document.querySelector('#docs-manual-copy');fallback.hidden=true;fallback.style.display='none';fallback.value='';renderContract()});
 renderContract();
}
function renderContract(){
 const e=scanContracts.find(item=>item.id===docsEndpoint);
 const response={id:'0123456789abcdef0123456789abcdef',status:'queued',status_url:'/v1/scans/0123456789abcdef0123456789abcdef'};
 document.querySelector('#docs-contract').innerHTML=`<div class="actions"><span class="tag kind">POST</span><code>${esc(e.path)}</code><span class="muted">${esc(e.type)}</span></div><p class="muted" style="margin-top:16px">${esc(e.description)}</p><h3>请求参数</h3>${docsTable(e.fields)}<div class="actions" style="margin:24px 0 12px;justify-content:space-between"><h3 style="margin:0">cURL 示例</h3><button class="primary" id="docs-copy-curl">复制 cURL</button></div><pre class="api-code">${esc(curlText(e))}</pre><p class="muted">复制时自动带入你的 Token。导入 Postman 后替换目标${e.id==='whitebox'?'和本地 ZIP 文件路径':e.id==='greybox'?'和目标系统的测试凭据':''}。</p><h3 style="margin-top:24px">返回结果 · HTTP 202</h3><pre class="api-code" style="min-height:0">${esc(JSON.stringify(response,null,2))}</pre><p class="muted"><code>id</code> 为任务编号，<code>status</code> 为当前状态，<code>status_url</code> 用于查询进度；任务完成后通过查询结果中的 <code>report_url</code> 获取报告。HTTP 202 表示已受理。</p>`;
 document.querySelector('#docs-copy-curl').onclick=e=>copyPersonalDocs(e.currentTarget,true);
}

