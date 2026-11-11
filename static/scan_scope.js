'use strict';
function scopeEntries(value){return String(value||'').split(/[\s,，;；]+/).filter(Boolean).join(',')}
async function scanScopePage(){
 const container=document.querySelector('#content');
 container.innerHTML=head('扫描范围','设置允许检测的系统地址，保存后生效，无需重启服务。')+'<div class="card"><div class="cardbody">正在读取扫描范围…</div></div>';
 try{
  const config=await api('/web/admin/config');if(view!=='scope')return;
  container.innerHTML=head('扫描范围','设置允许检测的系统地址，保存后生效，无需重启服务。')+`<div class="card" style="max-width:900px"><form id="scope-form" class="cardbody">
   <label style="display:flex;align-items:center;gap:12px;font-size:18px;font-weight:600"><input type="checkbox" name="scope_restrictions_enabled" role="switch" style="width:22px;height:22px;accent-color:#008c85" ${config.scope_restrictions_enabled?'checked':''}>开启扫描范围限制</label>
   <p id="scope-state" role="status"></p>
   <fieldset id="scope-rules" hidden style="border:0;padding:0;margin:20px 0">
   ${area('allowed_hosts','允许扫描的域名或 IP',config.allowed_hosts.split(',').filter(Boolean).join('\n'),'每行一个，例如 test.example.com 或 10.20.30.40。只填域名/IP，不填 https://、路径或通配符。')}
   ${area('allowed_cidrs','允许的目标 IP / 网段',config.allowed_cidrs.split(',').filter(Boolean).join('\n'),'每行一个，例如 10.20.30.40 或 10.20.0.0/16。填写域名时，它解析出的所有 IP 也必须落在这里。')}
   ${field('allowed_ports','允许访问的端口',config.allowed_ports,'例如 80,443,8080；多个端口用逗号分隔。')}
   <div class="note">关闭时不校验目标白名单，已填写规则会保留。开启后，域名/IP、解析后的 IP 范围和端口必须同时符合，才能提交黑盒、灰盒任务。清空目标或 IP 范围会禁止新的在线扫描；白盒源码扫描不受影响。本机回环、链路本地等基础安全校验始终保留；此配置不会自动打通网络。</div>
   </fieldset>
   <div class="actions" style="margin-top:20px"><button type="submit" class="primary">保存扫描范围</button></div><div id="scope-result" role="status" style="margin-top:16px"></div>
  </form></div>`;
  const form=document.querySelector('#scope-form');
  const toggle=form.elements.scope_restrictions_enabled;
  const updateScope=()=>{form.querySelector('#scope-rules').disabled=!toggle.checked;form.querySelector('#scope-rules').hidden=!toggle.checked;form.elements.allowed_ports.required=toggle.checked;form.querySelector('#scope-state').textContent=toggle.checked?'已开启：仅允许检测下方规则内的目标。':'已关闭：不限制目标域名、IP 范围及端口。'};
  toggle.onchange=updateScope;updateScope();
  form.onsubmit=async event=>{
   event.preventDefault();const button=form.querySelector('[type=submit]');button.disabled=true;
   const result=form.querySelector('#scope-result');result.textContent='正在保存…';
   try{
    const data=Object.fromEntries(['allowed_hosts','allowed_cidrs','allowed_ports'].map(key=>[key,scopeEntries(form.elements[key].value)]));
    data.scope_restrictions_enabled=toggle.checked;
    const saved=await api('/web/admin/config',{method:'PUT',body:JSON.stringify(data)});
    for(const key of ['allowed_hosts','allowed_cidrs'])form.elements[key].value=saved[key].split(',').filter(Boolean).join('\n');
    form.elements.allowed_ports.value=saved.allowed_ports;
    result.innerHTML='<div class="note">扫描范围已保存，新提交任务立即使用新范围。已排队任务执行前还会重新核对当前授权；正在执行的任务不会因此自动停止。</div>';
   }catch(error){result.innerHTML=`<div class="note warn" role="alert">${esc(error.message)}</div>`}
   finally{button.disabled=false}
  };
 }catch(error){if(view==='scope')container.innerHTML=head('扫描范围','管理允许检测的系统地址。')+`<div class="note warn">${esc(error.message)}</div>`}
}
