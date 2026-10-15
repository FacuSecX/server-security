/*
Server Security Monitor v2.0
Created by FacuSecX
https://github.com/FacuSecX/
*/
(() => {
  'use strict';
  const nativeFetch=window.fetch.bind(window),minimum=5000;
  const postPaths=new Set(['/api/ports/plan','/api/ports/apply','/api/forwarding/plan','/api/forwarding/apply',
    '/api/services/plan','/api/services/apply','/api/mysql/plan','/api/mysql/apply','/api/mysql/structure','/api/mysql/login','/api/mysql/data',
    '/api/cleanup/plan','/api/cleanup/apply','/api/server/reboot/plan','/api/server/reboot',
    '/api/authorized-ips/plan','/api/authorized-ips/apply','/api/blocks/ip','/api/blocks/provider','/api/providers/evaluate',
    '/api/reports/ssh','/api/refresh','/api/alerts/configure']);
  const manualReads=new Set(['/api/ports','/api/forwarding','/api/services','/api/mysql','/api/cleanup','/api/authorized-ips','/api/blocks','/api/server','/api/alerts']);
  const ids=new Set(['alertsSave','alertsToggle','alertsRefresh','portsRefresh','managedPortApply','forwardingRefresh','forwardingReview','forwardingApply',
    'ftpInstall','ftpUserReview','servicesApply','mysqlInstall','mysqlApply','dbReload','dbPrevious','dbNext',
    'authorizedRefresh','authorizedAdd','authorizedApply','cleanupRefresh','cleanupNow','cleanupSchedule','cleanupConfirmApply',
    'serverRebootOpen','serverRebootApply','sshReportGenerate','sshReportRetry','blockIpButton','blockConfirmApply',
    'unblockConfirmApply','providerBlockConfirmApply','providerUnblockConfirmApply','reloadBlocks','refreshButton']);
  const forms=new Set(['alertsForm','portsInspectForm','forwardingForm','ftpUserForm','mysqlDatabaseForm','mysqlUserForm','mysqlStructureForm',
    'mysqlNetworkForm','dbLogin','dbSearchForm','dbRecordForm','authorizedForm','cleanupScheduleForm','sshReportForm','ipForm','blockIpForm','providerEvaluateForm']);
  let pending=false,queued=false,serverBusy=false,until=0,token='',statusRequest=null,watchTimer=null,manualIntent=false;
  const marked=new Map();
  const locked=()=>pending||queued||serverBusy||Date.now()<until;
  function remoteButton(button){
    if(ids.has(button.id))return true;
    if(button.matches('.services-refresh,.mysql-refresh,[data-mysql-tab="structure"],[data-mysql-user]:not([data-mysql-user="edit"]),[data-port-action],[data-ftp-service],[data-mysql-service],[data-cleanup-action]'))return true;
    if(button.matches('[data-forward-action]:not([data-forward-action="edit"]),[data-ftp-user-action]:not([data-ftp-user-action="edit"])'))return true;
    if(button.closest('#authorizedRows,#dbTables'))return true;
    return button.type==='submit'&&forms.has(button.form?.id);
  }
  function render(){
    const blocked=locked(),notice=document.getElementById('remoteCommandStatus');
    document.documentElement.dataset.commandBlocked=blocked?'true':'false';
    for(const button of document.querySelectorAll('button')){
      if(!remoteButton(button))continue;
      button.dataset.remoteCommand='true';
      if(blocked){if(!marked.has(button))marked.set(button,button.getAttribute('aria-disabled'));button.setAttribute('aria-disabled','true');}
      else if(marked.has(button)){const old=marked.get(button);if(old===null)button.removeAttribute('aria-disabled');else button.setAttribute('aria-disabled',old);marked.delete(button);}
    }
    for(const button of marked.keys())if(!button.isConnected)marked.delete(button);
    const dialog=document.querySelector('dialog[open]');
    const text=pending||serverBusy?'Esperando la respuesta del servidor…':Date.now()<until?'Podés enviar otra acción en '+Math.max(1,Math.ceil((until-Date.now())/1000))+' s.':'Preparando la próxima consulta…';
    if(notice){notice.hidden=!blocked||!!dialog;if(notice.textContent!==text)notice.textContent=text;}
    if(dialog&&blocked&&!dialog.querySelector('.remote-command-dialog-status')){
      const line=document.createElement('p');line.className='remote-command-dialog-status';line.setAttribute('role','status');
      (dialog.querySelector('.confirm-content,.dialog-surface')||dialog).append(line);
    }
    for(const line of document.querySelectorAll('.remote-command-dialog-status')){
      line.hidden=!blocked||!line.closest('dialog').open;
      if(line.textContent!==text)line.textContent=text;
    }
  }
  async function sync(){
    if(statusRequest)return statusRequest;
    statusRequest=(async()=>{
      try{
        const response=await nativeFetch('/api/commands/status',{cache:'no-store',signal:AbortSignal.timeout(4000)});
        if(!response.ok)throw new Error('status unavailable');
        const data=await response.json();token=data.action_token||token;serverBusy=!!data.busy;
        if(data.cooldown_ms>0)until=Math.max(until,Date.now()+data.cooldown_ms);
      }catch{serverBusy=false;}
      finally{render();}
    })();
    try{await statusRequest;}finally{statusRequest=null;}
  }
  function watch(){
    clearTimeout(watchTimer);render();
    if(locked())watchTimer=setTimeout(async()=>{await sync();watch();},1000);
  }
  function safeFollowup(path,init){
    if(path==='/api/mysql/structure')return true;
    if(path!=='/api/mysql/data')return false;
    try{return ['tables','table','rows'].includes(JSON.parse(init.body).operation);}catch{return false;}
  }
  window.fetch=async function(input,init={}){
    const url=new URL(typeof input==='string'||input instanceof URL?input:input.url,location.href);
    const method=String(init.method||input?.method||'GET').toUpperCase();
    const protects=url.origin===location.origin&&((method==='POST'&&postPaths.has(url.pathname))||
      (method==='GET'&&(url.pathname==='/api/ip'||(manualIntent&&manualReads.has(url.pathname)))));
    if(!protects)return nativeFetch(input,init);
    if(pending||queued)throw new Error('Hay una solicitud en curso. Esperá su respuesta.');
    queued=true;render();let sent=false;
    try{
      await sync();watch();
      while(serverBusy||Date.now()<until){
        if(!safeFollowup(url.pathname,init))throw new Error('Esperá la respuesta y el tiempo indicado antes de enviar otra acción.');
        init.signal?.throwIfAborted();
        await new Promise(resolve=>setTimeout(resolve,150));
      }
      init.signal?.throwIfAborted();
      const headers=new Headers(init.headers||input?.headers);
      if(token&&!headers.has('X-StoryPulse-Token'))headers.set('X-StoryPulse-Token',token);
      pending=true;queued=false;sent=true;render();
      return await nativeFetch(input,{...init,headers});
    }finally{
      pending=false;queued=false;
      if(sent)until=Math.max(until,Date.now()+minimum);
      void sync().then(watch);
      render();
    }
  };
  document.addEventListener('DOMContentLoaded',()=>{
    render();
    let scheduled=false;
    new MutationObserver(()=>{if(!scheduled){scheduled=true;queueMicrotask(()=>{scheduled=false;render();});}})
      .observe(document.body,{childList:true,subtree:true,attributes:true,attributeFilter:['open']});
    document.addEventListener('click',event=>{
      if(!(event.target instanceof Element))return;
      const button=event.target.closest('button');if(!button||!remoteButton(button))return;
      if(locked()){event.preventDefault();event.stopImmediatePropagation();render();return;}
      manualIntent=true;queueMicrotask(()=>manualIntent=false);
    },true);
    document.addEventListener('submit',event=>{
      if(forms.has(event.target.id)&&locked()){event.preventDefault();event.stopImmediatePropagation();render();}
    },true);
  },{once:true});
})();
