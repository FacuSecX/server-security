/*
Server Security Monitor v2.0
Created by FacuSecX
https://github.com/FacuSecX/
*/
(() => {
  'use strict';
  const $=id=>document.getElementById(id);let state=null,loading=null,changing=false;
  function render(value){
    state=value;
    $('alertsState').textContent=!value.configured?'Sin configurar · El sistema de alertas anterior permanece independiente.':value.enabled?'🟢 Envío activado':'⏸ Envío desactivado';
    $('alertsState').classList.toggle('alerts-enabled',!!value.configured&&!!value.enabled&&!!value.running);
    $('alertsService').textContent=value.installed?'Servicio instalado una sola vez': 'Servicio pendiente de instalar en el servidor';
    $('alertsRuntime').textContent=value.runtime?.error||(!value.configured?'Creá un bot nuevo en BotFather e iniciá una conversación con él.':!value.running?'El servicio no está ejecutándose. Guardá la configuración para iniciarlo.':value.runtime?.last_sent?'Último envío: '+new Date(value.runtime.last_sent*1000).toLocaleString('es-AR'):'El receptor de controles está activo.');
    $('alertsRuntime').classList.toggle('error',!!value.runtime?.error||(value.configured&&!value.running));
    $('alertsAccount').textContent=value.configured?'Bot: @'+value.bot_username+' · Chat: '+value.chat_id:'Aún no se guardaron credenciales.';
    $('alertsPrepared').disabled=true;
    $('alertsSave').disabled=changing||!value.installed;
    $('alertsToggle').disabled=changing||!value.configured;$('alertsToggle').textContent=value.enabled?'Desactivar envío':'Activar envío';
    $('alertsCoverage').textContent=(value.runtime?.coverage||[]).map(row=>row.service+': '+(row.ready?row.mode:'fuente de autenticación pendiente')).join(' · ');
  }
  async function load(){
    if(loading||changing)return loading;
    loading=(async()=>{try{const r=await fetch('/api/alerts',{cache:'no-store',signal:AbortSignal.timeout(12000)});const v=await r.json();if(!r.ok)throw new Error(v.error);render(v);$('alertsError').textContent='';}catch(e){$('alertsError').textContent=e.message;}finally{loading=null;}})();return loading;
  }
  async function save(body){
    if(changing||!state)return;
    changing=true;$('alertsSave').disabled=true;$('alertsToggle').disabled=true;$('alertsError').textContent='';
    try{
      const r=await fetch('/api/alerts/configure',{method:'POST',headers:{'Content-Type':'application/json','X-StoryPulse-Token':state.action_token},body:JSON.stringify({...body,revision:state.revision,confirm:true}),signal:AbortSignal.timeout(65000)});
      const v=await r.json();if(!r.ok)throw new Error(v.error||'No se pudo guardar.');
      render({...v,action_token:state.action_token});$('alertsForm').reset();$('alertsError').textContent='Configuración guardada en el servidor.';
    }catch(e){$('alertsError').textContent=e.message;}
    finally{if('token' in body)body.token='';$('alertsToken').value='';changing=false;if(state)render(state);}
  }
  $('alertsForm').addEventListener('submit',event=>{
    event.preventDefault();if(!state)return;
    const chat=$('alertsChat').value.trim()||state.chat_id;
    const admin=$('alertsAdmin').value.trim()||(chat===state.chat_id?state.admin_id:'');
    void save({token:$('alertsToken').value.trim(),chat_id:chat,admin_id:admin,enabled:$('alertsEnable').checked});
  });
  $('alertsToggle').addEventListener('click',()=>{if(state)void save({enabled:!state.enabled});});
  $('alertsRefresh').addEventListener('click',load);
  window.addEventListener('storypulse-view',event=>{if(event.detail==='alerts')void load();});
  setInterval(()=>{if(!document.hidden&&document.getElementById('view-alerts')?.classList.contains('active'))void load();},5000);
  if(document.getElementById('view-alerts')?.classList.contains('active'))void load();
})();
