/*
Server Security Monitor v2.0
Created by FacuSecX
https://github.com/FacuSecX/
*/
(() => {
  'use strict';
  const byId=id=>document.getElementById(id);
  const dialog=byId('notificationsDialog'),bell=byId('notificationBell');
  let data=null,inFlight=null,marking=false,nextBefore=null,lastRefresh=0;
  function element(tag,text,className) {
    const node=document.createElement(tag);if(text!==undefined)node.textContent=text;
    if(className)node.className=className;return node;
  }
  function status(value) {
    data=value;
    window.dispatchEvent(new CustomEvent('server-monitor-notifications',{detail:value}));
    const count=Number(value.unread)||0,badge=byId('notificationCount');
    badge.textContent=count>99?'99+':String(count);badge.hidden=count===0;
    bell.setAttribute('aria-label',`Notificaciones de seguridad: ${count} sin leer`);
    byId('notificationsSummary').textContent=count?`${count} ${count===1?'alerta sin leer':'alertas sin leer'}`:'Todas las alertas están leídas';
    byId('notificationsReadAll').disabled=marking||count===0;
    byId('notificationsDeleteRead').disabled=marking||!value.read_count;
    const monitor=value.monitor||{},services=(monitor.services||[]).map(s=>s.service).join(', ');
    const unavailable=(monitor.access_sources||[]).filter(s=>!s.ready);
    const coverageMissing=unavailable.length>0;
    byId('notificationsCoverage').textContent=!monitor.ready?(monitor.error||'Esperando la configuración de alertas.'):
      `${value.connected?'Monitoreando':'Última sincronización; Servidor desconectado'}: ${services||'SSH'}${coverageMissing?' · Falta una fuente de autenticación para '+unavailable.map(s=>s.service).join(', '):''}`;
    bell.classList.toggle('monitor-warning',!monitor.ready||!value.connected||coverageMissing);
    bell.title=!monitor.ready?'Revisá la configuración de alertas':!value.connected?'Servidor desconectado; se muestra el último estado':'Notificaciones de seguridad';
  }
  function renderRows(rows,append) {
    const list=byId('notificationsList');if(!append)list.replaceChildren();
    if(!rows.length&&!append)list.append(element('p','No hay alertas registradas.','notifications-empty'));
    for(const item of rows) {
      const card=element('article',undefined,'notification-item'+(item.read_at?' is-read':''));
      const heading=element('div',undefined,'notification-item-heading');
      heading.append(element('strong',item.service),element('time',new Date(item.timestamp*1000).toLocaleString('es-AR')));
      card.append(heading,element('p',item.ip,'notification-ip'),element('p',item.detail));
      if(!item.read_at){const read=element('button','Marcar como leída','text-button');read.type='button';
        read.disabled=marking;read.addEventListener('click',()=>mutate('read',{id:item.id}));card.append(read);}
      else {
        const actions=element('div',undefined,'notification-read-actions'),remove=element('button','Borrar','text-button notification-delete');
        remove.type='button';remove.disabled=marking;
        remove.setAttribute('aria-label',`Borrar notificación leída de ${item.service}, IP ${item.ip}`);
        remove.addEventListener('click',()=>mutate('delete',{id:item.id}));
        actions.append(element('small','Leída'),remove);card.append(actions);
      }
      list.append(card);
    }
  }
  async function refresh({before=null,append=false}={}) {
    if(inFlight)return inFlight;
    const pending=(async()=>{
      try {
        const response=await fetch('/api/notifications'+(before?'?before='+before:''),{cache:'no-store',signal:AbortSignal.timeout(8000)});
        const value=await response.json();if(!response.ok)throw new Error(value.error||'No se pudieron cargar las alertas.');
        status(value);lastRefresh=Date.now();byId('notificationsError').textContent='';
        if(dialog.open){renderRows(value.items||[],append);nextBefore=value.next_before;byId('notificationsMore').hidden=!nextBefore;}
      } catch(error){byId('notificationsError').textContent=error.name==='TimeoutError'?'La consulta de alertas tardó demasiado. Intentá de nuevo.':error.message;}
    })();
    inFlight=pending;try{await pending;}finally{inFlight=null;}
  }
  async function mutate(action,body) {
    if(marking||!data?.action_token)return;
    marking=true;byId('notificationsReadAll').disabled=true;byId('notificationsDeleteRead').disabled=true;
    dialog.querySelectorAll('.notification-item button').forEach(b=>b.disabled=true);
    try {
      const response=await fetch('/api/notifications/'+action,{method:'POST',headers:{'Content-Type':'application/json','X-StoryPulse-Token':data.action_token},body:JSON.stringify(body),signal:AbortSignal.timeout(8000)});
      const value=await response.json();if(!response.ok)throw new Error(value.error||'No se pudo actualizar la notificación.');
      if(inFlight)await inFlight;
      marking=false;await refresh();
    }catch(error){byId('notificationsError').textContent=error.message;}
    finally{marking=false;byId('notificationsReadAll').disabled=!data?.unread;byId('notificationsDeleteRead').disabled=!data?.read_count;
      dialog.querySelectorAll('.notification-item button').forEach(b=>b.disabled=false);}
  }
  bell.addEventListener('click',async()=>{if(!dialog.open)dialog.showModal();if(inFlight)await inFlight;await refresh();});
  byId('notificationsClose').addEventListener('click',()=>dialog.close());
  dialog.addEventListener('click',event=>{if(event.target===dialog){const box=dialog.getBoundingClientRect();
    if(event.clientX<box.left||event.clientX>box.right||event.clientY<box.top||event.clientY>box.bottom)dialog.close();}});
  byId('notificationsReadAll').addEventListener('click',()=>mutate('read',{through_id:data?.through_id??0}));
  byId('notificationsDeleteRead').addEventListener('click',()=>mutate('delete',{through_id:data?.through_id??0}));
  byId('notificationsMore').addEventListener('click',()=>refresh({before:nextBefore,append:true}));
  window.addEventListener('storypulse-authorizations',()=>refresh());
  window.addEventListener('storypulse-dashboard',()=>{if(!document.hidden&&Date.now()-lastRefresh>10000&&!marking)refresh();});
  document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});
  setInterval(()=>{if(!marking&&Date.now()-lastRefresh>=4500)void refresh();},5000);
  refresh();
})();
