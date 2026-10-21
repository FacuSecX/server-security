(()=>{
 'use strict';
 const dialog=document.getElementById('serviceVersionsDialog'),list=document.getElementById('serviceVersionSelect'),message=document.getElementById('serviceVersionsMessage');
 let kind='ftp',mode='install',catalog=null,pending=false,polling=false,selected='',pollNeeded=false;
 const button=document.getElementById('serviceVersionContinue'),refreshButton=document.getElementById('serviceVersionsRefresh');
 function render(data){
  catalog=data.catalog;const running=data.job?.status==='running';pollNeeded=running;
  message.textContent=running?data.job.message:data.job?.status==='error'?data.job.message:catalog?.notice||'Actualizá los repositorios para consultar las versiones disponibles.';
  message.classList.toggle('auth-error',data.job?.status==='error');
  if(mode==='upgrade'&&!running&&catalog&&catalog.upgrade_available!==true&&data.job?.status!=='error')message.textContent=(!catalog.installed_version?'El servicio no está instalado. ':!catalog.latest_id?'No hay una actualización de la misma rama en los repositorios actuales; cambiar de rama requiere una migración. ':'Ya está instalada la versión más reciente compatible con su rama. ')+catalog.notice;
  const old=list.value;list.replaceChildren();
  for(const [index,row] of (catalog?.versions||[]).entries()){
   const option=document.createElement('option');option.value=row.id;
   option.textContent=row.version+(index===0?' · más reciente encontrada':'')+(row.archived?' · archivo oficial':' · repositorio activo')+(row.version===catalog.installed_version?' · instalada':'')+(mode==='upgrade'&&!row.upgrade_compatible?' · requiere migración':'');
   option.title=row.repository||'';option.disabled=mode==='upgrade'&&row.id!==catalog.latest_id;list.append(option);
  }
  if(mode==='upgrade')list.value=catalog?.latest_id||'';else if([...list.options].some(o=>o.value===old))list.value=old;
  selected=list.value;list.disabled=running||pending||mode==='upgrade';button.disabled=running||pending||!selected||(mode==='upgrade'&&catalog?.upgrade_available!==true);refreshButton.disabled=running||pending;
  document.getElementById('serviceVersionsInstalled').textContent=catalog?.installed_version?'Versión instalada: '+catalog.installed_version:'Servicio sin instalar.';
 }
 async function read(){
  if(polling)return;polling=true;
  try{const response=await fetch('/api/service-versions?service='+kind,{signal:AbortSignal.timeout(8000)}),data=await response.json();if(!response.ok)throw new Error(data.error||'No se pudo consultar el catálogo.');
   if(data.action_token)state.actionToken=data.action_token;render(data);
  }catch(error){message.textContent=error.message;message.classList.add('auth-error');button.disabled=true;}
  finally{polling=false;}
 }
 async function refresh(){
  if(pending)return;pending=true;button.disabled=true;refreshButton.disabled=true;list.disabled=true;catalog=null;let started=false;message.textContent='Actualizando repositorios y consultando versiones…';message.classList.remove('auth-error');
  try{const response=await fetch('/api/service-versions',{method:'POST',headers:{'Content-Type':'application/json','X-StoryPulse-Token':state.actionToken},body:JSON.stringify({service:kind}),signal:AbortSignal.timeout(10000)}),data=await response.json();if(!response.ok)throw new Error(data.error||'No se pudo actualizar el catálogo.');started=true;}
  catch(error){message.textContent=error.message;message.classList.add('auth-error');}
  finally{pending=false;refreshButton.disabled=false;if(started)await read();}
 }
 function open(service,action){if(dialog.open||pending)return;kind=service;mode=action;catalog=null;selected='';list.replaceChildren();button.disabled=true;
  document.getElementById('serviceVersionsTitle').textContent=(action==='upgrade'?'Actualizar ':'Instalar ')+(service==='ftp'?'FTP':'MySQL / MariaDB');
  document.getElementById('serviceVersionsInstalled').textContent='Consultando el servidor…';
  button.textContent=action==='upgrade'?'Revisar actualización':'Revisar versión seleccionada';dialog.showModal();void refresh();
 }
 window.ServiceVersions=Object.freeze({open});
 refreshButton.addEventListener('click',()=>void refresh());list.addEventListener('change',()=>{selected=list.value;button.disabled=!selected;});
 document.getElementById('serviceVersionsClose').addEventListener('click',()=>dialog.close());
 button.addEventListener('click',()=>{if(button.disabled||!catalog||!selected)return;const payload={action:mode,selection:selected};if(kind==='ftp'&&mode==='install')payload.open_firewall=document.getElementById('ftpOpenFirewall').checked;
  dialog.close();if(kind==='ftp')void previewService(payload);else void previewMysql(payload);
 });
 document.getElementById('ftpUpgrade').addEventListener('click',()=>open('ftp','upgrade'));document.getElementById('mysqlUpgrade').addEventListener('click',()=>open('mysql','upgrade'));
 setInterval(()=>{if(dialog.open&&!pending&&pollNeeded)void read();},2500);
})();