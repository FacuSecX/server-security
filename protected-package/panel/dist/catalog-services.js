(()=>{
 'use strict';
 const names={phpmyadmin:'phpMyAdmin',wordpress:'WordPress',nginx:'Nginx',apache:'Apache HTTP Server',php:'PHP-FPM',certbot:'Certbot / Let’s Encrypt',docker:'Docker Engine',postgresql:'PostgreSQL',redis:'Redis',fail2ban:'Fail2ban',wireguard:'WireGuard',postfix:'Postfix'};
 const descriptions={phpmyadmin:'MySQL desde la web · /phpmyadmin',wordpress:'Instalador de WordPress en la raíz web',nginx:'Web y proxy inverso',apache:'Servidor web HTTP',php:'Aplicaciones PHP',certbot:'Certificados y renovación',docker:'Motor de contenedores',postgresql:'Base de datos relacional',redis:'Datos en memoria',fail2ban:'Protección de accesos',wireguard:'Herramientas VPN',postfix:'Correo SMTP'};
 const categories={phpmyadmin:'Web',wordpress:'Web',nginx:'Web',apache:'Web',php:'Web',certbot:'Web',docker:'Aplicaciones',postgresql:'Datos',redis:'Datos',fail2ban:'Seguridad',wireguard:'Red',postfix:'Correo'};
 const $=id=>document.getElementById(id),dialog=$('catalogDialog');
 let rows=[],loading=null,last=0,service='',action='install',catalog=null,plan=null,request=null,jobId='',pollTimer=null;
 const renderedCards=new Map();
 function element(tag,text,cls){const node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(cls)node.className=cls;return node;}
 function message(text,error=false){$('catalogDialogStatus').textContent=text;$('catalogDialogStatus').classList.toggle('auth-error',error);}
 function card(kind,remove=false,manage=false){
  const row=rows.find(r=>r.id===kind),node=element('article',undefined,'panel catalog-card');node.dataset.catalogService=kind;
  const heading=element('div',undefined,'catalog-card-heading'),img=element('img');img.src='/service-logo-'+kind+'.svg';img.alt='';img.className='catalog-logo';img.loading='eager';heading.append(img,element('h3',names[kind]));node.append(heading,element('span',categories[kind],'panel-tag'),element('p',descriptions[kind]));
  const status=element('p',row?(row.installed?row.state+' · '+row.installed_version:'Todavía no está instalado.'):'Consultando estado…','catalog-state');status.classList.toggle('status-warning',!!row&&!row.installed);node.append(status);
  if(row?.installed&&row.used_by?.length)node.append(element('p','Componente compartido · '+row.used_by.join(', '),'catalog-note'));
  else if(row?.installed&&!row.managed)node.append(element('p','Instalación externa: se conserva su configuración y sus datos.','catalog-note'));
  if(row?.components?.length){
   const details=element('details',undefined,'catalog-components'),summary=element('summary','Componentes PHP instalados ('+row.components.length+')'),list=element('dl');details.append(summary);
   for(const item of row.components)list.append(element('dt',item.package),element('dd',item.version));details.append(list);node.append(details);
  }
  if(row?.phase==='error')node.append(element('p','La última operación falló. Revisá el mensaje y sus registros.','auth-error'));
  const controls=element('div',undefined,'catalog-card-actions');
  if(manage){
   const available=row?.installed&&!['wireguard'].includes(kind);
   for(const [mode,label] of [['start','Iniciar'],['stop','Detener'],['restart','Reiniciar']]){const control=element('button',label,'secondary-button');control.type='button';control.dataset.catalogAction=mode;control.dataset.catalogService=kind;control.disabled=!available||(mode==='start'?row.active:!row.active);controls.append(control);}
   if(kind==='nginx'){const cf=element('button','Protección Cloudflare','secondary-button');cf.type='button';cf.dataset.cloudflareOpen='';cf.disabled=!row?.installed;controls.append(cf);}
   node.append(controls);return node;
  }
  const retry=row?.managed&&row.phase==='error';
  const button=element('button',remove?'Revisar eliminación':retry?'Reparar instalación':row?.installed?'Actualizar':kind==='wordpress'?'Instalar última versión':'Elegir versión',remove?'danger-button':'primary-button');button.type='button';button.dataset.catalogAction=remove?'uninstall':retry?'install':row?.installed?'upgrade':'install';button.dataset.catalogService=kind;button.disabled=!row||(remove?!row.managed:row.installed&&!retry&&(!row.managed||row.upgrade_supported===false));
  if(row?.installed&&!retry&&row.upgrade_supported===false){button.title='WordPress se actualiza desde su propio panel. Para cambiar phpMyAdmin, eliminá y reinstalá la aplicación.';if(!remove)button.textContent='Aplicación instalada';}controls.append(button);node.append(controls);
  return node;
 }
 function renderCards(){
  for(const grid of [$('catalogInstallCards'),$('catalogRemoveCards'),$('catalogManageCards')])for(const kind of Object.keys(names)){
   if(grid.id==='catalogManageCards'&&!rows.find(row=>row.id===kind)?.installed){grid.querySelector('article[data-catalog-service="'+kind+'"]')?.remove();continue;}
   const key=grid.id+':'+kind,signature=JSON.stringify(rows.find(row=>row.id===kind)||null);
   const previous=grid.querySelector('article[data-catalog-service="'+kind+'"]');
   if(previous&&renderedCards.get(key)===signature)continue;
   const next=card(kind,grid.id==='catalogRemoveCards',grid.id==='catalogManageCards');
   if(previous){
    const expanded=previous.querySelector('details')?.open,details=next.querySelector('details');
    if(details)details.open=!!expanded;
    previous.replaceWith(next);
   }else grid.append(next);
   renderedCards.set(key,signature);
  }
  $('catalogManageStatus').textContent=rows.some(row=>row.installed)?'Elegí un servicio para iniciarlo, detenerlo o reiniciarlo.':'Todavía no hay servicios de este catálogo instalados.';
 }
 async function json(url,options){
  const response=await fetch(url,{...options,signal:AbortSignal.timeout(12000)}),data=await response.json();
  if(data.action_token&&typeof state!=='undefined')state.actionToken=data.action_token;
  if(!response.ok)throw new Error(data.error||'No se pudo completar la consulta.');return data;
 }
 function load(force=false){
  if(loading)return loading;
  if(!force&&last&&Date.now()-last<3000)return Promise.resolve();
  loading=(async()=>{
   try{const data=await json('/api/catalog-services');if(data.services){rows=data.services;last=Date.now();renderCards();}$('catalogStatus').textContent=data.job?.status==='running'?data.job.message:(data.distribution?'Distribución: '+data.distribution+'. ':'')+'14 servicios · Versiones reales verificadas antes de instalar.';$('catalogStatus').classList.remove('auth-error');}
   catch(error){$('catalogStatus').textContent=error.message;$('catalogStatus').classList.add('auth-error');}finally{loading=null;}
  })();
  return loading;
 }
 function buttons(busy){$('catalogVersionsRefresh').disabled=busy;$('catalogVersionContinue').disabled=busy||!$('catalogVersionSelect').value;$('catalogConfirm').disabled=busy||!plan||(action==='uninstall'&&!$('catalogErase').checked);}
 function renderCatalog(data){
  catalog=data;$('catalogVersionSelect').replaceChildren();
  for(const [index,row] of (data?.versions||[]).entries()){
   const option=element('option',row.version+(index===0?' · más reciente':'')+(row.archived?' · archivo oficial':' · repositorio activo')+(row.version===data.installed_version?' · instalada':''));option.value=row.id;option.title=row.repository||'';option.disabled=action==='upgrade'&&row.id!==data.latest_id;$('catalogVersionSelect').append(option);
  }
  if(action==='upgrade')$('catalogVersionSelect').value=data?.latest_id||'';
  $('catalogVersionNotice').textContent=(action==='upgrade'&&!data?.latest_id?'No hay actualización de la misma rama. ':'')+(data?.notice||'');
  message(data?.installed_version?'Versión instalada: '+data.installed_version:'Elegí una versión para verificar su instalación.');buttons(false);
 }
 function renderPlan(data){
  plan=data;$('catalogVersionArea').hidden=true;$('catalogReview').hidden=false;$('catalogVersionsRefresh').hidden=true;$('catalogVersionContinue').hidden=true;$('catalogConfirm').hidden=false;$('catalogEraseLabel').hidden=action!=='uninstall';$('catalogErase').checked=false;
  const details=$('catalogPlanDetails');details.replaceChildren();
  for(const [label,value] of [['Sistema',data.distribution],['Versión',data.version||data.installed_version],['Acción',action==='uninstall'?'Eliminar servicio y sus datos':action==='upgrade'?'Actualizar conservando datos':({start:'Iniciar',stop:'Detener',restart:'Reiniciar'}[action]||'Instalar')],['Paquetes',data.packages?.join(', ')||data.package],['Aviso',data.warning],['Configuración',data.note]])if(value)details.append(element('dt',label),element('dd',value));
  message(action==='uninstall'?'Revisá el borrado permanente antes de confirmar.':['start','stop','restart'].includes(action)?'Revisá el cambio de estado antes de confirmar.':'Dependencias comprobadas. Revisá y confirmá la instalación.',action==='uninstall');buttons(false);
 }
 async function poll(){
  if(!dialog.open)return;
  try{
   const data=await json('/api/catalog-services/versions?service='+service),job=data.job;
   if(job?.id!==jobId){message('La operación cambió. Volvé a abrir el servicio.',true);return;}
   if(job.status==='running'){message(job.message);pollTimer=setTimeout(()=>void poll(),2000);return;}
   if(job.status==='error'){message(job.message,true);buttons(false);return;}
   if(request==='versions')renderCatalog(data.catalog);
   else if(request==='plan')renderPlan(job.plan);
   else {message(job.message);$('catalogConfirm').hidden=true;$('catalogVersionContinue').hidden=true;$('catalogVersionsRefresh').hidden=true;$('catalogReview').hidden=true;last=0;void load();window.dispatchEvent(new Event('storypulse-services-changed'));}
  }catch(error){message(error.message,true);buttons(false);}
 }
 async function start(operation,payload){
  clearTimeout(pollTimer);request=operation;buttons(true);message(operation==='versions'?'Actualizando repositorios y buscando versiones…':'Esperando la respuesta del servidor…');
  try{const data=await json('/api/catalog-services/'+(operation==='versions'?'versions':operation==='plan'?'plan':'apply'),{method:'POST',headers:{'Content-Type':'application/json','X-StoryPulse-Token':state.actionToken},body:JSON.stringify(payload)});jobId=data.job.id;pollTimer=setTimeout(()=>void poll(),700);}
  catch(error){message(error.message,true);buttons(false);}
 }
 function open(kind,mode){
  if(dialog.open)return;service=kind;action=mode;$('catalogConfirm').className=mode==='uninstall'?'danger-button':'primary-button';catalog=null;plan=null;jobId='';$('catalogTitle').textContent=(mode==='uninstall'?'Eliminar ':mode==='upgrade'?'Actualizar ':({start:'Iniciar ',stop:'Detener ',restart:'Reiniciar '}[mode]||'Instalar '))+names[kind];
  $('catalogVersionArea').hidden=mode==='uninstall';$('catalogReview').hidden=true;$('catalogVersionsRefresh').hidden=mode==='uninstall';$('catalogVersionContinue').hidden=mode==='uninstall';$('catalogConfirm').hidden=true;$('catalogVersionSelect').replaceChildren();$('catalogVersionNotice').textContent='';message('');buttons(true);dialog.showModal();
  if(['start','stop','restart'].includes(mode)){$('catalogVersionArea').hidden=true;$('catalogVersionsRefresh').hidden=true;$('catalogVersionContinue').hidden=true;void start('plan',{service,action});}
  else if(mode==='uninstall')void start('plan',{service,action,erase_data:true});else void start('versions',{service});
 }
 document.addEventListener('click',event=>{const button=event.target.closest('[data-catalog-action]');if(button&&!button.disabled)open(button.dataset.catalogService,button.dataset.catalogAction);});
 $('catalogManageRefresh').addEventListener('click',()=>void load(true));
 $('catalogRefresh').addEventListener('click',()=>void load(true));$('catalogClose').addEventListener('click',()=>dialog.close());dialog.addEventListener('close',()=>clearTimeout(pollTimer));
 $('catalogVersionsRefresh').addEventListener('click',()=>void start('versions',{service}));$('catalogVersionSelect').addEventListener('change',()=>buttons(false));$('catalogErase').addEventListener('change',()=>buttons(false));
 $('catalogVersionContinue').addEventListener('click',()=>{if(!$('catalogVersionContinue').disabled)void start('plan',{service,action,selection:$('catalogVersionSelect').value});});
 $('catalogConfirm').addEventListener('click',()=>{if(!plan||$('catalogConfirm').disabled)return;void start('apply',{service,action,...(action==='uninstall'?{erase_data:true}:['start','stop','restart'].includes(action)?{}:{selection:plan.selection}),revision:plan.revision,confirm:true});});
 renderCards();window.CatalogServices=Object.freeze({load});
 setInterval(()=>{if(document.visibilityState==='visible'&&document.querySelector('#view-services-install.active,#view-services-remove.active,#view-services-manage.active')&&Date.now()-last>30000)void load();},3000);
})();
