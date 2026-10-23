// Server Security Monitor v3.0
// Created by FacuSecX
// https://github.com/FacuSecX/
(()=>{'use strict';
 const byId=id=>document.getElementById(id),dialog=byId('gamesDialog');
 let snapshot=null,loading=null,request=null,review=null,jobId='',operation='',pollTimer=null,dialogEpoch=0,consoleTimer=null,cursor='',consoleBusy=false,consoleAt=0,last=0,view='';
 let ftpId='',ftpVisible=false,ftpPending=false,ftpHideTimer=null,ftpAbort=null;
 function hideFtp(){clearTimeout(ftpHideTimer);ftpVisible=false;byId('gameFtpPassword').type='password';byId('gameFtpPassword').value='••••••••••••';byId('gameFtpReveal').setAttribute('aria-pressed','false');byId('gameFtpReveal').title=byId('gameFtpReveal').ariaLabel='Mostrar contraseña con Windows Hello';}
 const elem=(tag,text,className)=>{const node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(className)node.className=className;return node;};
 const may=action=>window.PanelAccess?.can(action==='install'?'games-install':action==='uninstall'?'games-remove':'games-manage')===true;
 const removalEdition=plan=>(plan?.edition||snapshot?.edition)==='zone'?'SA-MP GM Zone':'SA-MP clásico';
 const cleanupValid=cleanup=>cleanup&&Array.isArray(cleanup.remove)&&cleanup.remove.length>0&&Array.isArray(cleanup.preserve)&&[...cleanup.remove,...cleanup.preserve].every(item=>typeof item==='string'&&item.trim().length>0);
 function message(text,error=false){byId('gamesDialogStatus').textContent=text;byId('gamesDialogStatus').classList.toggle('auth-error',error);}
 function assets(id,kind,selected=[]){
  const available=new Map((snapshot?.[kind]||[]).map(item=>[item.name,item]));
  const names=[...selected,...[...available.keys()].filter(name=>!selected.includes(name))];
  byId(id).replaceChildren(...names.map(name=>{const item=available.get(name),label=elem('label',undefined,'games-check'),input=elem('input');input.type='checkbox';input.value=name;input.checked=selected.includes(name);input.disabled=!item?.available&&!input.checked;label.append(input,elem('span',name+(item?.available?'':' · '+(item?.reason||'Archivo no encontrado.'))));return label;}));
  if(!names.length)byId(id).append(elem('p','No hay '+(kind==='plugins'?'plugins .so':'filterscripts .amx')+' en esta carpeta.','games-note'));
 }
 const selection=id=>Array.from(byId(id).querySelectorAll('input:checked'),input=>input.value);
 async function json(url,options){const response=await fetch(url,{...options,signal:options?.signal||AbortSignal.timeout(15000)}),data=await response.json();if(data.action_token)state.actionToken=data.action_token;if(!response.ok)throw new Error(data.error||'No se pudo consultar el servidor.');return data;}
 function card(remove){
  const zone=remove&&snapshot?.edition==='zone';
  const node=elem('article',undefined,'panel catalog-card'),heading=elem('div',undefined,'catalog-card-heading'),logo=elem('img');logo.src='/game-logo-samp.png';logo.alt='SA-MP';logo.className='catalog-logo';heading.append(logo,elem('h3',remove?removalEdition():'San Andreas Multiplayer'));node.append(heading,elem('span',zone?'Juego + web + base de datos':'Juego · UDP','panel-tag'),elem('p',zone?'Instalación Zone con su GM, web, base de datos y acceso FTP. Revisá qué se eliminará antes de confirmar.':'SA-MP clásico con su gamemode inicial, arranque automático y consola en vivo.'));
  const incomplete=snapshot?.installed&&snapshot.phase!=='ready';
  const status=elem('p',incomplete?'Instalación incompleta · Requiere revisión':snapshot?.installed?'Instalado · '+snapshot.version+(snapshot.active?' · Encendido':' · Apagado'):snapshot?'No instalado':'Consultando…','catalog-state');status.classList.toggle('status-warning',!!snapshot&&(!snapshot.installed||incomplete));node.append(status);
  if(incomplete)node.append(elem('p','Podés eliminar esta instalación desde Eliminar juegos y volver a instalarla.','games-warning'));
  if(snapshot?.notice)node.append(elem('p',snapshot.notice,'games-warning'));
  const action=elem('div',undefined,'catalog-card-actions'),button=elem('button',remove?'Revisar eliminación':snapshot?.installed?'Juego instalado':'Instalar SA-MP',remove?'danger-button':'primary-button');button.type='button';button.dataset.gameAction=remove?'uninstall':'install';button.disabled=!snapshot||!may(remove?'uninstall':'install')||(remove?!snapshot.managed:snapshot.installed||snapshot.conflict||!snapshot.compatible);action.append(button);node.append(action);return node;
 }
 function render(updateConfig=false){
  for(const [id,remove] of [['gamesInstallCards',false],['gamesRemoveCards',true]]){const grid=byId(id),signature=JSON.stringify(snapshot);if(grid.dataset.signature!==signature){grid.replaceChildren(card(remove));grid.dataset.signature=signature;}}
  for(const id of ['gamesInstallStatus','gamesRemoveStatus']){byId(id).textContent=snapshot?('Distribución: '+snapshot.distribution+' · '+snapshot.architecture):'Consultando el servidor…';}
  const status=byId('gamesManageStatus'),ready=snapshot?.installed&&snapshot.phase==='ready';
  status.replaceChildren();if(ready){const dot=elem('span',undefined,'games-state-dot');dot.setAttribute('aria-hidden','true');status.append(dot);}status.append(document.createTextNode(snapshot?.installed?(snapshot.phase!=='ready'?'La instalación no pudo completarse. Revisá la consola o eliminá los archivos para reinstalar.':snapshot.active?'Estado: Encendido':'Estado: Apagado'):'SA-MP no está instalado.'));status.dataset.active=String(ready&&snapshot.active);
  byId('gamesManageStatus').classList.toggle('auth-error',!snapshot?.installed||snapshot?.phase!=='ready');
  byId('gameInstalledVersion').textContent=snapshot?.version?(snapshot.edition==='zone'?'SA-MP GM Zone · ':'SA-MP ')+snapshot.version:'Servidor de juego';
  byId('gameManagement').hidden=!snapshot?.installed;
  byId('gameResources').textContent=snapshot?.memory_bytes!=null?'RAM: '+(snapshot.memory_bytes/1048576).toFixed(1)+' MB':'';
  const power=byId('gamePower');power.dataset.gameAction=snapshot?.active?'stop':'start';power.dataset.active=String(!!snapshot?.active);power.title=power.ariaLabel=snapshot?.active?'Apagar servidor':'Encender servidor';power.setAttribute('aria-pressed',String(!!snapshot?.active));
  const players=snapshot?.players;byId('gamePlayers').textContent=(players?.available?players.connected:'—')+' / '+(players?.maximum??snapshot?.settings?.maxplayers??'—');byId('gamePlayersNotice').textContent=snapshot?.active?(players?.reason||'Estado y jugadores se actualizan cada 10 segundos.'):'';byId('gamePlayersNotice').hidden=!snapshot?.active;
  for(const button of document.querySelectorAll('#gameManagement [data-game-action]'))button.disabled=!may(button.dataset.gameAction)||(button.dataset.gameAction!=='stop'&&snapshot?.phase!=='ready')||(button.dataset.gameAction==='start'?snapshot?.active:!snapshot?.active);
  const settings=snapshot?.settings;
  if(settings&&(updateConfig||!byId('gameConfigForm').dataset.loaded)){
   byId('gameHostname').value=settings.hostname;byId('gamePort').value=settings.port;byId('gameMaxplayers').value=settings.maxplayers;
   byId('gameGamemode').replaceChildren(...snapshot.gamemodes.map(name=>{const option=elem('option',name);option.value=name;return option;}));byId('gameGamemode').value=settings.gamemode;
   assets('gameFilterscripts','filterscripts',settings.filterscripts);assets('gamePlugins','plugins',settings.plugins);
   byId('gameQuery').checked=settings.query;byId('gameChatlogging').checked=settings.chatlogging;byId('gameConfigForm').dataset.loaded='true';
  }
  byId('gameConfigSave').disabled=snapshot?.phase!=='ready'||!may('configure');
  const ftp=snapshot?.ftp;byId('gameFtpCard').hidden=!snapshot?.installed;byId('gameFtpDetails').hidden=!ftp?.enabled;
  if(ftpId!==(ftp?.id||'')){ftpId=ftp?.id||'';hideFtp();}
  byId('gameFtpNotice').textContent=ftp?.enabled?'FTP con TLS explícito · Puertos 21 y 50000–50019. Acceso limitado a la carpeta del juego. La contraseña vuelve a ocultarse a los 30 segundos.':'No se configuró una cuenta FTP para este juego. La opción está disponible al instalar SA-MP.';
  if(ftp?.enabled){byId('gameFtpHost').value=ftp.host;byId('gameFtpUsername').value=ftp.username;byId('gameFtpPort').value=ftp.port;byId('gameFtpDirectory').value=ftp.directory;}
  byId('gameFtpReveal').disabled=ftpPending||!ftp?.enabled||!window.PanelAccess?.can('panel-users');
 }
 function load(force=false,updateConfig=false){
  if(loading)return loading;if(!force&&Date.now()-last<3000)return Promise.resolve();
  loading=(async()=>{try{const data=await json('/api/games');if(data.game){snapshot=data;last=Date.now();render(updateConfig);}if(data.job?.status==='running')for(const id of ['gamesInstallStatus','gamesRemoveStatus','gamesManageStatus'])byId(id).textContent=data.job.message;}catch(error){for(const id of ['gamesInstallStatus','gamesRemoveStatus','gamesManageStatus']){byId(id).textContent=error.message;byId(id).classList.add('auth-error');}}finally{loading=null;}})();return loading;
 }
 function setBusy(busy){byId('gamesReview').disabled=busy;byId('gamesRestartAck').disabled=busy;byId('gamesErase').disabled=busy;byId('gamesConfirm').disabled=busy||!review||(request?.action==='uninstall'&&(!byId('gamesErase').checked||!cleanupValid(review.cleanup)))||(request?.action==='configure'&&!byId('gamesRestartAck').checked);}
 function showReview(plan){
  review=plan;byId('gameInstallForm').hidden=true;byId('gamesReview').hidden=true;byId('gamesConfirm').hidden=false;byId('gamesPlanDetails').hidden=false;byId('gamesEraseLabel').hidden=request.action!=='uninstall';
  byId('gamesRestartLabel').hidden=request.action!=='configure';byId('gamesConfirm').textContent=request.action==='configure'?'Confirmar cambios y reinicio':'Confirmar';
  const details=byId('gamesPlanDetails');details.replaceChildren();
  for(const [label,value] of [['Sistema',plan.distribution],['Juego',request.action==='uninstall'?removalEdition(plan)+(plan.version?' · '+plan.version:''):'SA-MP '+plan.version],['Carpeta',plan.directory],['Puerto',plan.settings?.port+'/UDP'],['Nombre',plan.settings?.hostname],['Gamemode',plan.settings?.gamemode],['Filterscripts',plan.settings?.filterscripts?.join(', ')],['Plugins',plan.settings?.plugins?.join(', ')],['Usuario FTP',request.ftp?.enabled?request.ftp.username:null],['Puertos FTP',request.ftp?.enabled?'21/TCP · 50000–50019/TCP · TLS obligatorio':null],['Dependencias',request.action==='install'?plan.packages?.join(', '):null],['Aviso',plan.warning]])if(value)details.append(elem('dt',label),elem('dd',value));
  if(request.action==='uninstall'){
   const cleanup=plan.cleanup,valid=cleanupValid(cleanup);
   if(valid){
    for(const [label,items] of [['Se eliminará permanentemente',cleanup.remove],['Se conservará',cleanup.preserve]]){const value=elem('dd'),list=elem('ul');for(const item of items)list.append(elem('li',item));if(!items.length)list.append(elem('li','No se informó ningún elemento adicional.'));value.append(list);details.append(elem('dt',label),value);}
    const zone=(plan.edition||snapshot?.edition)==='zone',database=cleanup.remove.some(item=>/\bbase(?:s)?\b/i.test(item));
    byId('gamesEraseText').textContent='Confirmo la eliminación permanente de todos los datos indicados en «Se eliminará»'+(zone&&database?', incluidas la base de datos de Zone y las cuentas de jugadores':'')+'. Se conservarán los servicios y elementos indicados en «Se conservará».';
   }
   message(valid?'Revisá todo lo que se eliminará. Esta operación es permanente.':'El controlador no informó un alcance de eliminación completo. Actualizá el estado y volvé a revisar.',true);
  }else message('Revisá los detalles antes de confirmar.');setBusy(false);
 }
 async function poll(epoch=dialogEpoch){
  if(!dialog.open||epoch!==dialogEpoch)return;
  try{const data=await json('/api/games');if(!dialog.open||epoch!==dialogEpoch)return;const job=data.job;if(job?.id!==jobId)throw new Error('La operación cambió. Cerrá y volvé a revisar.');
   if(job.status==='running'){message(job.message);pollTimer=setTimeout(()=>void poll(epoch),1500);return;}
   if(job.status==='error'){message(job.message,true);setBusy(false);return;}
   if(operation==='plan')showReview(job.plan);
   else{message(job.message);review=null;byId('gamesConfirm').hidden=true;byId('gamesPlanDetails').hidden=true;byId('gamesEraseLabel').hidden=true;byId('gamesRestartWarning').hidden=true;byId('gamesRestartLabel').hidden=true;cursor='';last=0;const updateConfig=['install','configure'].includes(request.action);setTimeout(()=>void load(true,updateConfig),3200);}
  }catch(error){if(dialog.open&&epoch===dialogEpoch){message(error.message,true);setBusy(false);}}
 }
 async function start(kind,payload){
  const epoch=dialogEpoch;
  operation=kind;clearTimeout(pollTimer);setBusy(true);message('Esperando la respuesta del servidor…');
  try{const data=await json('/api/games/'+kind,{method:'POST',headers:{'Content-Type':'application/json','X-StoryPulse-Token':state.actionToken},body:JSON.stringify(payload)});if(!dialog.open||epoch!==dialogEpoch)return;jobId=data.job.id;pollTimer=setTimeout(()=>void poll(epoch),700);}catch(error){if(dialog.open&&epoch===dialogEpoch){message(error.message,true);setBusy(false);}}
 }
 function open(action,settings){
  if(dialog.open||!may(action))return;dialogEpoch++;request={game:'samp',action,...(settings?{settings}:{}),...(action==='uninstall'?{erase_data:true}:{})};review=null;jobId='';
  byId('gamesRestartWarning').hidden=action!=='configure';byId('gamesRestartLabel').hidden=true;byId('gamesRestartAck').checked=false;byId('gamesConfirm').textContent='Confirmar';
  byId('gamesDialogTitle').textContent=({install:'Instalar',uninstall:'Eliminar',configure:'Configurar',start:'Encender',stop:'Apagar',restart:'Reiniciar'})[action]+' '+(action==='uninstall'?removalEdition():'SA-MP');
  byId('gameInstallForm').hidden=action!=='install';byId('gamesReview').hidden=action!=='install';byId('gamesConfirm').hidden=true;byId('gamesPlanDetails').hidden=true;byId('gamesEraseLabel').hidden=true;byId('gamesErase').checked=false;byId('gamesConfirm').className=action==='uninstall'?'danger-button':'primary-button';message('');setBusy(false);dialog.showModal();
  if(action!=='install')void start('plan',request);
 }
 async function consoleRead(){
  clearTimeout(consoleTimer);if(view!=='games-manage'||document.visibilityState!=='visible'||!snapshot?.installed||!may('console'))return;
  if(consoleBusy||Date.now()-consoleAt<3200){consoleTimer=setTimeout(()=>void consoleRead(),3200);return;}consoleBusy=true;consoleAt=Date.now();
  try{const data=await json('/api/games/console?cursor='+encodeURIComponent(cursor));if(view!=='games-manage')return;const node=byId('gameConsole'),bottom=node.scrollHeight-node.scrollTop-node.clientHeight<40;
   if(data.reset)node.textContent='';if(data.text)node.textContent=(node.textContent+data.text).slice(-150000);cursor=data.cursor;
   if(bottom||data.reset)node.scrollTop=node.scrollHeight;byId('gameConsoleStatus').textContent=data.waiting?'La consola se actualizará al terminar la operación.':'En vivo · cada 3 segundos. Se muestra lo que registra el servidor o su gamemode.';byId('gameConsoleStatus').classList.remove('auth-error');
  }catch(error){byId('gameConsoleStatus').textContent=error.message;byId('gameConsoleStatus').classList.add('auth-error');}finally{consoleBusy=false;if(view==='games-manage'&&document.visibilityState==='visible')consoleTimer=setTimeout(()=>void consoleRead(),3200);}
 }
 document.addEventListener('click',event=>{const button=event.target.closest('[data-game-action]');if(button&&!button.disabled)open(button.dataset.gameAction);});
 for(const id of ['gamesRefresh','gamesRemoveRefresh','gamesManageRefresh'])byId(id).addEventListener('click',()=>void load(true,true));
 function cancelDialog(){dialogEpoch++;clearTimeout(pollTimer);}
 byId('gamesClose').addEventListener('click',()=>{cancelDialog();dialog.close();});dialog.addEventListener('cancel',cancelDialog);dialog.addEventListener('close',()=>{if(!dialog.open)cancelDialog();});
 byId('gamesReview').addEventListener('click',()=>{if(!byId('gameInstallForm').reportValidity())return;request.settings={hostname:byId('gameInstallHostname').value,port:Number(byId('gameInstallPort').value),maxplayers:Number(byId('gameInstallPlayers').value),gamemode:'grandlarc',query:true,chatlogging:true,filterscripts:[],plugins:[]};request.ftp={enabled:byId('gameInstallFtp').checked,username:byId('gameInstallFtp').checked?byId('gameInstallFtpUsername').value:''};void start('plan',request);});
 byId('gameInstallFtp').addEventListener('change',()=>{byId('gameInstallFtpUsername').disabled=!byId('gameInstallFtp').checked;byId('gameInstallFtpUsername').required=byId('gameInstallFtp').checked;});
 byId('gameFtpReveal').addEventListener('click',async()=>{
  if(ftpVisible){hideFtp();return;}if(ftpPending||!snapshot?.ftp?.enabled||!window.PanelAccess?.can('panel-users'))return;
  ftpPending=true;const id=ftpId;ftpAbort=new AbortController();const deadline=setTimeout(()=>ftpAbort?.abort(),110000);byId('gameFtpReveal').disabled=true;byId('gameFtpMessage').textContent='Confirmá tu identidad en Windows Hello…';
  try{
   const data=await json('/api/games/ftp/reveal',{method:'POST',headers:{'Content-Type':'application/json','X-StoryPulse-Token':state.actionToken},body:'{}',signal:ftpAbort.signal});
   if(view!=='games-manage'||document.visibilityState!=='visible'||!document.hasFocus()||id!==ftpId){byId('gameFtpMessage').textContent='Contraseña oculta. Volvé a verificar para mostrarla.';return;}
   byId('gameFtpPassword').value=data.password;byId('gameFtpPassword').type='text';ftpVisible=true;byId('gameFtpReveal').setAttribute('aria-pressed','true');byId('gameFtpReveal').title=byId('gameFtpReveal').ariaLabel='Ocultar contraseña';byId('gameFtpMessage').textContent='Contraseña visible durante 30 segundos.';
   ftpHideTimer=setTimeout(()=>{hideFtp();byId('gameFtpMessage').textContent='Contraseña oculta.';},Math.min(data.hide_after_ms||30000,30000));
  }catch(error){hideFtp();byId('gameFtpMessage').textContent=error.name==='AbortError'?'Verificación cancelada.':error.message;}
  finally{clearTimeout(deadline);ftpPending=false;ftpAbort=null;byId('gameFtpReveal').disabled=!snapshot?.ftp?.enabled||!window.PanelAccess?.can('panel-users');}
 });
 byId('gameInstallForm').addEventListener('submit',event=>{event.preventDefault();byId('gamesReview').click();});
 byId('gamesErase').addEventListener('change',()=>setBusy(false));byId('gamesRestartAck').addEventListener('change',()=>setBusy(false));byId('gamesConfirm').addEventListener('click',()=>{if(review&&!byId('gamesConfirm').disabled)void start('apply',{...request,revision:review.revision,confirm:true,...(request.action==='configure'?{restart_confirmed:true}:{})});});
 byId('gameConfigForm').addEventListener('submit',event=>{event.preventDefault();if(!byId('gameConfigForm').reportValidity())return;open('configure',{hostname:byId('gameHostname').value,port:Number(byId('gamePort').value),maxplayers:Number(byId('gameMaxplayers').value),gamemode:byId('gameGamemode').value,query:byId('gameQuery').checked,chatlogging:byId('gameChatlogging').checked,filterscripts:selection('gameFilterscripts'),plugins:selection('gamePlugins')});});
 byId('gameConsoleClear').addEventListener('click',()=>{byId('gameConsole').textContent='';});
 window.addEventListener('storypulse-view',event=>{view=event.detail;if(view!=='games-manage'){hideFtp();ftpAbort?.abort();}clearTimeout(consoleTimer);if(view.startsWith('games-'))void load().then(()=>{if(view==='games-manage')void consoleRead();});});
 document.addEventListener('visibilitychange',()=>{clearTimeout(consoleTimer);if(document.visibilityState!=='visible'){hideFtp();ftpAbort?.abort();}if(document.visibilityState==='visible'&&view==='games-manage')void consoleRead();});
 window.addEventListener('blur',hideFtp);window.addEventListener('pagehide',()=>{hideFtp();ftpAbort?.abort();});
 setInterval(()=>{if(document.visibilityState==='visible'&&view==='games-manage'&&!dialog.open)void load(true);},10000);
 render();view=state.view;if(view.startsWith('games-'))void load().then(()=>{if(view==='games-manage')void consoleRead();});
})();
