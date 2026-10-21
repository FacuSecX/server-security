(() => {
 'use strict';
 const root=document.getElementById('view-panel-users');if(!root)return;
 const $=id=>document.getElementById(id),form=$('panelUsersForm'),controls=$('panelUsersControls'),
  message=$('panelUsersMessage'),status=$('panelUsersHelloStatus'),unlock=$('panelUsersUnlock'),lock=$('panelUsersLock');
 let active=false,grant='',expires=0,version=0,verifying=false,loading=null,busy=false,until=0,users=[],menus=[];
 const canAdmin=()=>window.PanelAccess?.can('panel-users')===true;
 const ready=()=>!!grant&&Date.now()<expires;
 async function api(path,body){
  const response=await fetch('/api/auth/users'+path,{method:body===undefined?'GET':'POST',cache:'no-store',
   headers:{'Content-Type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});
  const data=await response.json();if(!response.ok)throw Object.assign(new Error(data.error||'No se pudo completar la acción.'),{status:response.status});return data;
 }
 function render(){
  const authorized=active&&ready();controls.disabled=!authorized||busy||Date.now()<until;
  unlock.hidden=authorized;lock.hidden=!authorized;unlock.disabled=verifying||!!loading;
  if(!authorized){status.className='auth-error';if(!verifying)status.textContent='Gestión de usuarios bloqueada. Verificá tu identidad con Windows Hello.';}
  const seconds=Math.max(0,Math.ceil((until-Date.now())/1000));
  $('panelUsersSave').textContent=seconds?'Esperá '+seconds+' s':'Guardar cambio';
 }
 function resetGrant(){
  grant='';expires=0;version++;form.elements.password.value='';render();
 }
 async function close(){resetGrant();try{await api('/hello/lock',{});}catch{}}
 function selected(){return users.find(u=>u.username===form.elements.target.value);}
 function drawPermissions(rights){
  const box=$('panelPermissionOptions');box.replaceChildren();
  const groups=new Map();
  for(const menu of menus){
   if(!groups.has(menu.group)){const field=document.createElement('fieldset'),legend=document.createElement('legend');legend.textContent=menu.group;field.append(legend);box.append(field);groups.set(menu.group,field);}
   const label=document.createElement('label'),input=document.createElement('input');input.type='checkbox';input.name='menu';input.value=menu.id;input.checked=rights.includes(menu.id);
   const text=document.createElement('span');text.textContent=menu.label;label.append(input,text);groups.get(menu.group).append(label);
  }
 }
 function actionMode(){
  const action=form.elements.action.value,isNew=action==='create';
  $('panelNewUsername').hidden=!isNew;$('panelExistingUser').hidden=isNew;
  form.elements.username.required=isNew;form.elements.username.disabled=!isNew;
  form.elements.target.required=!isNew;form.elements.target.disabled=isNew;
  const needsPassword=['create','reset'].includes(action);
  $('panelTemporaryPassword').hidden=!needsPassword;form.elements.password.required=needsPassword;form.elements.password.disabled=!needsPassword;form.elements.password.value='';
  $('panelMenuPermissions').hidden=!['create','permissions'].includes(action);
  drawPermissions(isNew?[]:(selected()?.permissions||[]));render();
 }
 function renderUsers(){
  const old=form.elements.target.value,rows=$('panelUsersRows');rows.replaceChildren();form.elements.target.replaceChildren();
  for(const account of users){
   const tr=document.createElement('tr');
   for(const value of [account.username,account.administrator?'Administrador principal':'Usuario',account.must_change?'Debe cambiar su contraseña':'Activo',account.administrator?'Todos':String(account.permissions.length)+' menús']){
    const td=document.createElement('td');td.textContent=value;tr.append(td);
   }
   const td=document.createElement('td');
   if(!account.administrator){
    const option=document.createElement('option');option.value=account.username;option.textContent=account.username;form.elements.target.append(option);
    const button=document.createElement('button');button.type='button';button.className='secondary-button';button.textContent='Gestionar';button.dataset.panelUser=account.username;td.append(button);
   }else td.textContent='Protegido';
   tr.append(td);rows.append(tr);
  }
  if(users.some(u=>!u.administrator&&u.username===old))form.elements.target.value=old;
  actionMode();
 }
 async function enter(auto=false){
  if(!canAdmin()||!active)return false;if(loading){const current=version,available=await loading;if(auto&&available&&active&&version===current&&!ready())void verify();return available;}
  const current=version;loading=(async()=>{
   try{
    const [data,hello]=await Promise.all([api(''),api('/hello')]);
    if(!active||version!==current)return false;
    users=data.users;menus=data.menus;renderUsers();
    if(!hello.available){status.textContent='Windows Hello no está disponible. Configuralo en Windows para gestionar usuarios.';return false;}
    return true;
   }catch(e){message.dataset.tone='error';message.textContent=e.message;return false;}
   finally{loading=null;render();}
  })();
  const available=await loading;
  if(auto&&available&&active&&version===current&&!ready())void verify();
  return available;
 }
 async function verify(){
  if(verifying||!active||!canAdmin()||ready())return;
  verifying=true;const current=version;render();status.textContent='Confirmá tu identidad en Windows Hello…';
  try{
   const data=await api('/hello/unlock',{});
   if(!active||version!==current){await api('/hello/lock',{});return;}
   grant=data.grant;expires=data.expires_at;status.className='';status.textContent='Gestión de usuarios autorizada · Windows Hello · máximo cinco minutos.';
  }catch(e){message.dataset.tone='error';message.textContent=e.message;}
  finally{verifying=false;render();}
 }
 unlock.addEventListener('click',()=>void verify());lock.addEventListener('click',()=>void close());
 form.elements.action.addEventListener('change',actionMode);form.elements.target.addEventListener('change',actionMode);
 $('panelUsersRows').addEventListener('click',event=>{
  const button=event.target.closest('[data-panel-user]');if(!button)return;
  form.elements.action.value='permissions';form.elements.target.value=button.dataset.panelUser;actionMode();form.scrollIntoView({block:'nearest',behavior:'smooth'});
 });
 for(const [id,value] of [['panelPermissionsAll',true],['panelPermissionsNone',false]])$(id).addEventListener('click',()=>{for(const item of form.querySelectorAll('[name=menu]'))item.checked=value;});
 form.addEventListener('submit',async event=>{
  event.preventDefault();if(!ready()||busy||Date.now()<until||!active)return;
  const action=form.elements.action.value,username=action==='create'?form.elements.username.value:form.elements.target.value;
  if(action==='delete'&&!confirm('¿Eliminar el usuario '+username+' y cerrar sus sesiones?'))return;
  const body={action,username,hello_grant:grant};
  if(['create','reset'].includes(action))body.password=form.elements.password.value;
  if(['create','permissions'].includes(action))body.permissions=[...form.querySelectorAll('[name=menu]:checked')].map(input=>input.value);
  busy=true;message.dataset.tone='error';message.textContent='';const current=version;render();
  try{
   const data=await api('',body);
   if(current!==version||!active)return;
   users=data.users;renderUsers();message.dataset.tone='success';message.textContent='Cambio guardado. Los permisos se aplican al volver a ingresar; las sesiones anteriores de ese usuario se cierran.';
  }catch(e){if(current===version){message.dataset.tone='error';message.textContent=e.message;if(e.status===403)resetGrant();}}
  finally{form.elements.password.value='';busy=false;until=Date.now()+3000;render();}
 });
 addEventListener('storypulse-view',event=>{
  const next=event.detail==='panel-users';if(active&&!next)void close();active=next;if(next)void enter(false);render();
 });
 document.querySelector('[data-view="panel-users"]')?.addEventListener('click',()=>setTimeout(()=>{if(active&&!verifying)void enter(true);},0));
 document.addEventListener('visibilitychange',()=>{if(document.hidden&&active)void close();});
 setInterval(()=>{if(active&&grant&&Date.now()>=expires)void close();render();},1000);
 window.PanelAccess?.ready.then(()=>{active=document.getElementById('view-panel-users').classList.contains('active');if(active)void enter(false);render();});
 render();
})();