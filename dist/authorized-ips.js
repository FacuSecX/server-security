/*
Server Security Monitor v2.0
Created by FacuSecX
https://github.com/FacuSecX/
*/
(() => {
  'use strict';
  const byId=id=>document.getElementById(id),dialog=byId('authorizedDialog');
  let data=null,pending=null,busy=false,loading=false;
  function node(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;}
  async function request(path,body){
    const response=await fetch(path,{method:body?'POST':'GET',cache:'no-store',signal:AbortSignal.timeout(100000),
      headers:body?{'Content-Type':'application/json','X-StoryPulse-Token':data?.action_token||''}:{},body:body?JSON.stringify(body):undefined});
    const value=await response.json();if(!response.ok)throw new Error(value.error||'No se pudo completar la operación.');return value;
  }
  function render(){
    byId('authorizedSource').textContent='Guardado en el servidor · '+data.source;
    byId('authorizedCount').textContent=data.authorized_ips.length+' '+(data.authorized_ips.length===1?'entrada autorizada':'entradas autorizadas');
    const body=byId('authorizedRows');body.replaceChildren();
    for(const ip of data.authorized_ips){const row=node('tr');row.append(node('td',ip,'notification-ip'),node('td',ip.includes(':')?'IPv6':'IPv4'));
      const cell=node('td'),remove=node('button','Quitar','secondary-button');remove.type='button';remove.disabled=busy;
      remove.addEventListener('click',()=>preview('remove',ip));cell.append(remove);row.append(cell);body.append(row);}
    if(!data.authorized_ips.length){const row=node('tr'),cell=node('td','No hay IP autorizadas. Los accesos autenticados remotos generarán alertas.');cell.colSpan=3;row.append(cell);body.append(row);}
  }
  async function load(){
    if(loading)return;loading=true;byId('authorizedRefresh').disabled=true;
    try{data=await request('/api/authorized-ips');render();byId('authorizedError').textContent='';}
    catch(error){byId('authorizedError').textContent=error.message;}
    finally{loading=false;byId('authorizedRefresh').disabled=false;}
  }
  async function preview(action,ip){
    if(busy)return;busy=true;byId('authorizedAdd').disabled=true;
    try{if(!data)await load();if(!data)return;
      pending=await request('/api/authorized-ips/plan',{action,ip:ip.trim()});
      byId('authorizedEffect').textContent=(action==='add'?'Autorizar ':'Quitar autorización de ')+pending.ip+'. '+pending.effect;
      byId('authorizedConfirm').checked=false;byId('authorizedApply').disabled=true;byId('authorizedDialogError').textContent='';dialog.showModal();}
    catch(error){byId('authorizedError').textContent=error.message;}
    finally{busy=false;byId('authorizedAdd').disabled=false;}
  }
  async function apply(){
    if(busy||!pending||!byId('authorizedConfirm').checked)return;busy=true;byId('authorizedApply').disabled=true;
    byId('authorizedCancel').disabled=true;
    try{await request('/api/authorized-ips/apply',{action:pending.action,ip:pending.ip,revision:pending.revision,confirm:true});
      byId('authorizedIp').value='';dialog.close();pending=null;await load();window.dispatchEvent(new Event('storypulse-authorizations'));}
    catch(error){byId('authorizedDialogError').textContent=error.message;}
    finally{busy=false;byId('authorizedApply').disabled=!byId('authorizedConfirm').checked;byId('authorizedCancel').disabled=false;if(data)render();}
  }
  byId('authorizedForm').addEventListener('submit',event=>{event.preventDefault();preview('add',byId('authorizedIp').value);});
  byId('authorizedRefresh').addEventListener('click',load);
  byId('authorizedConfirm').addEventListener('change',()=>byId('authorizedApply').disabled=busy||!byId('authorizedConfirm').checked);
  byId('authorizedApply').addEventListener('click',apply);
  byId('authorizedCancel').addEventListener('click',()=>{if(!busy)dialog.close();});
  dialog.addEventListener('cancel',event=>{if(busy)event.preventDefault();});
  window.addEventListener('storypulse-view',event=>{if(event.detail==='authorized-ips')load();});
  if(location.hash==='#authorized-ips')load();
})();
