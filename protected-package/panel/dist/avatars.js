// Server Security Monitor v3.0
// Created by FacuSecX
// https://github.com/FacuSecX/
(()=>{'use strict';
 const avatars=[['astronaut','Astronauta'],['robot','Robot'],['ninja','Ninja'],['fox','Zorro'],['cat','Gato'],['owl','Búho'],['bear','Oso'],['panda','Panda'],['explorer','Explorador'],['pilot','Piloto']];
 const byId=id=>document.getElementById(id),button=byId('panelAvatarButton'),dialog=byId('avatarDialog');if(!button||!dialog)return;
 let saved=null,selected=null,busy=false,ready=false;
 function picture(id){const svg=document.createElementNS('http://www.w3.org/2000/svg','svg'),use=document.createElementNS(svg.namespaceURI,'use');svg.setAttribute('viewBox','0 0 64 64');svg.setAttribute('aria-hidden','true');use.setAttribute('href','/avatars.svg#'+id);svg.append(use);return svg;}
 function render(){for(const option of byId('avatarOptions').children)option.setAttribute('aria-checked',String(option.dataset.avatar===selected));byId('avatarSave').disabled=busy||!selected;}
 function apply(id){if(avatars.some(([value])=>value===id))button.replaceChildren(picture(id));}
 async function api(value){const response=await fetch('/api/profile/avatar',{method:value===undefined?'GET':'POST',cache:'no-store',headers:{'Content-Type':'application/json'},...(value===undefined?{}:{body:JSON.stringify({avatar:value})})});const data=await response.json();if(!response.ok)throw new Error(data.error||'No se pudo guardar el avatar.');return data;}
 async function init(){
  if(!await window.PanelAccess?.ready)return;
  for(const [id,label] of avatars){const option=document.createElement('button'),name=document.createElement('span');option.type='button';option.className='avatar-option';option.dataset.avatar=id;option.setAttribute('role','radio');option.setAttribute('aria-label',label);option.title=label;name.textContent=label;option.append(picture(id),name);option.addEventListener('click',()=>{if(!busy){selected=id;render();}});byId('avatarOptions').append(option);}
  try{const data=await api();saved=data.avatar;apply(saved);}catch{}ready=true;button.disabled=false;
 }
 button.addEventListener('click',()=>{if(!ready)return;selected=saved;byId('avatarMessage').textContent='';render();dialog.showModal();});
 byId('avatarCancel').addEventListener('click',()=>{if(!busy)dialog.close();});dialog.addEventListener('cancel',event=>{if(busy)event.preventDefault();});
 byId('avatarOptions').addEventListener('keydown',event=>{const options=[...byId('avatarOptions').children],index=options.indexOf(document.activeElement);if(index<0||!['ArrowRight','ArrowLeft','ArrowUp','ArrowDown','Home','End'].includes(event.key))return;event.preventDefault();const step={ArrowRight:1,ArrowLeft:-1,ArrowUp:-5,ArrowDown:5}[event.key];const next=event.key==='Home'?0:event.key==='End'?9:(index+step+10)%10;options[next].focus();options[next].click();});
 byId('avatarSave').addEventListener('click',async()=>{if(busy||!selected)return;busy=true;render();byId('avatarCancel').disabled=true;byId('avatarMessage').textContent='';try{const data=await api(selected);saved=data.avatar;apply(saved);dialog.close();button.focus();}catch(error){byId('avatarMessage').textContent=error.message;}finally{busy=false;byId('avatarCancel').disabled=false;render();}});
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',()=>void init(),{once:true});else void init();
})();
