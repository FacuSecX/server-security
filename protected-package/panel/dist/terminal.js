(() => {
  'use strict';
  const root=document.getElementById('view-terminal');if(!root)return;
  const status=document.getElementById('terminalStatus'),unlock=document.getElementById('terminalUnlock'),
    lock=document.getElementById('terminalLock'),form=document.getElementById('terminalForm'),
    command=document.getElementById('terminalCommand'),send=document.getElementById('terminalSend'),
    output=document.getElementById('terminalOutput'),clear=document.getElementById('terminalClear');
  let active=false,grant='',expires=0,generation=0,pending=false,checking=false,verification=false,available=false,checkingRequest=null;
  const clean=value=>String(value||'').replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'').replace(/[\x00-\x08\x0b-\x1f\x7f]/g,'');
  function setStatus(message,tone='info') {status.textContent=message;status.dataset.tone=tone;}
  function append(text,kind='') {
    const line=document.createElement('div');line.className='terminal-line '+kind;line.textContent=clean(text);
    output.append(line);while(output.childNodes.length>60)output.firstChild.remove();
    while(output.textContent.length>200000&&output.childNodes.length>1)output.firstChild.remove();
    output.scrollTop=output.scrollHeight;
  }
  function render() {
    const ready=active&&!!grant&&Date.now()<expires;
    form.hidden=!ready;lock.hidden=!ready;unlock.hidden=ready;
    unlock.disabled=!available||verification||checking;send.disabled=!ready||pending;
    root.dataset.terminalUnlocked=ready?'true':'false';
  }
  async function api(path,body) {
    const response=await fetch('/api/terminal'+path,{method:body===undefined?'GET':'POST',cache:'no-store',
      headers:{'Content-Type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});
    const value=await response.json();
    if(!response.ok)throw Object.assign(new Error(value.error||'No se pudo completar la acción.'),{status:response.status});
    return value;
  }
  function check() {
    if(!active)return Promise.resolve(false);
    if(checkingRequest)return checkingRequest;
    checking=true;const current=generation;render();
    checkingRequest=(async()=>{
      try {
        const value=await api('');
        if(!active||current!==generation)return false;
        if(!value.unlocked&&grant){grant='';expires=0;}
        available=value.available===true;
        if(!value.available)setStatus('Windows Hello no está disponible. Configurá PIN o biometría en las opciones de inicio de sesión de Windows.','error');
        else if(!grant)setStatus('Acceso bloqueado. Verificá tu identidad con Windows Hello para abrir la terminal.','error');
        return available;
      }catch(error){
        if(active&&current===generation){available=false;setStatus(error.message,'error');if(error.status===403)document.querySelector('[data-view="overview"]').click();}
        return false;
      }finally{checking=false;checkingRequest=null;render();}
    })();
    return checkingRequest;
  }
  function forget(message) {
    grant='';expires=0;generation++;command.value='';output.replaceChildren();setStatus(message,'error');render();
  }
  async function close() {
    forget('Terminal bloqueada. Para volver a entrar necesitás Windows Hello.');
    try{await api('/lock',{});}catch{}
  }
  async function requestUnlock() {
    if(verification||checking||!active||!available||document.hidden||(grant&&Date.now()<expires))return;verification=true;const current=generation;render();
    setStatus('Confirmá tu identidad en la ventana de Windows Hello…');
    try {
      const value=await api('/unlock',{});
      if(!active||current!==generation){await api('/lock',{});return;}
      grant=value.grant;expires=value.expires_at;setStatus('Terminal autorizada · una orden por vez · 60 segundos por comando.');
      render();command.focus();
    }catch(error){if(active)setStatus(error.message,'error');}
    finally{verification=false;render();}
  }
  unlock.addEventListener('click',requestUnlock);
  document.querySelector('[data-view="terminal"]')?.addEventListener('click',()=>{
    if(verification||document.hidden)return;
    setTimeout(async()=>{
      const current=generation,ready=await check();
      if(ready&&active&&!document.hidden&&current===generation&&!grant&&!verification)void requestUnlock();
    },0);
  });
  lock.addEventListener('click',close);
  clear.addEventListener('click',()=>output.replaceChildren());
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(pending||!grant||!active)return;
    if(Date.now()>=expires){await close();return;}
    const text=command.value;if(!text.trim())return;
    if(new TextEncoder().encode(text).length>8192){setStatus('El comando supera el límite de 8192 bytes.','error');return;}
    const id=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('');
    const current=generation;pending=true;render();append('$ '+text,'terminal-prompt');command.value='';
    setStatus('Esperando la respuesta del servidor…');
    try {
      const value=await api('/execute',{id,command:text,grant});
      if(!active||current!==generation)return;
      if(value.stdout)append(value.stdout);
      if(value.stderr)append(value.stderr,'terminal-stderr');
      append('Código de salida: '+value.exit_code+' · '+(value.duration_ms/1000).toFixed(2)+' s','terminal-meta');
      setStatus(value.timed_out?'Se alcanzó el límite de 60 segundos; se intentó detener el grupo del comando.':
        value.truncated?'Se alcanzó el límite de salida; el resultado se muestra recortado.':'Respuesta recibida. Esperá tres segundos antes de enviar otro comando.',value.timed_out||value.truncated||value.exit_code!==0?'error':'info');
    }catch(error) {
      if(active&&current===generation){append(error.message,'terminal-stderr');setStatus(error.message,'error');if(error.status===403)forget(error.message);}
    }finally{pending=false;render();}
  });
  command.addEventListener('keydown',event=>{if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();form.requestSubmit();}});
  addEventListener('storypulse-view',event=>{
    const next=event.detail==='terminal';if(active&&!next)void close();active=next;
    if(next)void check();render();
  });
  document.addEventListener('visibilitychange',()=>{if(document.hidden&&active)void close();});
  setInterval(()=>{if(active&&grant&&Date.now()>=expires)void close();},1000);
  active=location.hash==='#terminal';render();if(active)void check();
})();