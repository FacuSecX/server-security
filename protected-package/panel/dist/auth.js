(() => {
  'use strict';
  const originalFetch=window.fetch.bind(window),isLogin=location.pathname==='/login'||location.pathname==='/login.html';
  let serverId='',tab='',csrf='',user=null,lastActivity=Date.now(),lastSentActivity=0,ready=false,leaving=false,pulsePending=false;
  try{tab=sessionStorage.getItem('ssm-tab')||'';if(!/^[a-f0-9]{32}$/.test(tab)){tab=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('');sessionStorage.setItem('ssm-tab',tab);}}catch{tab='';}
  if(!isLogin)document.documentElement.dataset.authPending='true';
  const goLogin=()=>{if(!leaving){leaving=true;location.replace('/login');}};
  async function request(path,data){const response=await originalFetch(path,{method:data===undefined?'GET':'POST',cache:'no-store',credentials:'same-origin',headers:{'Content-Type':'application/json','X-Panel-Tab':tab,'X-Panel-CSRF':csrf,'X-Panel-Server':serverId},...(data===undefined?{}:{body:JSON.stringify(data)})});const body=await response.json();if(!response.ok)throw Object.assign(new Error(body.error||'No se pudo completar la acción.'),{status:response.status,retry:body.retry_ms});return body;}
  const sessionReady=(async()=>{try{const session=await request('/api/auth/session');serverId=session.server_id||'';csrf=session.csrf;user=session.user;lastActivity=Date.now()-session.idle_elapsed_ms;lastSentActivity=lastActivity;return true;}catch{return false;}})();
  window.PanelAccess=Object.freeze({
    ready:sessionReady,
    can:view=>!!user&&!user.must_change&&((view==='no-access'||view==='forbidden')||user.administrator===true||(Array.isArray(user.permissions)&&user.permissions.includes(view))),
    reportDenied:view=>request('/api/auth/access-attempt',{view}).catch(()=>{}),
    first:()=>user?.administrator?'overview':user?.permissions?.[0]||'no-access'
  });
  if(!isLogin){
    window.fetch=async function(input,init={}){
      const url=new URL(typeof input==='string'||input instanceof URL?input:input.url,location.href);
      if(url.origin!==location.origin)return originalFetch(input,init);
      if(!await sessionReady){goLogin();throw new Error('Ingresá para continuar.');}
      if(user.must_change){location.replace('/login');throw new Error('Cambiá la contraseña temporal.');}
      if(Date.now()-lastActivity>=300000){void request('/api/auth/logout',{}).finally(goLogin);throw new Error('Sesión bloqueada por inactividad.');}
      const headers=new Headers(init.headers||input?.headers);headers.set('X-Panel-Tab',tab);headers.set('X-Panel-CSRF',csrf);headers.set('X-Panel-Server',serverId);
      const response=await originalFetch(input,{...init,headers});if(response.status===401)goLogin();if(response.status===409){const value=await response.clone().json().catch(()=>null);if(value?.server_changed)goLogin();}return response;
    };
  }
  function countdown(button,milliseconds=3000){let left=Math.max(3,Math.ceil(milliseconds/1000));button.disabled=true;const label=button.textContent;button.textContent='Esperá '+left+' s';const timer=setInterval(()=>{left--;button.textContent=left>0?'Esperá '+left+' s':label;if(left<=0){clearInterval(timer);button.disabled=false;}},1000);}
  async function pulse(){if(!ready||pulsePending)return;pulsePending=true;const activity=lastActivity,background=document.hidden,active=!background&&activity>lastSentActivity;try{await request('/api/auth/pulse',{active,background});if(active)lastSentActivity=activity;}catch(e){if(e.status===401)goLogin();}finally{pulsePending=false;if(ready&&!leaving&&document.hidden!==background)void pulse();}}
  async function logout(){try{await request('/api/auth/logout',{});}finally{goLogin();}}
  addEventListener('pagehide',()=>{if(csrf)navigator.sendBeacon('/api/auth/leave',new Blob([JSON.stringify({tab,csrf})],{type:'application/json'}));});
  addEventListener('pageshow',event=>{if(event.persisted)location.reload();});
  document.addEventListener('DOMContentLoaded',async()=>{
    if(isLogin){
      const login=document.getElementById('panelLogin'),change=document.getElementById('panelPassword'),message=document.getElementById('authMessage');
      const setup=document.getElementById('panelSetup'),recovery=document.getElementById('panelRecovery'),note=document.getElementById('authNote');let installation=null;
      async function installationForm(){
        try{installation=await request('/api/auth/installation');}
        catch(e){if(![401,404].includes(e.status))throw e;const health=await request('/api/health');if(!Number.isInteger(health.version)||health.version>=53)throw e;installation={mode:'ready'};}
        const mode=installation.mode;
        let connection=document.getElementById('loginServerIdentity');
        if(installation.server_label){if(!connection){connection=document.createElement('p');connection.id='loginServerIdentity';connection.className='auth-note';login.parentNode.insertBefore(connection,login);}connection.textContent='Servidor: '+installation.server_label;}
        login.hidden=mode!=='ready';setup.hidden=mode!=='setup';recovery.hidden=mode!=='recovery';
        note.textContent=mode==='installation-required'?'Para configurar el primer administrador, ejecutá Instalar protección local. Windows solicitará permisos administrativos y Windows Hello.':mode==='recovery'?'La recuperación exige la contraseña actual del administrador y Windows Hello del propietario original. Si falta el respaldo, restaurá una copia externa.':'La sesión se bloquea después de cinco minutos sin actividad.';
      }
      function enrollmentForm(form,mode){form.addEventListener('submit',async event=>{
        event.preventDefault();const button=form.querySelector('button');if(button.disabled)return;message.textContent='';
        if(mode==='setup'&&form.elements.password.value!==form.elements.confirm.value){message.textContent='Las contraseñas no coinciden.';return;}
        button.disabled=true;
        try{
          const body={challenge:installation?.challenge,password:form.elements.password.value};
          if(mode==='setup'){body.username=form.elements.username.value;body.confirm=form.elements.confirm.value;}
          await request(mode==='setup'?'/api/auth/setup':'/api/auth/recover',body);form.reset();await installationForm();message.textContent=mode==='setup'?'Cuenta creada. Ingresá con tu usuario y contraseña.':'Cuentas restauradas. Ingresá con tus datos habituales.';
        }catch(e){message.textContent=e.message;form.elements.password.value='';if(mode==='setup')form.elements.confirm.value='';try{await installationForm();}catch{message.textContent='No se pudo comprobar la instalación. Volvé a abrir el panel desde su acceso directo.';}}
        finally{countdown(button);}
      });}
      enrollmentForm(setup,'setup');enrollmentForm(recovery,'recovery');
      function passwordForm(){login.hidden=true;change.hidden=false;document.getElementById('passwordHeading').textContent=user?.must_change?'Elegí tu contraseña personal':'Cambiar contraseña';}
      if(await sessionReady){if(user.must_change||location.hash==='#password'){passwordForm();ready=true;}else{location.replace('/');return;}}
      else{login.hidden=true;try{await installationForm();}catch{message.textContent='No se pudo comprobar la instalación protegida. Abrí el panel desde su acceso directo.';}}
      if(!tab){message.textContent='Permití el almacenamiento de sesión del navegador para poder ingresar.';login.querySelector('button').disabled=true;return;}
      login.addEventListener('submit',async event=>{event.preventDefault();const button=login.querySelector('button');if(button.disabled)return;button.disabled=true;message.textContent='';try{const result=await request('/api/auth/login',{username:login.elements.username.value,password:login.elements.password.value,tab});login.elements.password.value='';serverId=result.server_id||'';csrf=result.csrf;user=result.user;lastActivity=Date.now();ready=true;if(user.must_change)passwordForm();else location.replace('/');}catch(e){message.textContent=e.message;login.elements.password.value='';if(e.retry)countdown(button,e.retry);}finally{if(button.textContent==='Ingresar')countdown(button);}});
      change.addEventListener('submit',async event=>{event.preventDefault();const button=change.querySelector('button');if(button.disabled)return;message.textContent='';if(change.elements.password.value!==change.elements.confirm.value){message.textContent='Las contraseñas nuevas no coinciden.';return;}button.disabled=true;try{await request('/api/auth/password',{current:change.elements.current.value,password:change.elements.password.value});change.reset();ready=false;csrf='';change.hidden=true;login.hidden=false;message.textContent='Contraseña guardada. Ingresá nuevamente.';}catch(e){message.textContent=e.message;if(e.status===401)void logout();}finally{countdown(button);}});
      document.getElementById('passwordCancel').addEventListener('click',logout);
    }else{
      if(!await sessionReady||user.must_change){goLogin();return;}
      document.documentElement.dataset.authPending='false';ready=true;
      for(const node of document.querySelectorAll('.nav-item[data-view]'))node.hidden=!window.PanelAccess.can(node.dataset.view);
      for(const node of document.querySelectorAll('.view'))node.hidden=!window.PanelAccess.can(node.id.slice(5));
      for(const group of document.querySelectorAll('.nav-group'))group.hidden=![...group.querySelectorAll('.nav-item')].some(node=>!node.hidden);
      for(const link of document.querySelectorAll('[data-view-link]'))link.hidden=!window.PanelAccess.can(link.dataset.viewLink);
      document.getElementById('panelCurrentUser').textContent=user.username;
      document.getElementById('panelLogout').addEventListener('click',logout);
      document.getElementById('panelOwnPassword').addEventListener('click',()=>location.assign('/login#password'));

    }
    for(const event of ['pointerdown','keydown','wheel','touchstart'])document.addEventListener(event,e=>{if(e.isTrusted&&!document.hidden){lastActivity=Date.now();if(ready&&lastActivity-lastSentActivity>15000)void pulse();}},{passive:true});
    document.addEventListener('visibilitychange',()=>{if(!document.hidden&&Date.now()-lastActivity>=300000){void logout();return;}void pulse();});
    setInterval(()=>{if(ready&&Date.now()-lastActivity>=300000)void logout();else void pulse();},10000);
  });
})();
