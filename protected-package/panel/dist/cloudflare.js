(()=>{
 'use strict';
 const dialog=document.createElement('dialog');dialog.className='confirm-dialog cloudflare-dialog';dialog.id='cloudflareDialog';dialog.setAttribute('aria-labelledby','cloudflareTitle');
 // Static markup only. All server messages and plan details use textContent.
 dialog.innerHTML=`<h2 id="cloudflareTitle">Protección Cloudflare · Nginx</h2>
 <div class="cf-status-grid"><div id="cfProtectionState" class="cf-protection-state cf-protection-pending" role="status" aria-live="polite"><span class="cf-protection-dot" aria-hidden="true"></span><div><strong>Bloqueo de acceso directo</strong><span>Estado: <b id="cfProtectionLabel">Verificando…</b></span></div></div>
 <div id="cfSslState" class="cf-protection-state cf-protection-pending" role="status" aria-live="polite"><span class="cf-protection-dot" aria-hidden="true"></span><div><strong>SSL / HTTPS</strong><span>Estado: <b id="cfSslLabel">Verificando…</b></span></div></div></div>
 <p id="cfCurrent" class="catalog-note"></p><p id="cfMessage" role="status" aria-live="polite"></p>
 <form id="cfForm" autocomplete="off"><label for="cfDomain">Dominio del sitio</label><input id="cfDomain" type="text" placeholder="ejemplo.com" maxlength="253" autocomplete="off" spellcheck="false">
 <label class="cf-check"><input id="cfBlock" type="checkbox"> Bloquear tráfico directo a Nginx</label><p class="catalog-note">Solo Cloudflare podrá acceder por los puertos 80 y 443, en IPv4 e IPv6. Se conserva el acceso SSH.</p>
 <label class="cf-check"><input id="cfSsl" type="checkbox"> Añadir SSL de Cloudflare y redirigir a HTTPS</label><p class="catalog-note">SSL habilita automáticamente los puertos 80 y 443. Si también bloqueás el tráfico directo, solo se permiten los rangos de Cloudflare.</p>
 <div id="cfCertificateFields" hidden><label for="cfCertificate">Origin Certificate · PEM</label><textarea id="cfCertificate" autocomplete="off" spellcheck="false" maxlength="65536" rows="5" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
 <label for="cfPrivateKey">Private Key · PEM</label><textarea id="cfPrivateKey" class="cf-private" autocomplete="off" spellcheck="false" maxlength="65536" rows="4" placeholder="Pegá la clave privada completa"></textarea>
 <p class="catalog-note" id="cfKeepCertificate"></p></div>
 <p class="cf-help">El dominio debe apuntar a este VPS con la nube naranja activada en Cloudflare. Para SSL, elegí <strong>Full (strict)</strong> en Cloudflare antes de confirmar. El panel comprobará que el dominio llegue a este Nginx; si falla, restaurará el estado anterior.</p>
 <label class="cf-check"><input id="cfRefresh" type="checkbox"> Actualizar ahora los rangos oficiales de Cloudflare</label>
 <p class="catalog-note">Los rangos también se revisan diariamente. Si falla su descarga, se conservan los últimos válidos.</p>
 <div id="cfReview" hidden><h3>Revisá el cambio</h3><dl id="cfDetails"></dl></div>
 <div class="confirm-actions"><button id="cfClose" type="button" class="secondary-button">Volver</button><button id="cfCheck" type="submit" class="secondary-button">Revisar cambios</button><button id="cfApply" type="button" class="primary-button" hidden>Confirmar y aplicar</button></div></form>`;
 document.body.append(dialog);
 const $=id=>document.getElementById(id);let plan=null,jobId='',poll=null,working=false,generation=0;
 const message=(value,error=false)=>{$('cfMessage').textContent=value;$('cfMessage').classList.toggle('auth-error',error);};
 function protectionState(data){for(const [id,label,active] of [['cfProtectionState','cfProtectionLabel',data?.protection_active===true],['cfSslState','cfSslLabel',data?.ssl_active===true]]){$(id).className='cf-protection-state '+(active?'cf-protection-on':'cf-protection-off');$(label).textContent=active?'Activado':'Desactivado';$(id).dataset.protection=active?'active':'inactive';}}
 function clear(){ $('cfCertificate').value='';$('cfPrivateKey').value='';plan=null;$('cfReview').hidden=true;$('cfApply').hidden=true; }
 function controls(busy){working=busy;for(const input of dialog.querySelectorAll('input,textarea'))input.disabled=busy;$('cfCheck').disabled=busy;$('cfApply').disabled=busy||!plan;}
 async function api(path,body){const response=await fetch(path,{method:body?'POST':'GET',headers:body?{'Content-Type':'application/json','X-StoryPulse-Token':state.actionToken}:{},...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(20000)});const result=await response.json();if(!response.ok)throw new Error(result.error||'No se pudo completar la operación.');return result;}
 function body(){return {domain:$('cfDomain').value.trim(),block_direct:$('cfBlock').checked,ssl:$('cfSsl').checked,certificate:$('cfSsl').checked?$('cfCertificate').value:'',private_key:$('cfSsl').checked?$('cfPrivateKey').value:'',refresh:$('cfRefresh').checked};}
 function showPlan(value){plan=value;$('cfDetails').replaceChildren();for(const [label,text] of [['Dominio',value.domain||'Sin protección'],['Acceso directo',value.block_direct?'Bloqueado · solo Cloudflare':'Permitido según las reglas previas'],['SSL y HTTPS',value.ssl?'Activado':'Desactivado'],['Sitio Nginx',value.site||'Restaurar configuración previa'],['Certificado válido hasta',value.certificate?.expires||'No se aplica']]){const term=document.createElement('dt'),desc=document.createElement('dd');term.textContent=label;desc.textContent=text;$('cfDetails').append(term,desc);}$('cfReview').hidden=false;$('cfApply').hidden=false;$('cfApply').disabled=false;}
 function schedule(token){clearTimeout(poll);poll=setTimeout(()=>checkJob(token),1500);}
 async function checkJob(token){
  if(token!==generation||!dialog.open)return;
  try{const data=await api('/api/cloudflare');if(token!==generation||!dialog.open)return;const job=data.job;if(job?.id!==jobId){controls(false);message('La operación cambió. Volvé a revisar.',true);return;}
   message(job.message,job.status==='error');if(job.status==='running'){schedule(token);return;}
   protectionState(data);
   controls(false);if(job.status==='success'&&job.plan)showPlan(job.plan);else{clear();if(job.status==='success'){window.CatalogServices?.load(true);document.dispatchEvent(new CustomEvent('storypulse-services-changed'));}}
  }catch(error){if(token!==generation)return;message(error.message,true);schedule(token);}
 }
 async function open(){generation++;const token=generation;clear();controls(true);for(const [id,label] of [['cfProtectionState','cfProtectionLabel'],['cfSslState','cfSslLabel']]){$(id).className='cf-protection-state cf-protection-pending';$(label).textContent='Verificando…';}message('Comprobando Nginx y la configuración de este servidor…');dialog.showModal();
  try{const data=await api('/api/cloudflare');if(token!==generation||!dialog.open)return;$('cfDomain').value=data.domain||'';$('cfBlock').checked=!!data.block_direct;$('cfSsl').checked=!!data.ssl;$('cfRefresh').checked=false;$('cfCertificateFields').hidden=!data.ssl;$('cfKeepCertificate').textContent=data.ssl?'Podés dejar ambos campos vacíos para conservar el certificado instalado.':'Pegá el certificado y la clave que te entrega Cloudflare.';
   protectionState(data);$('cfCurrent').textContent=(data.active?'Nginx activo':'Nginx detenido')+' · Acceso directo '+(data.protection_active?'bloqueado por el firewall':'sin bloqueo verificado')+' · SSL '+(data.ssl?'activo':'sin configurar')+(data.updated_at?' · Última comprobación: '+new Date(data.updated_at).toLocaleString():'');
   if(data.job?.status==='running'){jobId=data.job.id;message(data.job.message);schedule(token);}else{controls(false);message(data.error||'Elegí las opciones que querés aplicar.',!!data.error);if(!data.installed)$('cfCheck').disabled=true;}
  }catch(error){protectionState(null);controls(false);$('cfCheck').disabled=true;message(error.message,true);}
 }
 $('cfSsl').addEventListener('change',()=>{$('cfCertificateFields').hidden=!$('cfSsl').checked;if(!$('cfSsl').checked){$('cfCertificate').value='';$('cfPrivateKey').value='';}});
 $('cfForm').addEventListener('input',()=>{plan=null;$('cfReview').hidden=true;$('cfApply').hidden=true;});
 $('cfForm').addEventListener('submit',async event=>{event.preventDefault();if(working)return;controls(true);message('Comprobando el cambio…');try{const data=await api('/api/cloudflare/plan',body());jobId=data.job.id;schedule(generation);}catch(error){controls(false);message(error.message,true);}});
 $('cfApply').addEventListener('click',async()=>{if(working||!plan)return;controls(true);message('Aplicando el cambio…');try{const data=await api('/api/cloudflare/apply',{...body(),revision:plan.revision,confirm:true});jobId=data.job.id;clear();schedule(generation);}catch(error){controls(false);message(error.message,true);}});
 $('cfClose').addEventListener('click',()=>dialog.close());dialog.addEventListener('close',()=>{generation++;clearTimeout(poll);clear();controls(false);});
 document.addEventListener('click',event=>{if(event.target.closest('[data-cloudflare-open]'))open();});
 window.addEventListener('pagehide',()=>{clear();clearTimeout(poll);});
})();
