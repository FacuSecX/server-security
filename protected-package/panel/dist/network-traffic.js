/* Read-only network view. Polls share the dashboard's existing refresh cadence. */
(()=>{
 const node=id=>document.getElementById(id),filters=['outgoingDecision','outgoingProtocol','outgoingCountry','outgoingIsp','outgoingSourcePort','outgoingPort','outgoingQuery'];
 const keys=['decision','protocol','country','isp','source_port','port','q'];
 let request=null,serial=0,lastKey='',lastLoaded=0,timer=null;
 async function load(force=false){
  if(state.view!=='outgoing'||document.hidden||window.PanelAccess&&!window.PanelAccess.can('outgoing'))return;
  const params=new URLSearchParams({hours:String(state.hours)});
  filters.forEach((id,index)=>{const value=node(id).value.trim();if(value)params.set(keys[index],value);});
  const key=params.toString();if(!force&&(request||key===lastKey&&Date.now()-lastLoaded<2500))return;
  request?.abort();const controller=new AbortController();request=controller;const revision=++serial;
  try{
   const timeout=setTimeout(()=>controller.abort(),15000);let response;
   try{response=await fetch('/api/network/outgoing?'+key,{signal:controller.signal,cache:'no-store'});}finally{clearTimeout(timeout);}
   const data=await response.json();if(!response.ok)throw new Error(data.error||'No se pudo consultar el tráfico saliente.');
   if(revision!==serial||state.view!=='outgoing')return;
   lastKey=key;lastLoaded=Date.now();
   node('outgoingCoverage').textContent=data.monitor?.enabled?`Nuevas conexiones IPv4 e IPv6 · registro limitado a ${data.monitor.limit_per_second||20} eventos/s por familia`:'El registro saliente todavía no está activo en el servidor.';
   node('outgoingMessage').textContent=data.truncated?'Se muestran los 1.000 registros más recientes que coinciden. Ajustá los filtros para reducir el resultado.':'Detectada significa observada; no confirma por sí sola que el destino la haya recibido.';
   const labels={observed:'Detectada',accepted:'Permitido',blocked:'Bloqueado'};
   node('outgoingRows').innerHTML=data.events.length?data.events.map(row=>`<tr><td>${dateFmt(row.timestamp)}</td><td>${esc(row.source_port||'—')}</td><td>${esc(row.ip)}</td><td>${esc(row.port||'—')}</td><td><span class="protocol">${esc(row.protocol)}</span></td><td>${countryMarkup(row)}</td><td class="provider-cell" title="${esc(row.provider)}">${esc(row.provider||'Sin identificar')}</td><td><span class="status ${row.decision==='blocked'?'blocked':row.decision==='accepted'?'allowed':'observed'}">${labels[row.decision]||'Detectada'}</span></td></tr>`).join(''):'<tr><td colspan="8" class="empty-state">No hay conexiones salientes que coincidan con los filtros.</td></tr>';
  }catch(error){if(revision===serial&&error.name!=='AbortError')node('outgoingMessage').textContent=error.message;}
  finally{if(request===controller)request=null;}
 }
 node('outgoingFilters').addEventListener('submit',event=>event.preventDefault());
 filters.forEach(id=>node(id).addEventListener(node(id).tagName==='SELECT'?'change':'input',()=>{clearTimeout(timer);timer=setTimeout(()=>load(true),300);}));
 window.addEventListener('storypulse-view',event=>{if(event.detail==='outgoing')void load(true);else{serial++;request?.abort();request=null;}});
 window.addEventListener('storypulse-dashboard',()=>void load());
 document.addEventListener('visibilitychange',()=>{if(document.hidden){serial++;request?.abort();request=null;}else void load(true);});
 void load();
})();
