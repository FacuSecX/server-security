const VALID_VIEWS=new Set(["overview","activity","providers","ssh","reports","ports","investigate","blocks","system"]);
const storedHours=Number(localStorage.getItem("server-security-hours"));
const initialHours=[24,168,720].includes(storedHours)?storedHours:24;
const requestedView=location.hash.replace(/^#/,"");
const storedView=localStorage.getItem("server-security-view")||"overview";
const initialView=VALID_VIEWS.has(requestedView)?requestedView:(VALID_VIEWS.has(storedView)?storedView:"overview");
const state = { data:null, blocks:null, report:null, actionToken:"", hours:initialHours, view:initialView, activityFilter:"", protocol:"", decision:"", selectedPort:null, pendingBlock:null, pendingUnblock:null, providerEvaluation:null, pendingProviderUnblock:null, loading:false, blocksLoading:false, reportLoading:false, sshLiveLoading:false, sshLiveDebounce:null };
const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const fmt = value => new Intl.NumberFormat("es-AR").format(Number(value || 0));
const dateFmt = timestamp => new Intl.DateTimeFormat("es-AR", {day:"2-digit",month:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"}).format(new Date(timestamp*1000));
const timeFmt = timestamp => new Intl.DateTimeFormat("es-AR", {hour:"2-digit",minute:"2-digit",second:"2-digit"}).format(new Date(timestamp*1000));
const esc = value => String(value ?? "").replace(/[&<>"']/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));

function periodLabel(hours){ return hours===24?"Últimas 24 horas":hours===168?"Últimos 7 días":"Últimos 30 días"; }
function duration(seconds){const days=Math.floor(seconds/86400),hours=Math.floor((seconds%86400)/3600),mins=Math.floor((seconds%3600)/60);return days?`${days} d ${hours} h`:hours?`${hours} h ${mins} min`:`${mins} min`;}
function decisionClass(value){const text=String(value).toLowerCase();if(text.includes("bloq"))return"blocked";if(text.includes("fall"))return"failed";if(text.includes("permit"))return"allowed";return"rejected";}
function showToast(message){const toast=$("#toast");toast.textContent=message;toast.classList.add("show");setTimeout(()=>toast.classList.remove("show"),2600);}

function isTailscaleIp(ip){const parts=String(ip||"").split(".").map(Number);return parts.length===4&&parts[0]===100&&parts[1]>=64&&parts[1]<=127;}
function countryMarkup(row){
  const code=String(row?.country_code||row?.key||"").toUpperCase();
  let name=String(row?.country||row?.label||"Desconocido");
  if(isTailscaleIp(row?.ip)&&(!code||code==="XX"||name==="Desconocido")){
    return `<span class="country-label"><span class="country-fallback private" aria-hidden="true">◆</span><span>Red privada Tailscale</span></span>`;
  }
  if(!/^[A-Z]{2}$/.test(code)||code==="XX"){
    return `<span class="country-label"><span class="country-fallback" aria-hidden="true">🌐</span><span>${esc(name||"Desconocido")}</span></span>`;
  }
  const url=`https://flagcdn.com/24x18/${code.toLowerCase()}.png`;
  return `<span class="country-label"><img class="country-flag" src="${url}" width="24" height="18" loading="lazy" referrerpolicy="no-referrer" alt="Bandera de ${esc(name)}"><span>${esc(name)}</span></span>`;
}

function setView(view){
  if(!VALID_VIEWS.has(view))view="overview";
  state.view=view;
  $$(".view").forEach(node=>node.classList.toggle("active",node.id===`view-${view}`));
  $$(".nav-item").forEach(node=>node.classList.toggle("active",node.dataset.view===view));
  const titles={overview:["Resumen de seguridad","Actividad consolidada del servidor"],activity:["Actividad en vivo","Paquetes, accesos y eventos recientes"],providers:["Proveedores bloqueados","Reglas UFW-VPS e ipset"],ssh:["Seguridad SSH","Intentos y sesiones registradas"],reports:["Generar reporte SSH","Crear, descargar y abrir análisis del VPS"],ports:["Puertos y protocolos","Objetivos observados por el firewall"],investigate:["Investigar IP","Historial local de actividad"],blocks:["Bloqueos","Control de IP y evaluación de proveedores"],system:["Estado del sistema","Servicios y conexión privada"]};
  $("#pageTitle").textContent=titles[view][0];$("#pageSubtitle").textContent=titles[view][1];
  history.replaceState(null,"",`#${view}`);
  localStorage.setItem("server-security-view",view);
  $(".sidebar").classList.remove("open");
  if(view==="blocks")loadBlocks();
  if(view==="reports")loadReportStatus();
}

function renderBars(container, rows, valueKey="count", limit=6){
  const data=(rows||[]).slice(0,limit),max=Math.max(1,...data.map(row=>Number(row[valueKey]||0)));
  container.innerHTML=data.length?data.map(row=>`<div class="bar-row"><span class="bar-label" title="${esc(row.label||row.name)}">${esc(row.label||row.name)}</span><div class="bar-track"><div class="bar-fill" style="--width:${Math.max(2,Number(row[valueKey]||0)/max*100)}%"></div></div><span class="bar-value">${fmt(row[valueKey])}</span></div>`).join(""):`<div class="empty-state">Sin datos para este período.</div>`;
}

function renderCountries(rows){
  const all=rows||[],total=all.reduce((sum,row)=>sum+Number(row.count||0),0),top=all.slice(0,7),otherCount=all.slice(7).reduce((sum,row)=>sum+Number(row.count||0),0),chartRows=otherCount?[...top,{key:"XX",label:"Otros",count:otherCount}]:top;$("#donutTotal").textContent=fmt(total);
  const colors=["#159ef5","#2477d4","#8674ff","#ff8738","#ffc84b","#385873","#44d9ed","#39d98a"];
  let cursor=0;const segments=[];
  for(const [index,row] of chartRows.entries()){const pct=total?row.count/total*100:0;segments.push(`${colors[index%colors.length]} ${cursor}% ${cursor+pct}%`);cursor+=pct;}
  $("#countryDonut").style.setProperty("--segments",segments.length?`conic-gradient(${segments.join(",")})`:"#173247");
  $("#countryLegend").innerHTML=chartRows.map(row=>`<div class="legend-row"><span>${countryMarkup({country_code:row.key,country:row.label})}</span><span>${total?Math.round(row.count/total*100):0}%</span></div>`).join("");
}

function renderAllCountries(data){
  const rows=data?.countries_all||[];
  const blocked=rows.reduce((sum,row)=>sum+Number(row.blocked||0),0);
  const accepted=rows.reduce((sum,row)=>sum+Number(row.accepted||0),0);
  const total=blocked+accepted;
  $("#countryDialogSubtitle").textContent=`${periodLabel(state.hours)} · eventos registrados por el firewall`;
  $("#countryDetailStats").innerHTML=`<div><span>Países observados</span><strong>${fmt(rows.length)}</strong></div><div><span>Eventos DROP</span><strong class="country-drop-value">${fmt(blocked)}</strong></div><div><span>Eventos aceptados</span><strong class="country-accepted-value">${fmt(accepted)}</strong></div><div><span>Total del firewall</span><strong>${fmt(total)}</strong></div>`;
  $("#countryAllGrid").innerHTML=rows.length?rows.map((row,index)=>{
    const share=total?Number(row.total||0)/total*100:0;
    return `<article class="country-summary-card"><header><span class="country-rank">${index+1}</span>${countryMarkup({country_code:row.key,country:row.label})}</header><div class="country-summary-values"><div><span>DROP</span><strong class="country-drop-value">${fmt(row.blocked)}</strong></div><div><span>Aceptados</span><strong class="country-accepted-value">${fmt(row.accepted)}</strong></div></div><div class="country-share"><span>Total: <b>${fmt(row.total)}</b></span><span>${fmt(row.unique_ips)} IP únicas</span><span>${share.toLocaleString("es-AR",{maximumFractionDigits:1})}%</span></div><div class="country-share-track"><i style="--country-share:${Math.max(1,share)}%"></i></div></article>`;
  }).join(""):`<div class="empty-state country-empty">No hay eventos del firewall para este período.</div>`;
}

function drawTimeline(rows){
  const canvas=$("#timelineChart"),rect=canvas.getBoundingClientRect(),dpr=window.devicePixelRatio||1;canvas.width=Math.max(600,rect.width*dpr);canvas.height=Math.max(170,rect.height*dpr);const ctx=canvas.getContext("2d");ctx.scale(dpr,dpr);const w=canvas.width/dpr,h=canvas.height/dpr,p={l:38,r:12,t:10,b:25};ctx.clearRect(0,0,w,h);const max=Math.max(5,...rows.flatMap(row=>[row.blocked,row.accepted||0,row.ssh]));ctx.strokeStyle="#183348";ctx.lineWidth=1;ctx.fillStyle="#6f8ca2";ctx.font="11px Segoe UI";for(let i=0;i<=4;i++){const y=p.t+(h-p.t-p.b)*i/4;ctx.beginPath();ctx.moveTo(p.l,y);ctx.lineTo(w-p.r,y);ctx.stroke();ctx.fillText(String(Math.round(max*(1-i/4))),3,y+4);}function line(key,color,fill){ctx.beginPath();rows.forEach((row,i)=>{const x=p.l+(w-p.l-p.r)*(i/Math.max(1,rows.length-1)),y=p.t+(h-p.t-p.b)*(1-Number(row[key]||0)/max);i?ctx.lineTo(x,y):ctx.moveTo(x,y);});if(fill){ctx.lineTo(w-p.r,h-p.b);ctx.lineTo(p.l,h-p.b);ctx.closePath();const g=ctx.createLinearGradient(0,p.t,0,h-p.b);g.addColorStop(0,fill);g.addColorStop(1,"transparent");ctx.fillStyle=g;ctx.fill();ctx.beginPath();rows.forEach((row,i)=>{const x=p.l+(w-p.l-p.r)*(i/Math.max(1,rows.length-1)),y=p.t+(h-p.t-p.b)*(1-Number(row[key]||0)/max);i?ctx.lineTo(x,y):ctx.moveTo(x,y);});}ctx.strokeStyle=color;ctx.lineWidth=2;ctx.stroke();}line("blocked","#159ef5","#159ef52b");line("accepted","#39d98a",null);line("ssh","#44d9ed",null);const marks=[0,Math.floor((rows.length-1)/2),rows.length-1];ctx.fillStyle="#6f8ca2";for(const i of marks){if(!rows[i])continue;const label=new Intl.DateTimeFormat("es-AR",state.hours===24?{hour:"2-digit",minute:"2-digit"}:{day:"2-digit",month:"2-digit"}).format(new Date(rows[i].timestamp*1000));const x=p.l+(w-p.l-p.r)*(i/Math.max(1,rows.length-1));ctx.fillText(label,Math.max(0,x-18),h-5);}}

function rowHtml(row,full=false){return `<tr><td>${full?dateFmt(row.timestamp):timeFmt(row.timestamp)}</td><td>${esc(row.display_ip||row.ip)}</td><td>${countryMarkup(row)}</td><td class="provider-cell" title="${esc(row.provider)}">${esc(row.provider||"Sin identificar")}</td><td><span class="protocol">${esc(row.protocol)}</span></td><td>${esc(row.port)}</td>${full?`<td>${esc(row.service)}</td>`:""}<td><span class="status ${decisionClass(row.decision)}">${esc(row.decision)}</span></td>${full?"":`<td>${esc(row.details)}</td>`}</tr>`;}

function filteredEvents(){const text=state.activityFilter.toLowerCase();const filteredSource=state.decision&&state.data?.activity_events?.[state.decision];const rows=filteredSource||state.data?.events||[];return rows.filter(row=>(!state.protocol||row.protocol===state.protocol)&&(!state.decision||row.flow_status===state.decision)&&(!text||[row.ip,row.provider,row.port,row.service,row.country].some(value=>String(value||"").toLowerCase().includes(text))));}
function renderActivity(){const rows=filteredEvents();$("#activityRows").innerHTML=rows.length?rows.map(row=>rowHtml(row,true)).join(""):`<tr><td colspan="8" class="empty-state">No hay eventos que coincidan con el filtro.</td></tr>`;}

function renderProviders(data){const providers=data.providers||[];$("#providerCount").textContent=fmt(data.summary.providers);$("#providerPackets").textContent=fmt(data.summary.drop_packets);$("#providerActive").textContent=fmt(providers.filter(row=>row.packets>0).length);const text=$("#providerFilter").value.toLowerCase();const visible=providers.filter(row=>row.name.toLowerCase().includes(text));$("#providerCards").innerHTML=visible.map(row=>`<article class="provider-card"><header><h3 title="${esc(row.name)}">${esc(row.name)}</h3><span class="status blocked">DROP</span></header><div class="number">${fmt(row.packets)}</div><small>paquetes bloqueados · ${fmt(row.entries)} rangos (${fmt(row.ipv4_entries)} IPv4 + ${fmt(row.ipv6_entries)} IPv6)</small><footer><span>${fmt(row.logged_events)} eventos registrados</span><span>${fmt(row.unique_ips)} IP</span></footer></article>`).join("")||`<div class="empty-state">No se encontraron proveedores.</div>`;}

function renderSsh(data){$("#sshFailures").textContent=fmt(data.summary.ssh_failures);$("#sshSuccess").textContent=fmt(data.summary.ssh_success);$("#sshUsersCount").textContent=fmt((data.ssh_users||[]).length);renderBars($("#sshFullBars"),data.ssh_users,"count",20);$("#sshRows").innerHTML=(data.ssh_events||[]).map(row=>`<tr><td>${dateFmt(row.timestamp)}</td><td>${esc(row.display_ip||row.ip)}</td><td>${countryMarkup(row)}</td><td>${esc(row.ssh_user||"—")}</td><td><span class="status ${decisionClass(row.decision)}">${esc(row.decision)}</span></td></tr>`).join("")||`<tr><td colspan="5" class="empty-state">Sin actividad SSH registrada.</td></tr>`;}

function renderSshLive(data){
  const summary=data.summary||{},userSelect=$("#sshLiveUser"),selected=userSelect.value;
  userSelect.innerHTML=`<option value="">Todos los usuarios</option>${(data.users||[]).map(row=>`<option value="${esc(row.key)}">${esc(row.label)} (${fmt(row.count)})</option>`).join("")}`;
  if([...userSelect.options].some(option=>option.value===selected))userSelect.value=selected;
  $("#sshLiveSubtitle").textContent=`${periodLabel(data.hours)} · sincronización automática cada ${fmt(data.refresh_seconds||20)} segundos`;
  $("#sshLiveStats").innerHTML=`<div><span>Coincidencias</span><strong>${fmt(summary.matched)}</strong></div><div><span>IP coincidentes</span><strong>${fmt(summary.matched_unique_ips)}</strong></div><div><span>Exitosos</span><strong class="ssh-success-value">${fmt(summary.success)}</strong></div><div><span>Fallidos</span><strong class="ssh-failed-value">${fmt(summary.failed)}</strong></div><div><span>Bloqueados</span><strong class="ssh-blocked-value">${fmt(summary.blocked)}</strong></div>`;
  $("#sshLiveRows").innerHTML=(data.events||[]).length?data.events.map(row=>{
    const provider=row.provider||row.isp||"Sin identificar",isp=row.isp&&row.isp!==provider?row.isp:"",asn=row.asn||"ASN no disponible",providerMeta=[isp,asn].filter(Boolean).join(" · ");
    const statusClass=row.ssh_result==="success"?"allowed":row.ssh_result==="blocked"?"blocked":"failed";
    return `<tr><td>${dateFmt(row.timestamp)}</td><td>${esc(row.display_ip||row.ip)}</td><td>${countryMarkup(row)}</td><td class="ssh-provider-cell" title="${esc(`${provider} · ${providerMeta}`)}"><strong>${esc(provider)}</strong><small>${esc(providerMeta)}</small></td><td>${esc(row.ssh_user||"—")}</td><td>${esc(row.auth_method||"—")}</td><td><span class="status ${statusClass}">${esc(row.result_label)}</span></td></tr>`;
  }).join(""):`<tr><td colspan="7" class="empty-state">No hay eventos SSH que coincidan con estos filtros.</td></tr>`;
  const shown=(data.events||[]).length;
  $("#sshLiveRows").closest("table").classList.toggle("is-truncated",Boolean(data.truncated));
  if(data.truncated)$("#sshLiveSubtitle").textContent+=` · mostrando los ${fmt(shown)} más recientes`;
}

async function loadSshLive({open=false}={}){
  const dialog=$("#sshLiveDialog");
  if(open&&!dialog.open){
    dialog.showModal();
    $("#sshLiveRows").innerHTML=`<tr><td colspan="7" class="empty-state">Cargando actividad SSH…</td></tr>`;
  }
  if(state.sshLiveLoading)return;
  state.sshLiveLoading=true;
  try{
    const params=new URLSearchParams({hours:String(state.hours)});
    const result=$("#sshLiveResult").value,user=$("#sshLiveUser").value,query=$("#sshLiveQuery").value.trim();
    if(result)params.set("result",result);if(user)params.set("user",user);if(query)params.set("query",query);
    const response=await fetch(`/api/ssh-live?${params}`,{cache:"no-store"}),raw=await response.text();
    let data;
    try{data=JSON.parse(raw);}catch{throw new Error("El servidor local quedó en una versión anterior. Reinicia iniciar-panel.bat.");}
    if(!response.ok)throw new Error(data.error||`HTTP ${response.status}`);
    if(dialog.open)renderSshLive(data);
  }catch(error){
    if(dialog.open)$("#sshLiveRows").innerHTML=`<tr><td colspan="7" class="empty-state">${esc(error.message)}</td></tr>`;
  }finally{state.sshLiveLoading=false;}
}

function renderPorts(data){$("#portCards").innerHTML=(data.ports||[]).map(row=>{const separator=row.key.indexOf("/"),protocol=row.key.slice(0,separator),port=row.key.slice(separator+1);return `<button type="button" class="port-card" data-protocol="${esc(protocol)}" data-port="${esc(port)}"><div class="port-title"><strong>${esc(row.key)}</strong><span class="protocol">${esc(protocol)}</span></div><div class="port-count">${fmt(row.count)}</div><small>${esc(row.label.split("—").slice(1).join("—").trim())} · ${fmt(row.unique_ips)} IP únicas</small><span class="port-drill">Ver IP y horarios <b aria-hidden="true">→</b></span></button>`;}).join("")||`<div class="empty-state">Sin puertos registrados.</div>`;}

async function loadPortDetails(protocol,port,{open=true}={}){
  const dialog=$("#portDialog");
  state.selectedPort={protocol,port};
  if(open){
    $("#portDialogTitle").textContent=`${protocol}/${port}`;
    $("#portDialogSubtitle").textContent="Consultando eventos bloqueados…";
    $("#portDetailStats").innerHTML="";
    $("#portDetailRows").innerHTML=`<tr><td colspan="5" class="empty-state">Cargando registros…</td></tr>`;
    if(!dialog.open)dialog.showModal();
  }
  try{
    const response=await fetch(`/api/port?protocol=${encodeURIComponent(protocol)}&port=${encodeURIComponent(port)}&hours=${state.hours}`,{cache:"no-store"});
    const raw=await response.text();
    let data;
    try{data=JSON.parse(raw);}catch{
      if(response.status===404)throw new Error("El servidor local quedó en una versión anterior. Cierra la ventana del panel y ejecuta nuevamente iniciar-panel.bat.");
      throw new Error(`Respuesta no válida del panel local (HTTP ${response.status}).`);
    }
    if(!response.ok)throw new Error(data.error||`HTTP ${response.status}`);
    if(!state.selectedPort||state.selectedPort.protocol!==protocol||state.selectedPort.port!==port)return;
    $("#portDialogTitle").textContent=`${data.protocol}/${data.port} — ${data.service}`;
    $("#portDialogSubtitle").textContent=`${periodLabel(data.hours)} · eventos registrados por las reglas UFW-VPS`;
    $("#portDetailStats").innerHTML=`<div><span>Eventos bloqueados</span><strong>${fmt(data.total)}</strong></div><div><span>IP únicas</span><strong>${fmt(data.unique_ips)}</strong></div><div><span>Mostrados</span><strong>${fmt(data.events.length)}${data.truncated?"+":""}</strong></div>`;
    $("#portDetailRows").innerHTML=data.events.length?data.events.map(row=>`<tr><td>${dateFmt(row.timestamp)}</td><td>${esc(row.ip)}</td><td>${countryMarkup(row)}</td><td class="provider-cell" title="${esc(row.provider)}">${esc(row.provider||"Sin identificar")}</td><td><span class="status blocked">Bloqueado</span></td></tr>`).join(""):`<tr><td colspan="5" class="empty-state">No hay eventos bloqueados para este objetivo.</td></tr>`;
  }catch(error){
    if(open||dialog.open)$("#portDetailRows").innerHTML=`<tr><td colspan="5" class="empty-state">${esc(error.message)}</td></tr>`;
  }
}

function renderSystem(data){const system=data.system||{},labels={active:"Activo",completed:"Completado",inactive:"Inactivo",failed:"Falló",missing:"No instalado",unknown:"Desconocido"},monitor=system.accept_monitor||{};$("#systemDisk").textContent=system.disk_percent!=null?`${system.disk_percent}%`:"—";$("#systemMemory").textContent=system.memory_percent!=null?`${system.memory_percent}%`:"—";$("#systemUptime").textContent=duration(system.uptime_seconds||0);$("#systemHost").textContent=system.hostname||"—";$("#systemTailscale").textContent=system.tailscale_ip||data.connection.host||"—";$("#systemTransport").textContent=data.connection.transportConnected?"Persistente · Activo":"Persistente · Reconectando";$("#systemUfwLogging").textContent=monitor.enabled?`Activo · ${fmt(monitor.rules)} reglas ALLOW`:"Pendiente de instalar";$("#systemRules").textContent=fmt(system.provider_rules||data.summary.providers);$("#systemSync").textContent=data.connection.lastSuccess?dateFmt(data.connection.lastSuccess):"Pendiente";$("#serviceList").innerHTML=(system.services||[]).map(row=>`<div class="service-row" title="Estado systemd: ${esc(row.active_state||row.state)}${row.sub_state?` / ${esc(row.sub_state)}`:""}"><code>${esc(row.unit)}</code><span class="service-state ${esc(row.state)}">${labels[row.state]||esc(row.state)}</span></div>`).join("")||`<div class="empty-state">Esperando información del VPS.</div>`;}

function renderConnection(data){const pill=$("#connectionPill"),notice=$("#connectionNotice"),isLive=data.mode==="live"&&data.connection.connected;pill.className=`connection-pill ${isLive?"online":data.connection.error?"offline":"waiting"}`;pill.querySelector("span").textContent=isLive?"VPS conectado · En vivo":"Sin conexión";$("#sidebarMode").textContent=isLive?"Monitoreo activo 24/7":"Conexión pendiente";if(!data.connection.connected){notice.className="notice error";notice.textContent=`No se pudo consultar el VPS: ${data.connection.error||"conexión pendiente"}`;}else notice.className="notice hidden";}

function render(data){state.data=data;renderConnection(data);$("#kpiDrops").textContent=fmt(data.summary.drop_packets);$("#kpiEvents").textContent=fmt(data.summary.total_events??data.summary.logged_events);$("#kpiIps").textContent=fmt(data.summary.unique_ips);$("#kpiCritical").textContent=fmt(data.summary.critical);$("#eventsPeriod").textContent=periodLabel(state.hours);$("#timelineCaption").textContent=periodLabel(state.hours);$("#liveUpdated").textContent=data.connection.lastSuccess?`Actualizado automáticamente a las ${timeFmt(data.connection.lastSuccess)}`:"Esperando datos del VPS";const monitor=data.system?.accept_monitor||{},coverage=$("#activityCoverage");coverage.className=monitor.enabled?"coverage-ready":"coverage-warning";coverage.textContent=monitor.enabled?`Conexiones nuevas aceptadas y bloqueadas · ${fmt(monitor.rules)} reglas ALLOW vigiladas`:"Sólo se ven bloqueos, SSH y web · ejecuta instalar-control-vps.bat para registrar conexiones aceptadas";renderCountries(data.countries_all||data.countries);renderAllCountries(data);const activeProviders=[...(data.providers||[])].sort((a,b)=>Number(b.logged_events||0)-Number(a.logged_events||0)).map(row=>({...row,label:row.name}));renderBars($("#providerBars"),activeProviders,"logged_events",6);renderBars($("#sshUserBars"),data.ssh_users,"count",6);drawTimeline(data.timeline||[]);const score=Math.min(100,data.summary.critical*45+Math.min(35,data.summary.ssh_failures/20)+Math.min(20,data.summary.logged_events/100));const level=score>=70?"Alto":score>=35?"Medio":"Bajo";$("#riskLabel").textContent=level;$("#riskScore").textContent=`${Math.round(score)}/100`;$("#riskRing").style.setProperty("--score",`${Math.min(50,score/2)}%`);$("#riskCritical").textContent=fmt(data.summary.critical);$("#riskSsh").textContent=fmt(data.summary.ssh_failures);$("#riskBlocked").textContent=fmt(data.summary.logged_events);$("#liveRows").innerHTML=(data.events||[]).slice(0,8).map(row=>rowHtml(row,false)).join("");renderActivity();renderProviders(data);renderSsh(data);renderPorts(data);renderSystem(data);if(state.blocks)renderBlocks();}

async function load(){if(state.loading)return;state.loading=true;try{const response=await fetch(`/api/dashboard?hours=${state.hours}`,{cache:"no-store"});if(!response.ok)throw new Error(`HTTP ${response.status}`);render(await response.json());if($("#portDialog").open&&state.selectedPort)loadPortDetails(state.selectedPort.protocol,state.selectedPort.port,{open:false});if($("#sshLiveDialog").open)loadSshLive();}catch(error){$("#connectionNotice").className="notice error";$("#connectionNotice").textContent=`El panel local no respondió: ${error.message}`;}finally{state.loading=false;}}

async function investigate(ip){
  const result=$("#ipResult");result.className="ip-result";result.textContent="Buscando…";
  try{
    const response=await fetch(`/api/ip?address=${encodeURIComponent(ip)}`,{cache:"no-store"});
    const data=await response.json();
    if(!response.ok)throw new Error(data.error||"No se pudo consultar");
    if(!data.count){result.className="ip-result empty-state";result.textContent="No hay eventos almacenados para esa dirección.";return;}
    const geo=data.geo||{},ssh=data.ssh||{total:0,users:[],events:[]};
    const sshUsers=(ssh.users||[]).map(row=>`<tr><td><strong>${esc(row.user)}</strong></td><td>${fmt(row.attempts)}</td><td>${dateFmt(row.first_seen)}</td><td>${dateFmt(row.last_seen)}</td></tr>`).join("");
    const sshEvents=(ssh.events||[]).map(row=>`<tr><td>${dateFmt(row.timestamp)}</td><td>${esc(row.ssh_user||"desconocido")}</td><td>${esc(row.auth_method||"—")}</td><td><span class="status ${decisionClass(row.decision)}">${esc(row.decision)}</span></td></tr>`).join("");
    result.innerHTML=`
      <div class="ip-summary">
        <div><span>IP</span><strong>${esc(data.ip)}</strong></div>
        <div><span>País</span><strong>${countryMarkup({ip:data.ip,country_code:geo.country_code,country:geo.country})}</strong></div>
        <div><span>ISP</span><strong>${esc(geo.isp||"Sin identificar")}</strong></div>
        <div><span>Eventos</span><strong>${fmt(data.count)}</strong></div>
      </div>
      <div class="ip-actions">
        <button type="button" class="ip-ssh-toggle" data-total="${Number(ssh.total||0)}" aria-expanded="false" ${ssh.total?"":"disabled"}>
          ${ssh.total?`Consultar registros SSH · ${fmt(ssh.total)} eventos`:"Sin registros SSH para esta IP"}
        </button>
      </div>
      <section class="ip-ssh-details hidden" aria-label="Registros SSH de la dirección investigada">
        <div class="ip-section-heading"><div><h3>Usuarios probados por esta IP</h3><p>${fmt((ssh.users||[]).length)} usuarios diferentes</p></div></div>
        <div class="table-scroll"><table><thead><tr><th>Usuario</th><th>Intentos</th><th>Primer intento</th><th>Último intento</th></tr></thead><tbody>${sshUsers||`<tr><td colspan="4" class="empty-state">No se registraron usuarios fallidos.</td></tr>`}</tbody></table></div>
        <div class="ip-section-heading"><div><h3>Cronología SSH</h3><p>${ssh.truncated?"Se muestran los 1.000 eventos más recientes":`${fmt(ssh.total)} eventos registrados`}</p></div></div>
        <div class="table-scroll ip-ssh-scroll"><table><thead><tr><th>Fecha</th><th>Usuario</th><th>Método</th><th>Resultado</th></tr></thead><tbody>${sshEvents||`<tr><td colspan="4" class="empty-state">Sin actividad SSH.</td></tr>`}</tbody></table></div>
      </section>
      <div class="ip-section-heading"><div><h3>Historial completo</h3><p>Últimos ${fmt(Math.min(data.events.length,100))} eventos de esta IP</p></div></div>
      <div class="table-scroll"><table><thead><tr><th>Fecha</th><th>Protocolo</th><th>Puerto</th><th>Servicio</th><th>Resultado</th></tr></thead><tbody>${data.events.slice(0,100).map(row=>`<tr><td>${dateFmt(row.timestamp)}</td><td>${esc(row.protocol)}</td><td>${esc(row.port)}</td><td>${esc(row.service)}</td><td>${esc(row.decision)}</td></tr>`).join("")}</tbody></table></div>`;
  }catch(error){result.className="ip-result empty-state";result.textContent=error.message;}
}

function renderBlockProviders(){
  const rows=state.data?.providers||state.blocks?.providers||[];
  const text=$("#blockProviderFilter").value.trim().toLowerCase();
  const visible=rows.filter(row=>String(row.name||"").toLowerCase().includes(text));
  $("#blockProviderRows").innerHTML=visible.length?visible.map(row=>`<tr><td class="provider-cell" title="${esc(row.name)}"><strong>${esc(row.name)}</strong></td><td>${fmt(row.ipv4_entries)}</td><td>${fmt(row.ipv6_entries)}</td><td>${fmt(row.entries)}</td><td>${fmt(row.packets)}</td></tr>`).join(""):`<tr><td colspan="5" class="empty-state">No se encontraron proveedores.</td></tr>`;
}

function renderBlocks(){
  const data=state.blocks||{},controller=data.controller||{},entries=controller.entries||[],reviewedProviders=controller.provider_blocks||[],providers=state.data?.providers||data.providers||[];
  $("#manualBlockCount").textContent=fmt(entries.length);
  $("#blockProviderCount").textContent=fmt(providers.length+reviewedProviders.length);
  const ready=Boolean(controller.installed&&controller.rules?.ipv4&&controller.rules?.ipv6&&controller.provider_rules?.ipv4&&controller.provider_rules?.ipv6);
  $("#blockControllerState").textContent=ready?"Activo":controller.installed?"Requiere sincronización":"No instalado";
  const notice=$("#blockControllerNotice");
  if(ready){notice.className="block-controller-notice online";notice.textContent=`Controlador activo: ${fmt(controller.ipv4)} IPv4 y ${fmt(controller.ipv6)} IPv6 bloqueadas manualmente.`;}
  else if(controller.installed){notice.className="block-controller-notice error";notice.textContent="El controlador existe, pero falta una regla IPv4 o IPv6. Ejecuta en el VPS: sudo server-securityctl sync";}
  else{notice.className="block-controller-notice error";notice.textContent="Falta instalar el controlador limitado del VPS. Usa los archivos de la carpeta vps antes de aplicar bloqueos desde el panel.";}
  $("#blockIpButton").disabled=!ready;
  $("#manualBlockRows").innerHTML=entries.length?entries.map(row=>`<tr><td><strong>${esc(row.ip)}</strong></td><td>IPv${Number(row.family)===6?"6":"4"}</td><td>${esc(new Date(row.created_at).toLocaleString("es-AR"))}</td><td title="${esc(row.reason)}">${esc(row.reason)}</td><td><button type="button" class="table-action unblock-ip" data-ip="${esc(row.ip)}">Quitar</button></td></tr>`).join(""):`<tr><td colspan="5" class="empty-state">No hay IP bloqueadas manualmente.</td></tr>`;
  $("#reviewedProviderRows").innerHTML=reviewedProviders.length?reviewedProviders.map(row=>`<tr><td><strong>${esc(row.name)}</strong></td><td>${esc(row.asn)}</td><td>${fmt(row.ipv4)}</td><td>${fmt(row.ipv6)}</td><td>${esc(new Date(row.created_at).toLocaleString("es-AR"))}</td><td><button type="button" class="table-action unblock-provider" data-asn="${esc(row.asn)}" data-name="${esc(row.name)}">Quitar</button></td></tr>`).join(""):`<tr><td colspan="6" class="empty-state">No hay proveedores bloqueados desde el panel.</td></tr>`;
  const audit=data.audit||[];
  const actionLabels={block:"Bloqueo IP",unblock:"Desbloqueo IP","provider-block":"Bloqueo proveedor","provider-unblock":"Desbloqueo proveedor"};
  $("#blockAuditRows").innerHTML=audit.length?audit.map(row=>`<tr><td>${dateFmt(row.timestamp)}</td><td>${actionLabels[row.action]||esc(row.action)}</td><td>${esc(row.target)}</td><td><span class="status ${row.ok?"allowed":"failed"}">${row.ok?"Aplicado":"Falló"}</span></td><td title="${esc(row.reason||row.details)}">${esc(row.reason||row.details||"—")}</td></tr>`).join(""):`<tr><td colspan="5" class="empty-state">Todavía no hay acciones realizadas desde el panel.</td></tr>`;
  renderBlockProviders();
}

async function loadBlocks(){
  if(state.blocksLoading)return;
  state.blocksLoading=true;
  try{
    const response=await fetch("/api/blocks",{cache:"no-store"});
    const raw=await response.text();let data;
    try{data=JSON.parse(raw);}catch{throw new Error("El servidor local quedó en una versión anterior. Reinicia iniciar-panel.bat.");}
    if(!response.ok)throw new Error(data.error||`HTTP ${response.status}`);
    state.blocks=data;state.actionToken=data.action_token||"";renderBlocks();
  }catch(error){
    const notice=$("#blockControllerNotice");notice.className="block-controller-notice error";notice.textContent=`No se pudo consultar el control de bloqueos: ${error.message}`;$("#blockIpButton").disabled=true;
  }finally{state.blocksLoading=false;}
}

function renderProviderEvaluation(data){
  const result=$("#providerEvaluation"),geo=data.geo||{};
  state.providerEvaluation=data;
  const reasons=(data.reasons||[]).map(reason=>`<li>${esc(reason)}</li>`).join("");
  const prefixes=(data.prefixes?.preview||[]).map(prefix=>`<code>${esc(prefix)}</code>`).join("");
  const sources=(data.sources||[]).map(source=>`<a href="${esc(source.url)}" target="_blank" rel="noopener noreferrer">${esc(source.name)} ↗</a>`).join("");
  const approvalState=data.panel_block
    ?`<div class="provider-approval approved"><strong>Bloqueo activo</strong><span>${esc(data.panel_block.asn)} ya está aplicado desde el panel.</span></div>`
    :data.approved_for_blocking
      ?`<div class="provider-approval approved"><strong>Revisión aprobada</strong><span>La huella actual coincide con la aprobación guardada.</span></div>`
      :`<div class="provider-approval pending"><strong>Pendiente de aprobación</strong><span>Código de revisión: <code>${esc(data.review_code)}</code>. Confírmalo primero durante la revisión en ChatGPT.</span></div>`;
  const action=data.panel_block?"":`<div class="provider-evaluation-action"><button type="button" class="danger-button apply-provider-block" ${data.can_apply?"":"disabled"}>${data.can_apply?"Revisar bloqueo del proveedor":"Falta aprobación para bloquear"}</button><small>La aprobación sólo es válida mientras no cambien los prefijos BGP.</small></div>`;
  result.className="provider-evaluation";
  result.innerHTML=`<div class="evaluation-head"><div><h3>${esc(data.holder||data.asn)}</h3><p>${data.sample_ip?`${esc(data.sample_ip)}${data.observed_prefix?` · prefijo ${esc(data.observed_prefix)}`:""}`:"Evaluación directa del ASN"}</p></div><span class="evaluation-badge ${esc(data.assessment)}">${esc(data.assessment_label)}</span></div>
    <div class="evaluation-facts"><div><span>ASN</span><strong>${esc(data.asn)}</strong></div><div><span>País observado</span><strong>${data.sample_ip?countryMarkup({ip:data.sample_ip,country_code:geo.country_code,country:geo.country}):"No aplica"}</strong></div><div><span>Prefijos anunciados</span><strong>${fmt(data.prefixes?.total)} (${fmt(data.prefixes?.ipv4)} IPv4 + ${fmt(data.prefixes?.ipv6)} IPv6)</strong></div></div>
    <ul class="evaluation-reasons">${reasons}</ul>
    ${approvalState}
    ${prefixes?`<div><span class="dialog-kicker">Vista previa BGP</span><div class="prefix-preview">${prefixes}</div></div>`:""}
    <div class="evaluation-sources">${sources}</div>
    ${action}
    <p class="evaluation-warning">No se aplicó ningún cambio. Los anuncios BGP sirven como evidencia técnica, pero no autorizan por sí solos a bloquear un proveedor completo.</p>`;
}

async function applyIpAction(action,ip,reason=""){
  if(!state.actionToken){showToast("Recarga el módulo de bloqueos");return;}
  const button=action==="block"?$("#blockConfirmApply"):$("#unblockConfirmApply");button.disabled=true;
  try{
    const response=await fetch("/api/blocks/ip",{method:"POST",headers:{"Content-Type":"application/json","X-Server-Security-Token":state.actionToken},body:JSON.stringify({action,ip,reason,confirm:true})});
    const data=await response.json();if(!response.ok)throw new Error(data.error||`HTTP ${response.status}`);
    if(action==="block")$("#blockConfirmDialog").close();else $("#unblockConfirmDialog").close();
    showToast(data.changed?(action==="block"?"IP bloqueada correctamente":"Bloqueo eliminado correctamente"):(action==="block"?"La IP ya estaba bloqueada":"La IP no estaba bloqueada"));
    await loadBlocks();
  }catch(error){showToast(`No se pudo aplicar: ${error.message}`);}
  finally{button.disabled=false;}
}

function updateProviderConfirmation(){
  const data=state.providerEvaluation||{},typed=$("#providerBlockConfirmInput").value.trim().toUpperCase();
  $("#providerBlockConfirmApply").disabled=!($("#providerBlockConfirmCheck").checked&&typed===String(data.asn||"").toUpperCase());
}

function openProviderBlockConfirmation(){
  const data=state.providerEvaluation;
  if(!data?.can_apply){showToast("Este proveedor todavía no está aprobado");return;}
  $("#providerBlockConfirmName").textContent=data.holder||data.asn;
  $("#providerBlockConfirmAsn").textContent=data.asn;
  $("#providerBlockConfirmPrefixes").textContent=`${fmt(data.prefixes?.total)} prefijos`;
  $("#providerBlockConfirmInput").value="";
  $("#providerBlockConfirmInput").placeholder=data.asn;
  $("#providerBlockConfirmCheck").checked=false;
  updateProviderConfirmation();
  $("#providerBlockConfirmDialog").showModal();
}

async function applyProviderAction(action,data){
  if(!state.actionToken){showToast("Recarga el módulo de bloqueos");return;}
  const button=action==="block"?$("#providerBlockConfirmApply"):$("#providerUnblockConfirmApply");button.disabled=true;
  try{
    const body={action,asn:data.asn,confirm_asn:data.asn,confirm:true,reason:`Proveedor ${data.asn} confirmado tras revisión manual`};
    if(action==="block"){body.expected_name=data.holder||"";body.prefix_digest=data.prefix_digest;}
    const response=await fetch("/api/blocks/provider",{method:"POST",headers:{"Content-Type":"application/json","X-Server-Security-Token":state.actionToken},body:JSON.stringify(body)});
    const payload=await response.json();if(!response.ok)throw new Error(payload.error||`HTTP ${response.status}`);
    if(action==="block")$("#providerBlockConfirmDialog").close();else $("#providerUnblockConfirmDialog").close();
    showToast(payload.changed?(action==="block"?"Proveedor bloqueado correctamente":"Bloqueo del proveedor eliminado"):(action==="block"?"El proveedor ya estaba bloqueado":"El proveedor no estaba bloqueado"));
    state.providerEvaluation=null;
    $("#providerEvaluation").className="provider-evaluation empty-state";
    $("#providerEvaluation").textContent="Vuelve a evaluar una IP o ASN para consultar su estado actual.";
    await loadBlocks();
  }catch(error){showToast(`No se pudo aplicar: ${error.message}`);button.disabled=false;}
}

function reportDate(timestamp){
  return timestamp?new Intl.DateTimeFormat("es-AR",{dateStyle:"short",timeStyle:"medium"}).format(new Date(timestamp*1000)):"—";
}

function reportSize(bytes){
  const value=Number(bytes||0);
  if(value<1024)return`${fmt(value)} B`;
  if(value<1024*1024)return`${(value/1024).toLocaleString("es-AR",{maximumFractionDigits:1})} KB`;
  return`${(value/1024/1024).toLocaleString("es-AR",{maximumFractionDigits:1})} MB`;
}

function reportStatusInfo(status){
  return ({
    idle:{label:"Listo",title:"Listo para generar",icon:"✓",progress:0},
    generating:{label:"Generando",title:"Analizando registros en el VPS",icon:"⋯",progress:38},
    downloading:{label:"Descargando",title:"Descargando el TXT a Windows",icon:"↓",progress:76},
    complete:{label:"Completado",title:"Reporte completado",icon:"✓",progress:100},
    error:{label:"Error",title:"No se completó el reporte",icon:"!",progress:100},
  })[status]||{label:"Listo",title:"Listo para generar",icon:"✓",progress:0};
}

function updateReportPreview(){
  const input=$("#sshReportDays"),days=Number(input.value||0);
  $("#reportSincePreview").textContent=Number.isInteger(days)&&days>0?`--since "${days*1440} minutes ago"`:'--since "N minutes ago"';
  $$('[data-report-days]').forEach(button=>button.classList.toggle("active",Number(button.dataset.reportDays)===days));
}

function renderReportStatus(data){
  state.report=data;
  const job=data.job||{},config=data.config||{},status=String(job.status||"idle"),info=reportStatusInfo(status),busy=status==="generating"||status==="downloading";
  const files=Array.isArray(job.files)?job.files:[];
  const period=Number(job.days||0);
  $("#reportStateSummary").textContent=info.label;
  $("#reportPeriodSummary").textContent=period?`${fmt(period)} ${period===1?"día":"días"}`:"—";
  $("#reportFilesSummary").textContent=fmt(files.length);
  const badge=$("#reportStatusBadge");badge.className=`report-status-badge ${status}`;badge.textContent=info.label;
  const icon=$("#reportStatusIcon");icon.className=`report-status-icon ${status}`;icon.textContent=info.icon;
  $("#reportStatusTitle").textContent=info.title;
  $("#reportStatusMessage").textContent=job.message||"Elegí un período y comenzá el análisis.";
  $("#reportProgressBar").style.width=`${info.progress}%`;
  $("#reportRemoteDir").textContent=config.remote_output_dir||"/var/lib/server-security/reports";
  $("#reportLocalDir").textContent=config.local_output_dir||"No configurado";
  $("#reportStartedAt").textContent=reportDate(job.started_at);
  $("#reportFinishedAt").textContent=reportDate(job.finished_at);
  $("#reportFileList").innerHTML=files.length?files.map(file=>`<li><strong>${esc(file.name)}</strong><span>${esc(String(file.type||"").toUpperCase())} · ${reportSize(file.size)}</span></li>`).join(""):`<li>${status==="complete"?"El análisis no produjo archivos nuevos.":"Todavía no hay archivos generados desde el panel."}</li>`;
  const error=$("#reportError");error.classList.toggle("hidden",!job.error);error.textContent=job.error||"";
  const button=$("#sshReportGenerate");
  button.disabled=busy||config.downloader_ready===false;
  button.textContent=busy?(status==="generating"?"Generando reporte…":"Descargando reporte…"):(config.downloader_ready===false?"Falta configurar el BAT":"Generar y descargar reporte");
  const retry=$("#sshReportRetry");
  retry.disabled=busy||config.downloader_ready===false;
  retry.textContent=status==="downloading"?"Descargando…":"Descargar último TXT existente";
  if(config.max_days){$("#sshReportDays").max=String(config.max_days);}
}

async function loadReportStatus(){
  if(state.reportLoading)return;
  state.reportLoading=true;
  try{
    const response=await fetch("/api/reports/ssh",{cache:"no-store"});
    const data=await response.json();
    if(!response.ok)throw new Error(data.error||`HTTP ${response.status}`);
    state.actionToken=data.action_token||state.actionToken;
    renderReportStatus(data);
  }catch(error){
    const notice=$("#reportError");notice.classList.remove("hidden");notice.textContent=`No se pudo consultar el generador: ${error.message}`;
  }finally{state.reportLoading=false;}
}

async function generateSshReport(){
  const days=Number($("#sshReportDays").value);
  const maximum=Number($("#sshReportDays").max||7);
  if(!Number.isInteger(days)||days<1||days>maximum){showToast(`Elegí entre 1 y ${maximum} días completos`);return;}
  if(!state.actionToken)await loadReportStatus();
  const button=$("#sshReportGenerate");button.disabled=true;button.textContent="Iniciando…";
  try{
    const response=await fetch("/api/reports/ssh",{method:"POST",headers:{"Content-Type":"application/json","X-Server-Security-Token":state.actionToken},body:JSON.stringify({action:"generate",days,confirm:true})});
    const data=await response.json();
    if(!response.ok)throw new Error(data.error||`HTTP ${response.status}`);
    renderReportStatus({...(state.report||{}),job:data.job});
    showToast("Reporte SSH iniciado");
  }catch(error){showToast(`No se pudo iniciar: ${error.message}`);await loadReportStatus();}
}

async function downloadLatestSshReport(){
  if(!state.actionToken)await loadReportStatus();
  const button=$("#sshReportRetry");button.disabled=true;button.textContent="Iniciando descarga…";
  try{
    const response=await fetch("/api/reports/ssh",{method:"POST",headers:{"Content-Type":"application/json","X-Server-Security-Token":state.actionToken},body:JSON.stringify({action:"download",confirm:true})});
    const data=await response.json();
    if(!response.ok)throw new Error(data.error||`HTTP ${response.status}`);
    renderReportStatus({...(state.report||{}),job:data.job});
    showToast("Descarga iniciada");
  }catch(error){showToast(`No se pudo descargar: ${error.message}`);await loadReportStatus();}
}

$$('.nav-item').forEach(button=>button.addEventListener("click",()=>setView(button.dataset.view)));
$$('[data-view-link]').forEach(button=>button.addEventListener("click",()=>setView(button.dataset.viewLink)));
$$('[data-hours]').forEach(button=>button.addEventListener("click",()=>{
  state.hours=Number(button.dataset.hours);
  localStorage.setItem("server-security-hours",String(state.hours));
  $$('[data-hours]').forEach(item=>item.classList.toggle("active",Number(item.dataset.hours)===state.hours));
  load();
}));
$("#mobileMenu").addEventListener("click",()=>$(".sidebar").classList.toggle("open"));
$("#activityFilter").addEventListener("input",event=>{state.activityFilter=event.target.value;renderActivity();});
$("#activityProtocol").addEventListener("change",event=>{state.protocol=event.target.value;renderActivity();});
$("#activityDecision").addEventListener("change",event=>{state.decision=event.target.value;renderActivity();});
$("#providerFilter").addEventListener("input",()=>state.data&&renderProviders(state.data));
$("#ipForm").addEventListener("submit",event=>{event.preventDefault();investigate($("#ipInput").value.trim());});
$("#refreshButton").addEventListener("click",async()=>{await fetch("/api/refresh",{method:"POST"});showToast("Actualización solicitada");setTimeout(load,1800);});
window.addEventListener("resize",()=>state.data&&drawTimeline(state.data.timeline||[]));
$("#portCards").addEventListener("click",event=>{const card=event.target.closest(".port-card");if(card)loadPortDetails(card.dataset.protocol,card.dataset.port);});
$("#portDialogClose").addEventListener("click",()=>$("#portDialog").close());
$("#portDialog").addEventListener("close",()=>{state.selectedPort=null;});
$("#portDialog").addEventListener("click",event=>{if(event.target===$("#portDialog"))$("#portDialog").close();});
$("#countryDialogOpen").addEventListener("click",()=>{$("#countryDialog").showModal();state.data&&renderAllCountries(state.data);});
$("#countryDialogClose").addEventListener("click",()=>$("#countryDialog").close());
$("#countryDialog").addEventListener("click",event=>{if(event.target===$("#countryDialog"))$("#countryDialog").close();});
$("#sshLiveOpen").addEventListener("click",()=>loadSshLive({open:true}));
$("#sshLiveClose").addEventListener("click",()=>$("#sshLiveDialog").close());
$("#sshLiveDialog").addEventListener("click",event=>{if(event.target===$("#sshLiveDialog"))$("#sshLiveDialog").close();});
$("#sshLiveResult").addEventListener("change",()=>loadSshLive());
$("#sshLiveUser").addEventListener("change",()=>loadSshLive());
$("#sshLiveQuery").addEventListener("input",()=>{
  clearTimeout(state.sshLiveDebounce);
  state.sshLiveDebounce=setTimeout(()=>loadSshLive(),350);
});
$("#sshLiveClear").addEventListener("click",()=>{
  clearTimeout(state.sshLiveDebounce);
  $("#sshLiveResult").value="";
  $("#sshLiveUser").value="";
  $("#sshLiveQuery").value="";
  loadSshLive();
});
$("#sshLiveDialog").addEventListener("close",()=>clearTimeout(state.sshLiveDebounce));
$$('[data-report-days]').forEach(button=>button.addEventListener("click",()=>{$("#sshReportDays").value=button.dataset.reportDays;updateReportPreview();}));
$("#sshReportDays").addEventListener("input",updateReportPreview);
$("#sshReportForm").addEventListener("submit",event=>{event.preventDefault();generateSshReport();});
$("#sshReportRetry").addEventListener("click",downloadLatestSshReport);
$("#ipResult").addEventListener("click",event=>{const button=event.target.closest(".ip-ssh-toggle");if(!button||button.disabled)return;const details=$("#ipResult .ip-ssh-details"),willOpen=details.classList.contains("hidden");details.classList.toggle("hidden",!willOpen);button.setAttribute("aria-expanded",String(willOpen));button.textContent=willOpen?"Ocultar registros SSH":`Consultar registros SSH · ${fmt(button.dataset.total)} eventos`;});
$("#reloadBlocks").addEventListener("click",loadBlocks);
$("#blockProviderFilter").addEventListener("input",renderBlockProviders);
$("#blockIpForm").addEventListener("submit",event=>{event.preventDefault();const ip=$("#blockIpInput").value.trim(),reason=$("#blockReasonInput").value.trim();state.pendingBlock={ip,reason};$("#blockConfirmIp").textContent=ip;$("#blockConfirmReason").textContent=reason?`Motivo: ${reason}`:"Motivo: bloqueo manual desde el panel local";$("#blockConfirmCheck").checked=false;$("#blockConfirmApply").disabled=true;$("#blockConfirmDialog").showModal();});
$("#blockConfirmCheck").addEventListener("change",event=>{$("#blockConfirmApply").disabled=!event.target.checked;});
$("#blockConfirmApply").addEventListener("click",()=>state.pendingBlock&&applyIpAction("block",state.pendingBlock.ip,state.pendingBlock.reason));
$("#blockConfirmClose").addEventListener("click",()=>$("#blockConfirmDialog").close());
$("#blockConfirmCancel").addEventListener("click",()=>$("#blockConfirmDialog").close());
$("#manualBlockRows").addEventListener("click",event=>{const button=event.target.closest(".unblock-ip");if(!button)return;state.pendingUnblock=button.dataset.ip;$("#unblockConfirmIp").textContent=state.pendingUnblock;$("#unblockConfirmDialog").showModal();});
$("#unblockConfirmApply").addEventListener("click",()=>state.pendingUnblock&&applyIpAction("unblock",state.pendingUnblock));
$("#unblockConfirmClose").addEventListener("click",()=>$("#unblockConfirmDialog").close());
$("#unblockConfirmCancel").addEventListener("click",()=>$("#unblockConfirmDialog").close());
$("#providerEvaluation").addEventListener("click",event=>{if(event.target.closest(".apply-provider-block"))openProviderBlockConfirmation();});
$("#providerBlockConfirmInput").addEventListener("input",updateProviderConfirmation);
$("#providerBlockConfirmCheck").addEventListener("change",updateProviderConfirmation);
$("#providerBlockConfirmApply").addEventListener("click",()=>state.providerEvaluation&&applyProviderAction("block",state.providerEvaluation));
$("#providerBlockConfirmClose").addEventListener("click",()=>$("#providerBlockConfirmDialog").close());
$("#providerBlockConfirmCancel").addEventListener("click",()=>$("#providerBlockConfirmDialog").close());
$("#reviewedProviderRows").addEventListener("click",event=>{const button=event.target.closest(".unblock-provider");if(!button)return;state.pendingProviderUnblock={asn:button.dataset.asn,name:button.dataset.name};$("#providerUnblockConfirmName").textContent=state.pendingProviderUnblock.name;$("#providerUnblockConfirmAsn").textContent=state.pendingProviderUnblock.asn;$("#providerUnblockConfirmApply").disabled=false;$("#providerUnblockConfirmDialog").showModal();});
$("#providerUnblockConfirmApply").addEventListener("click",()=>state.pendingProviderUnblock&&applyProviderAction("unblock",state.pendingProviderUnblock));
$("#providerUnblockConfirmClose").addEventListener("click",()=>$("#providerUnblockConfirmDialog").close());
$("#providerUnblockConfirmCancel").addEventListener("click",()=>$("#providerUnblockConfirmDialog").close());
$("#providerEvaluateForm").addEventListener("submit",async event=>{event.preventDefault();const result=$("#providerEvaluation"),button=event.currentTarget.querySelector("button");state.providerEvaluation=null;result.className="provider-evaluation empty-state";result.textContent="Consultando ASN y prefijos anunciados…";button.disabled=true;try{const response=await fetch("/api/providers/evaluate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({query:$("#providerEvaluateQuery").value.trim(),expected_name:$("#providerExpectedName").value.trim()})});const data=await response.json();if(!response.ok)throw new Error(data.error||`HTTP ${response.status}`);renderProviderEvaluation(data);}catch(error){result.className="provider-evaluation empty-state";result.textContent=`No se pudo evaluar: ${error.message}`;}finally{button.disabled=false;}});
[$("#blockConfirmDialog"),$("#unblockConfirmDialog"),$("#providerBlockConfirmDialog"),$("#providerUnblockConfirmDialog")].forEach(dialog=>dialog.addEventListener("click",event=>{if(event.target===dialog)dialog.close();}));
document.addEventListener("error",event=>{if(event.target instanceof HTMLImageElement&&event.target.classList.contains("country-flag")){const fallback=document.createElement("span");fallback.className="country-fallback";fallback.textContent="🌐";event.target.replaceWith(fallback);}},true);
document.addEventListener("visibilitychange",()=>{if(document.visibilityState==="visible")load();});
$$('[data-hours]').forEach(button=>button.classList.toggle("active",Number(button.dataset.hours)===state.hours));
setView(state.view);
updateReportPreview();
load();setInterval(()=>{if(document.visibilityState==="visible")load();},10000);setInterval(()=>{if(document.visibilityState==="visible"&&state.view==="blocks")loadBlocks();},30000);setInterval(()=>{if(document.visibilityState==="visible"&&(state.view==="reports"||["generating","downloading"].includes(state.report?.job?.status)))loadReportStatus();},2500);
