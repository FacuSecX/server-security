/*
Server Security Monitor v2.0
Created by FacuSecX
https://github.com/FacuSecX/
*/
const serverInfo={data:null,cpuServerId:null,lastCpuPercent:null,online:false,pending:false,plan:null,requesting:false,job:{status:'idle'}};
const serverInfoBytes=value=>(Number(value||0)/1024**3).toLocaleString('es-AR',{minimumFractionDigits:1,maximumFractionDigits:2})+' GB';
function renderServerInfo(online=serverInfo.online){
  serverInfo.online=online;
  const data=serverInfo.data;
  $('#serverBanner').classList.toggle('server-stale',!online);
  $('#serverBannerState').textContent=online?'En vivo · cada 5 s':data?'Sin conexión · últimos datos':'Conectando al servidor…';
  if(data){
    $('#serverBannerHost').textContent=data.hostname;
    $('#serverBannerIp').textContent=data.public_ip||'IP pública no disponible';
    $('#serverBannerIp').title=(data.public_ips||[]).join(' · ');
    if(serverInfo.cpuServerId!==data.server_id){serverInfo.cpuServerId=data.server_id;serverInfo.lastCpuPercent=null;}
    if(Number.isFinite(data.cpu.percent))serverInfo.lastCpuPercent=data.cpu.percent;
    const cpuPercent=serverInfo.lastCpuPercent;
    $('#serverBannerCpu').textContent=data.cpu.cores+' vCPU'+(Number.isFinite(cpuPercent)?' · '+cpuPercent.toLocaleString('es-AR')+'%':'');
    $('#serverBannerCpu').title=data.cpu.model;
    $('#serverBannerMemory').textContent=serverInfoBytes(data.memory.used)+' / '+serverInfoBytes(data.memory.total);
    $('#serverBannerDisk').textContent=serverInfoBytes(data.disk.used)+' / '+serverInfoBytes(data.disk.total);
    $('#serverBannerUpdated').textContent='Última lectura '+new Intl.DateTimeFormat('es-AR',{timeStyle:'medium'}).format(new Date(data.generated_at*1000));
    $('#systemPublicIp').textContent=data.public_ip||'No disponible';
    $('#systemOsInfo').textContent=data.distribution?(data.distribution.name+' · '+data.distribution.architecture):'No disponible';
    $('#systemCpuInfo').textContent=data.cpu.cores+' vCPU · '+data.cpu.model;
    $('#systemRamInfo').textContent=serverInfoBytes(data.memory.total);
    $('#systemDiskInfo').textContent=serverInfoBytes(data.disk.total);
    $('#systemDisk').textContent=(100*data.disk.used/data.disk.total).toFixed(1)+'%';
    $('#systemMemory').textContent=(100*data.memory.used/data.memory.total).toFixed(1)+'%';
    $('#systemUptime').textContent=duration(data.uptime_seconds);
  }
  const job=serverInfo.job,busy=serverInfo.requesting||['requesting','restarting'].includes(job.status);
  $('#serverRebootOpen').disabled=!online||!data||busy;
  $('#serverRebootStatus').textContent=job.message||'Reinicia el servidor completo. Las conexiones y los servicios se interrumpirán temporalmente.';
  $('#serverRebootStatus').classList.toggle('error',job.status==='error');
}
async function refreshServerInfo(){
  if(serverInfo.pending)return;serverInfo.pending=true;
  try{
    const response=await fetch('/api/server',{cache:'no-store',signal:AbortSignal.timeout(25000)}),data=await response.json();
    if(data.reboot_job)serverInfo.job=data.reboot_job;
    if(!response.ok)throw new Error(data.error||'Sin conexión');
    serverInfo.data=data;state.actionToken=data.action_token;renderServerInfo(true);
  }catch{renderServerInfo(false);}finally{serverInfo.pending=false;}
}
async function serverInfoPost(path,body){
  const response=await fetch('/api/server/reboot'+path,{method:'POST',headers:{'Content-Type':'application/json','X-StoryPulse-Token':state.actionToken},body:JSON.stringify(body),signal:AbortSignal.timeout(30000)});
  const data=await response.json();if(!response.ok)throw new Error(data.error||'No se pudo completar la operación.');return data;
}
$('#serverRebootOpen').addEventListener('click',async()=>{
  serverInfo.requesting=true;renderServerInfo();
  try{
    const plan=await serverInfoPost('/plan',{});serverInfo.plan=plan;
    $('#serverRebootTarget').textContent=(plan.public_ip||'IP pública no disponible')+' · '+plan.hostname;
    $('#serverRebootConfirm').checked=false;$('#serverRebootApply').disabled=true;$('#serverRebootError').textContent='';
    $('#serverRebootDialog').showModal();
  }catch(error){showToast(error.message);}finally{serverInfo.requesting=false;renderServerInfo();}
});
$('#serverRebootConfirm').addEventListener('change',()=>$('#serverRebootApply').disabled=!$('#serverRebootConfirm').checked);
$('#serverRebootCancel').addEventListener('click',()=>$('#serverRebootDialog').close());
$('#serverRebootDialog').addEventListener('close',()=>serverInfo.plan=null);
$('#serverRebootDialog').addEventListener('cancel',event=>{if(serverInfo.requesting)event.preventDefault();});
$('#serverRebootApply').addEventListener('click',async()=>{
  const plan=serverInfo.plan;
  if(!plan||!$('#serverRebootConfirm').checked||serverInfo.requesting)return;
  serverInfo.requesting=true;$('#serverRebootApply').disabled=true;$('#serverRebootCancel').disabled=true;
  try{
    const data=await serverInfoPost('',{ticket:plan.ticket,server_id:plan.server_id,boot_id:plan.boot_id,confirm:true});
    serverInfo.job=data.reboot_job;$('#serverRebootDialog').close();showToast('Reinicio solicitado. El panel intentará reconectarse automáticamente.');
  }catch(error){$('#serverRebootError').textContent=error.message;$('#serverRebootApply').disabled=false;}
  finally{serverInfo.requesting=false;$('#serverRebootCancel').disabled=false;renderServerInfo();}
});
const serverBannerObserver=new ResizeObserver(entries=>{
  document.documentElement.style.setProperty('--server-bar-height',Math.ceil(entries[0].target.getBoundingClientRect().height)+'px');
});
serverBannerObserver.observe($('#serverBanner'));
setInterval(()=>{if(!document.hidden)refreshServerInfo();},5000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)refreshServerInfo();});
refreshServerInfo();

window.addEventListener('storypulse-dashboard',()=>{if(serverInfo.data)renderServerInfo();});
