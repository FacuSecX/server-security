/*
Server Security Monitor v2.0
Created by FacuSecX
https://github.com/FacuSecX/
*/
const uuid=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
export function rebootPayload(body){
  if(!body||Object.keys(body).sort().join(',')!=='boot_id,confirm,server_id,ticket'||body.confirm!==true||
    !/^[a-f0-9]{64}$/.test(body.ticket||'')||!/^[a-f0-9]{32}$/.test(body.server_id||'')||!uuid.test(body.boot_id||''))
    throw new Error('Revisá el servidor y confirmá el reinicio antes de continuar.');
  return {ticket:body.ticket,server_id:body.server_id,boot_id:body.boot_id,confirm:true};
}
export function cpuPercent(current,previous){
  if(!previous||previous.server_id!==current.server_id||previous.boot_id!==current.boot_id)return null;
  const total=current.cpu.total_ticks-previous.cpu.total_ticks,idle=current.cpu.idle_ticks-previous.cpu.idle_ticks;
  if(!Number.isFinite(total)||!Number.isFinite(idle)||total<=0||idle<0||idle>total)return null;
  return Math.round(1000*(1-idle/total))/10;
}

export function createSystemApi({securityCtl,requireActionToken,readJsonBody,sendJson,actionToken,otherBusy,clock=Date.now}){
  let cache=null,loading=null,planning=false,job={status:'idle'};
  const busy=()=>planning||['requesting','restarting'].includes(job.status);
  async function metrics(){
    if(cache&&clock()>=cache.at&&clock()-cache.at<4000)return cache.data;
    if(!loading)loading=securityCtl('system-metrics',{}).then(snapshot=>{
      const percent=cpuPercent(snapshot,cache?.data);
      if(job.server_id&&snapshot.server_id!==job.server_id){
        job={...job,status:'error',message:'Cambió la identidad del servidor. Verificá la conexión antes de continuar.'};
      }else if(job.boot_id&&snapshot.boot_id!==job.boot_id&&snapshot.server_id===job.server_id){
        job={...job,status:'complete',message:'El servidor se reinició y volvió a conectarse.'};
      }else if(['scheduled','scheduling'].includes(snapshot.reboot?.status)){
        job={status:'restarting',boot_id:snapshot.boot_id,server_id:snapshot.server_id,message:'Reinicio solicitado. Esperando a que vuelva el servidor…'};
      }else if(snapshot.reboot?.status==='error'&&job.status!=='idle'){
        job={...job,status:'error',message:snapshot.reboot.message};
      }
      const data={...snapshot,cpu:{...snapshot.cpu,percent}};
      cache={data,at:clock()};return data;
    }).finally(()=>loading=null);
    return loading;
  }
  async function handle(request,response,url){
    if(!url.pathname.startsWith('/api/server'))return false;
    if(url.pathname==='/api/server'&&request.method==='GET'){
      try{sendJson(response,200,{...await metrics(),action_token:actionToken,reboot_job:job});}
      catch(error){sendJson(response,502,{error:'No se pudo actualizar la información del servidor.',reboot_job:job});}return true;
    }
    if(!['/api/server/reboot/plan','/api/server/reboot'].includes(url.pathname)||request.method!=='POST'){
      sendJson(response,404,{error:'Operación no disponible.'});return true;
    }
    if(!requireActionToken(request)){sendJson(response,403,{error:'Autorización local inválida. Recargá el panel.'});return true;}
    let body,payload;
    try{
      body=await readJsonBody(request);
      if(url.pathname.endsWith('/plan')){
        if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).length)throw new Error('La preparación no acepta parámetros.');
        payload={};
      }else payload=rebootPayload(body);
    }catch(error){sendJson(response,error.status||400,{error:error.message});return true;}
    if(busy()||otherBusy()){sendJson(response,409,{error:'Hay una operación en curso. Esperá su resultado antes de reiniciar.'});return true;}
    planning=true;
    if(url.pathname.endsWith('/plan')){
      try{sendJson(response,200,await securityCtl('system-plan',{}));}
      catch(error){sendJson(response,502,{error:error.message});}finally{planning=false;}return true;
    }
    job={status:'requesting',boot_id:payload.boot_id,server_id:payload.server_id,message:'Solicitando el reinicio del servidor…'};
    try{
      const result=await securityCtl('system-reboot',payload);
      job={...job,status:'restarting',message:'Reinicio solicitado. Esperando a que vuelva el servidor…'};cache=null;
      sendJson(response,202,{ok:true,delay_seconds:result.delay_seconds,reboot_job:job});
    }catch(error){job={...job,status:'error',message:'No se pudo confirmar el reinicio. '+error.message};sendJson(response,502,{error:job.message,reboot_job:job});}
    finally{planning=false;}return true;
  }
  return {handle,busy};
}
