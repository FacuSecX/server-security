/*
Server Security Monitor v2.0
Created by FacuSecX
https://github.com/FacuSecX/
*/
import {randomUUID} from 'node:crypto';
const identities=/^[a-f0-9]{32}$/;
export function cleanupPayload(body,now=Math.floor(Date.now()/1000)){
  if(!body||!['clean','schedule','cancel','delete'].includes(body.action))throw new Error('Acción de limpieza inválida.');
  const result={action:body.action};
  if(body.action==='schedule'){
    if(!Number.isSafeInteger(body.at)||body.at<now+60||body.at>now+5*366*86400)throw new Error('Elegí una fecha futura, al menos un minuto después de ahora.');
    if(!Number.isInteger(body.interval_days)||![0,1,2,3,5,7,14,30].includes(body.interval_days))throw new Error('Frecuencia inválida.');
    Object.assign(result,{at:body.at,interval_days:body.interval_days});
  }
  if(['cancel','delete'].includes(body.action)){
    if(typeof body.id!=='string'||!identities.test(body.id))throw new Error('Programación inválida.');result.id=body.id;
  }
  return result;
}

export function createCleanupApi({securityCtl,requireActionToken,readJsonBody,sendJson,actionToken,historyStore,otherBusy}){
  let cache=null,loading=null,working=false,job={status:'idle'};
  const busy=()=>working;
  async function status(){
    if(working&&cache)return cache;
    if(!loading)loading=securityCtl('cleanup-status',{}).then(data=>{
      historyStore.applyReset(data.reset);cache=data;return data;
    }).finally(()=>loading=null);
    return loading;
  }
  async function handle(request,response,url){
    if(!url.pathname.startsWith('/api/cleanup'))return false;
    if(url.pathname==='/api/cleanup'&&request.method==='GET'){
      try{sendJson(response,200,{...await status(),local:historyStore.storage(),action_token:actionToken,job});}
      catch(error){sendJson(response,502,{error:error.message,job,local:historyStore.storage()});}return true;
    }
    if(!['/api/cleanup/plan','/api/cleanup/apply'].includes(url.pathname)||request.method!=='POST'){
      sendJson(response,404,{error:'Operación no disponible.'});return true;
    }
    if(!requireActionToken(request)){sendJson(response,403,{error:'Autorización local inválida. Recargá el panel.'});return true;}
    let body,payload;
    try{body=await readJsonBody(request);payload=cleanupPayload(body);}catch(error){sendJson(response,error.status||400,{error:error.message});return true;}
    if(working||otherBusy()){sendJson(response,409,{error:'Hay otra operación en curso. Esperá su resultado.'});return true;}
    const apply=url.pathname.endsWith('/apply');
    if(apply&&(body.confirm!==true||!/^[a-f0-9]{64}$/.test(body.revision||''))){sendJson(response,400,{error:'Revisá y confirmá la operación antes de continuar.'});return true;}
    working=true;
    if(!apply){
      try{sendJson(response,200,await securityCtl('cleanup-plan',payload));}
      catch(error){sendJson(response,502,{error:error.message});}finally{working=false;}return true;
    }
    job={id:randomUUID(),status:'running',action:payload.action,message:payload.action==='clean'?'Limpiando registros del servidor y del panel…':'Guardando programación en el servidor…'};
    securityCtl('cleanup-apply',{...payload,confirm:true,revision:body.revision}).then(result=>{
      historyStore.applyReset(result.reset);cache=null;job={...job,status:'success',message:'Operación completada correctamente.'};
    }).catch(error=>{job={...job,status:'error',message:error.message};}).finally(()=>working=false);
    sendJson(response,202,{ok:true,job});return true;
  }
  return {handle,busy};
}
