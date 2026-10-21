export function validateAlertSettings(body){
  if(!body||Array.isArray(body)||typeof body!=='object')throw new Error('Configuración no válida.');
  const keys=Object.keys(body).sort().join(',');
  if(!['confirm,enabled,revision','admin_id,chat_id,confirm,enabled,revision,token'].includes(keys)||body.confirm!==true||
      !/^[a-f0-9]{64}$/.test(body.revision||'')||typeof body.enabled!=='boolean')throw new Error('Revisá y confirmá la configuración.');
  if('token' in body){
    if(typeof body.token!=='string'||(body.token&&!/^[0-9]{5,20}:[A-Za-z0-9_-]{25,80}$/.test(body.token)))throw new Error('Token no válido.');
    if(typeof body.chat_id!=='string'||! /^-?[1-9][0-9]{0,18}$/.test(body.chat_id)||typeof body.admin_id!=='string'||
      (body.admin_id&&!/^[1-9][0-9]{0,18}$/.test(body.admin_id))||(body.chat_id.startsWith('-')&&!body.admin_id))throw new Error('Revisá el chat ID y el administrador del grupo.');
  }
  return body;
}

export function createAlertsApi({securityCtl,requireActionToken,readJsonBody,sendJson,actionToken}){
  let changing=false;
  async function handle(request,response,url){
    if(url.pathname==='/api/alerts'&&request.method==='GET'){
      try{sendJson(response,200,{...await securityCtl('alerts-status',{}),action_token:actionToken});}
      catch{sendJson(response,502,{error:'No se pudo leer el servicio independiente de alertas.'});}return true;
    }
    if(url.pathname!=='/api/alerts/configure'||request.method!=='POST')return false;
    if(!requireActionToken(request)){sendJson(response,403,{error:'Autorización local inválida.'});return true;}
    let body;try{body=validateAlertSettings(await readJsonBody(request));}
    catch(error){sendJson(response,400,{error:error.message});return true;}
    if(changing){sendJson(response,409,{error:'Esperá el resultado del cambio anterior.'});return true;}
    changing=true;
    try{sendJson(response,200,await securityCtl('alerts-configure',body));}
    catch(error){sendJson(response,error.status||409,{error:error.status===429?error.message:'No se pudo guardar: '+error.message});}
    finally{body.token='';changing=false;}return true;
  }
  return {handle,busy:()=>changing};
}
