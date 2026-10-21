import {randomBytes} from 'node:crypto';
export const CATALOG_SERVICES=Object.freeze(['phpmyadmin','wordpress','nginx','apache','php','certbot','docker','postgresql','redis','fail2ban','wireguard','postfix']);
const paths=new Set(['/api/catalog-services','/api/catalog-services/versions','/api/catalog-services/plan','/api/catalog-services/apply']);
export function catalogPayload(body,apply=false){
 if(!body||Array.isArray(body)||typeof body!=='object'||!CATALOG_SERVICES.includes(body.service))throw new Error('Servicio no permitido.');
 const control=['start','stop','restart'].includes(body.action);
 const allowed=['service','action',...(body.action==='uninstall'?['erase_data']:control?[]:['selection']),...(apply?['revision','confirm']:[])];
 if(Object.keys(body).some(k=>!allowed.includes(k))||!['install','upgrade','uninstall','start','stop','restart'].includes(body.action))throw new Error('Parámetros no permitidos.');
 if(body.action==='uninstall'){if(body.erase_data!==true)throw new Error('Confirmá el borrado permanente.');}
 else if(!control&&(typeof body.selection!=='string'||!/^[a-f0-9]{64}$/.test(body.selection)))throw new Error('Versión no válida.');
 if(apply&&(body.confirm!==true||typeof body.revision!=='string'||!/^[a-f0-9]{64}$/.test(body.revision)))throw new Error('Revisá y confirmá la operación.');
 return {...body};
}
export function createCatalogServicesApi({securityCtl,requireActionToken,readJsonBody,sendJson,actionToken,authorizeService=()=>{},otherBusy=()=>false,invalidate=()=>{},audit=()=>{}}){
 const catalogs=new Map();let job={status:'idle'},cache=null,pending=null;
 const busy=()=>job.status==='running';
 function launch(command,payload){
  const id=randomBytes(8).toString('hex');job={id,service:payload.service,action:payload.action||'versions',status:'running',message:command==='catalog-versions'?'Consultando repositorios y archivos oficiales…':command==='catalog-plan'?'Verificando paquetes y dependencias…':'Aplicando el cambio confirmado…'};
  securityCtl(command,payload).then(result=>{
   if(result?.ok!==true)throw new Error('El controlador no confirmó la operación.');
   if(command==='catalog-versions'){
    if(!Array.isArray(result.versions)||result.versions.length>5)throw new Error('Catálogo no válido.');catalogs.set(payload.service,result);
   }
   if(command==='catalog-apply'){cache=null;invalidate();audit('service-'+payload.action,payload.service,'Cambio de servicio confirmado',true,'');}
   job={id,service:payload.service,action:payload.action||'versions',status:'success',message:result.message||'Verificación completada.',...(command==='catalog-plan'?{plan:result}:{})};
  }).catch(error=>{cache=null;job={id,service:payload.service,action:payload.action||'versions',status:'error',message:String(error.message||error).slice(0,2400)};});
  return {...job};
 }
 async function handle(req,res,url){
  if(!paths.has(url.pathname))return false;
  try{
   if(req.method==='GET'){
    if(url.pathname==='/api/catalog-services'){
     if(url.search)throw new Error('Consulta no válida.');
     if(!cache||Date.now()-cache.time>15000){
      if(!busy()&&!otherBusy()){
       pending||=(async()=>{const data=await securityCtl('catalog-status',{});cache={data,time:Date.now()};return data;})().finally(()=>pending=null);
       await pending;
      }
     }
     sendJson(res,200,{ok:true,...cache?.data,job,action_token:actionToken});return true;
    }
    if(url.pathname==='/api/catalog-services/versions'){
     const service=url.searchParams.get('service');if(!CATALOG_SERVICES.includes(service)||[...url.searchParams.keys()].some(k=>k!=='service'))throw new Error('Servicio no válido.');
     sendJson(res,200,{ok:true,catalog:catalogs.get(service)||null,job,action_token:actionToken});return true;
    }
    sendJson(res,405,{error:'Método no permitido.'});return true;
   }
   if(req.method!=='POST'){sendJson(res,405,{error:'Método no permitido.'});return true;}
   if(!requireActionToken(req)){sendJson(res,403,{error:'Autorización local inválida.'});return true;}
   const body=await readJsonBody(req,2048,5000);
   if(busy()||otherBusy()){sendJson(res,409,{error:'Hay otra operación en curso.'});return true;}
   if(url.pathname.endsWith('/versions')){
    if(Object.keys(body).length!==1||!CATALOG_SERVICES.includes(body.service))throw new Error('Servicio no válido.');
    authorizeService(req,'install');sendJson(res,202,{ok:true,job:launch('catalog-versions',body)});return true;
   }
   if(!['/api/catalog-services/plan','/api/catalog-services/apply'].includes(url.pathname)){sendJson(res,405,{error:'Método no permitido.'});return true;}
   const apply=url.pathname.endsWith('/apply'),payload=catalogPayload(body,apply);authorizeService(req,payload.action);
   sendJson(res,202,{ok:true,job:launch(apply?'catalog-apply':'catalog-plan',payload)});return true;
  }catch(error){sendJson(res,error.status||400,{error:String(error.message||error)});return true;}
 }
 return {handle,busy};
}