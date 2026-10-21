import {randomBytes} from 'node:crypto';
export function createServiceVersionsApi({securityCtl,requireActionToken,readJsonBody,sendJson,actionToken,otherBusy=()=>false}){
 const catalogs=new Map();let job={status:'idle'};
 const busy=()=>job.status==='running';
 async function handle(req,res,url){
  if(url.pathname!=='/api/service-versions')return false;
  try{
   if(req.method==='GET'){
    const kind=url.searchParams.get('service');if(!['ftp','mysql'].includes(kind)||[...url.searchParams.keys()].some(k=>k!=='service'))throw new Error('Servicio no válido.');
    sendJson(res,200,{ok:true,catalog:catalogs.get(kind)||null,job:job.service===kind?job:{status:'idle'},action_token:actionToken});return true;
   }
   if(req.method!=='POST'){sendJson(res,405,{error:'Método no permitido.'});return true;}
   if(!requireActionToken(req)){sendJson(res,403,{error:'Autorización local inválida.'});return true;}
   const body=await readJsonBody(req,512,5000);
   if(Object.keys(body).length!==1||!['ftp','mysql'].includes(body.service))throw new Error('Servicio no válido.');
   if(busy()||otherBusy()){sendJson(res,409,{error:'Hay otra operación en curso.'});return true;}
   const service=body.service,id=randomBytes(8).toString('hex');job={id,service,status:'running',message:'Actualizando repositorios y consultando versiones disponibles…'};
   securityCtl('services-versions',{service}).then(catalog=>{
    if(!catalog?.ok||!Array.isArray(catalog.versions)||catalog.versions.length>80)throw new Error('El catálogo recibido no es válido.');
    catalogs.set(service,catalog);job={id,service,status:'success',message:'Catálogo actualizado.'};
   }).catch(error=>{job={id,service,status:'error',message:String(error.message||error).slice(0,800)};catalogs.delete(service);});
   sendJson(res,202,{ok:true,job,action_token:actionToken});return true;
  }catch(error){sendJson(res,error.status||400,{error:error.message});return true;}
 }
 return {handle,busy};
}