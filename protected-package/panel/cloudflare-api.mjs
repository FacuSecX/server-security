import {randomBytes} from 'node:crypto';
const paths=new Set(['/api/cloudflare','/api/cloudflare/plan','/api/cloudflare/apply']);
function publicError(error){const value=String(error.message||'No se pudo completar la operación.');return /BEGIN |PRIVATE KEY|CERTIFICATE|-----|Traceback/.test(value)?'No se pudo verificar la configuración Cloudflare. No se publicaron certificados ni claves.':value.slice(0,1500);}
export function cloudflarePayload(body,apply=false){
 const allowed=['block_direct','ssl','domain','certificate','private_key','refresh',...(apply?['revision','confirm']:[])];
 if(!body||Array.isArray(body)||typeof body!=='object'||Object.keys(body).some(k=>!allowed.includes(k))||typeof body.block_direct!=='boolean'||typeof body.ssl!=='boolean')throw new Error('Opciones Cloudflare no válidas.');
 for(const key of ['certificate','private_key'])if(body[key]!==undefined&&(typeof body[key]!=='string'||body[key].length>65536||body[key].includes('\0')))throw new Error('Certificado o clave fuera del formato permitido.');
 if(typeof body.domain!=='string'||body.domain.length>253||body.refresh!==undefined&&typeof body.refresh!=='boolean')throw new Error('Dominio u opciones no válidas.');
 if(apply&&(body.confirm!==true||!(/^[a-f0-9]{64}$/).test(body.revision||'')))throw new Error('Revisá y confirmá la operación.');
 return {...body};
}
export function createCloudflareApi({securityCtl,requireActionToken,readJsonBody,sendJson,authorizeService,otherBusy=()=>false,invalidate=()=>{},audit=()=>{}}){
 let job={status:'idle'},cache=null,pending=null;
 const busy=()=>job.status==='running';
 function launch(command,payload){
  const id=randomBytes(8).toString('hex');job={id,status:'running',message:command==='cloudflare-plan'?'Comprobando Nginx, certificado y firewall…':'Aplicando y comprobando el acceso por Cloudflare…'};
  securityCtl(command,payload).then(result=>{
   if(result?.ok!==true)throw new Error('El servidor no confirmó la operación.');
   job={id,status:'success',message:result.message||'Verificación completada.',...(command==='cloudflare-plan'?{plan:result}:{})};
   if(command==='cloudflare-apply'){cache=result.state;invalidate();audit('cloudflare-configure','nginx','Configuración Cloudflare confirmada',true,'');}
  }).catch(error=>{
   job={id,status:'error',message:publicError(error)};
  });
  return {...job};
 }
 async function handle(req,res,url){
  if(!paths.has(url.pathname))return false;
  try{
   authorizeService(req,'manage');
   if(url.search)throw new Error('Consulta no válida.');
   if(req.method==='GET'&&url.pathname==='/api/cloudflare'){
    if(!busy()&&!otherBusy()){
     pending||=securityCtl('cloudflare-status',{}).then(value=>cache=value).finally(()=>pending=null);await pending;
    }
    sendJson(res,200,{ok:true,...cache,job});return true;
   }
   if(req.method!=='POST'||url.pathname==='/api/cloudflare'){sendJson(res,405,{error:'Método no permitido.'});return true;}
   if(!requireActionToken(req)){sendJson(res,403,{error:'Autorización local inválida.'});return true;}
   if(busy()||otherBusy()){sendJson(res,409,{error:'Hay otra operación en curso.'});return true;}
   const apply=url.pathname.endsWith('/apply'),payload=cloudflarePayload(await readJsonBody(req,140000,10000),apply);
   sendJson(res,202,{ok:true,job:launch(apply?'cloudflare-apply':'cloudflare-plan',payload)});return true;
  }catch(error){sendJson(res,error.status||400,{error:publicError(error)});return true;}
 }
 return {handle,busy};
}
