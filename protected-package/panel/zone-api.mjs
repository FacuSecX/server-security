// Server Security Monitor v3.0
import {randomBytes,createHash} from 'node:crypto';
import {isIP} from 'node:net';
const keys=['name','web_domain','port','maxplayers','database','db_user','db_password','rcon_password','ftp_user'];
export function zoneDomain(value){
 if(typeof value!=='string'||value.length<1||value.length>253||!/^[A-Za-z0-9.-]+$/.test(value)||isIP(value))throw new Error('Ingresá un dominio válido, sin protocolo, IP, puerto ni ruta.');
 const labels=value.toLowerCase().split('.'),last=labels.at(-1);
 if(labels.length<2||labels.some(label=>label.length>63||!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))||!(/^[a-z]{2,63}$/.test(last)||/^xn--[a-z0-9-]+$/.test(last)))throw new Error('Ingresá un dominio válido, como rol.ejemplo.com.');
 return labels.join('.');
}
export function zonePayload(body,apply=false){
 const allowed=[...keys,...(apply?['revision','confirm']:[])];
 if(!body||Array.isArray(body)||typeof body!=='object'||Object.keys(body).length!==allowed.length||Object.keys(body).some(k=>!allowed.includes(k)))throw new Error('Parámetros Zone no permitidos.');
 if(typeof body.name!=='string'||!/^[A-Za-z]{1,24}$/.test(body.name)||/zone$/i.test(body.name))throw new Error('Escribí una palabra de hasta 24 letras; Zone se agrega automáticamente.');
 if(!Number.isInteger(body.port)||body.port<1024||body.port>65535||!Number.isInteger(body.maxplayers)||body.maxplayers<1||body.maxplayers>500)throw new Error('Puerto o jugadores no válidos.');
 if(typeof body.database!=='string'||!/^[a-z][a-z0-9_]{2,47}$/.test(body.database)||['mysql','sys','performance_schema','information_schema'].includes(body.database))throw new Error('Nombre de base no válido.');
 if(typeof body.db_user!=='string'||!/^[a-z][a-z0-9_]{2,23}$/.test(body.db_user)||['root','mysql','debian','admin'].includes(body.db_user))throw new Error('Usuario MySQL no válido.');
 if(typeof body.ftp_user!=='string'||!/^[a-z][a-z0-9_-]{2,31}$/.test(body.ftp_user)||['root','debian','admin','anonymous','ftp','spftp','sm-samp','sm-samp-ftp'].includes(body.ftp_user))throw new Error('Usuario FTP no válido.');
 for(const k of ['db_password','rcon_password'])if(typeof body[k]!=='string'||!/^[A-Za-z0-9_!@%+=.,:-]{16,64}$/.test(body[k]))throw new Error('Las contraseñas requieren entre 16 y 64 caracteres permitidos.');
 if(body.db_password===body.rcon_password)throw new Error('MySQL y RCON deben tener contraseñas distintas.');
 if(apply&&(body.confirm!==true||typeof body.revision!=='string'||!/^[a-f0-9]{64}$/.test(body.revision)))throw new Error('Revisá y confirmá la instalación.');
 return {...structuredClone(body),web_domain:zoneDomain(body.web_domain)};
}
export function createZoneApi({securityCtl,requireActionToken,readJsonBody,sendJson,actionToken,authorizeGame,ftpVault,auth,hello,otherBusy=()=>false,invalidate=()=>{},audit=()=>{},runAction=work=>work()}){
 let job={status:'idle'},cache=null,pending=null,finished=0,approved=null,revealing=false;
 const digest=body=>createHash('sha256').update(JSON.stringify(keys.map(key=>[key,body[key]]))).digest('hex');
 const busy=()=>revealing||job.status==='running';
 async function handle(req,res,url){
  if(!['/api/games/zone','/api/games/zone/plan','/api/games/zone/apply','/api/games/zone/repair','/api/games/zone/forum-credentials'].includes(url.pathname))return false;
  try{
   if(url.search)throw new Error('La operación no acepta parámetros en la dirección.');
   if(req.method==='GET'&&url.pathname==='/api/games/zone'){
    if(!busy()&&!otherBusy()&&Date.now()-finished>5000&&(!cache||Date.now()-cache.time>10000)){pending||=securityCtl('zone-status',{}).then(data=>cache={data,time:Date.now()}).finally(()=>pending=null);await pending;}
    sendJson(res,200,{ok:true,...cache?.data,job,action_token:actionToken});return true;
   }
   if(req.method!=='POST'){sendJson(res,405,{error:'Método no permitido.'});return true;}
   if(!requireActionToken(req))throw Object.assign(new Error('Autorización local inválida.'),{status:403});
   authorizeGame(req,'install');
   if(url.pathname.endsWith('/forum-credentials')){
    const session=auth?.session(req),current=()=>auth?.canAct(req)&&auth.session(req)===session&&session?.userId==='primary-admin'&&req.panelUser?.administrator===true&&!session.background&&res.destroyed!==true;
    if(!current()||!hello)throw Object.assign(new Error('Sólo el administrador principal puede consultar este acceso con Windows Hello.'),{status:403});
    const body=await readJsonBody(req,512,5000);if(!body||Array.isArray(body)||Object.keys(body).length)throw new Error('La consulta no admite parámetros.');
    if(busy()||otherBusy())throw Object.assign(new Error('Hay otra operación en curso.'),{status:409});
    const abort=new AbortController(),closed=()=>abort.abort();res.once?.('close',closed);revealing=true;
    try{
     await runAction(async()=>{
      if(await hello.verify(abort.signal,'users')!==true||!current())throw Object.assign(new Error('Windows Hello no autorizó mostrar el acceso.'),{status:403});
      const result=await securityCtl('zone-forum-credentials',{});
      if(!current())throw Object.assign(new Error('La autorización dejó de estar vigente.'),{status:403});
      res.setHeader?.('Cache-Control','no-store');audit('forum-credentials','samp-zone','Acceso al foro consultado con Windows Hello',true,'');
      sendJson(res,200,{...result,hide_after_ms:30000});
     });
    }finally{revealing=false;finished=Date.now();res.removeListener?.('close',closed);}
    return true;
   }
   if(url.pathname.endsWith('/repair')){
    const body=await readJsonBody(req,512,5000);
    if(!body||Array.isArray(body)||!['confirm,revision','confirm,revision,web_domain'].includes(Object.keys(body).sort().join(','))||body.confirm!==true||typeof body.revision!=='string'||!/^[a-f0-9]{64}$/.test(body.revision))throw new Error('Revisá y confirmá la actualización de Zone.');
    if(Object.hasOwn(body,'web_domain'))body.web_domain=zoneDomain(body.web_domain);
    if(busy()||otherBusy())throw Object.assign(new Error('Hay otra operación en curso.'),{status:409});
    const id=randomBytes(12).toString('hex');job={id,status:'running',message:'Actualizando la GM y la web, y comprobando el registro…'};
    runAction(async()=>{
     try{const result=await securityCtl('zone-repair',body);if(result?.ok!==true)throw new Error('El VPS no confirmó la actualización.');cache=null;invalidate();job={id,status:'success',message:result.message};audit('game-repair','samp-zone','Actualización Zone confirmada',true,'');}
     catch(error){job={id,status:'error',message:String(error.message||error).slice(0,2000)};}
     finally{finished=Date.now();}
    }).catch(()=>{job={id,status:'error',message:'No se completó la actualización.'};});
    sendJson(res,202,{ok:true,job});return true;
   }
   if(!url.pathname.endsWith('/plan')&&!url.pathname.endsWith('/apply')){sendJson(res,405,{error:'Método no permitido.'});return true;}
   const apply=url.pathname.endsWith('/apply'),body=zonePayload(await readJsonBody(req,8192,5000),apply);
   if(busy()||otherBusy())throw Object.assign(new Error('Hay otra operación en curso.'),{status:409});
   const principal=req.panelUser?.id||req.panelUser?.username||'';
   if(apply&&(!approved||approved.revision!==body.revision||approved.digest!==digest(body)||approved.principal!==principal||Date.now()-approved.at>10*60*1000))throw new Error('Revisá nuevamente estos datos antes de confirmar.');
   const id=randomBytes(12).toString('hex');job={id,status:'running',message:apply?'Descargando, compilando y preparando Zone. Puede tardar varios minutos…':'Comprobando dependencias y destinos…'};
   runAction(async()=>{
    let credential;
    try{
     if(apply){const proposal=await securityCtl('zone-plan',Object.fromEntries(keys.map(key=>[key,body[key]])));if(proposal.revision!==body.revision)throw new Error('El VPS cambió. Revisá nuevamente la instalación.');approved=null;credential={id:randomBytes(16).toString('hex'),username:body.ftp_user,password:randomBytes(24).toString('base64url')};if(!ftpVault)throw new Error('Falta el almacén protegido FTP.');await ftpVault.save(credential);}
     const result=await securityCtl(apply?'zone-apply':'zone-plan',{...body,...(credential?{ftp_secret:{id:credential.id,password:credential.password}}:{})});
     if(result?.ok!==true)throw new Error('El VPS no confirmó la operación.');
     if(!apply)approved={revision:result.revision,digest:digest(body),principal,at:Date.now()};
     if(apply){cache=null;invalidate();audit('game-install','samp-zone','Instalación Zone verificada',true,'');}
     finished=Date.now();job={id,status:'success',message:result.message||'Revisión completada.',...(!apply?{plan:result}:{})};
    }catch(error){finished=Date.now();if(credential)await ftpVault.clear(credential.id).catch(()=>{});let message=String(error.message||error);for(const k of ['db_password','rcon_password'])message=message.split(body[k]).join('[oculto]');job={id,status:'error',message:message.slice(0,2000)};}
   }).catch(()=>{job={id,status:'error',message:'No se completó la instalación.'};});
   sendJson(res,202,{ok:true,job});return true;
  }catch(error){sendJson(res,error.status||400,{error:error.message});return true;}
 }
 return {handle,busy};
}
