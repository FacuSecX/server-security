// Server Security Monitor v3.0
// Created by FacuSecX
// https://github.com/FacuSecX/
import {randomBytes} from 'node:crypto';
const paths=new Set(['/api/games','/api/games/console','/api/games/plan','/api/games/apply','/api/games/ftp/reveal']);
export function gamePayload(body,apply=false){
 if(!body||Array.isArray(body)||typeof body!=='object'||body.game!=='samp'||!['install','uninstall','start','stop','restart','configure'].includes(body.action))throw new Error('Juego o acción no permitidos.');
 if(apply&&body.action==='configure'&&body.restart_confirmed!==true)throw new Error('Confirmá el aviso de reinicio y desconexión de jugadores antes de guardar los cambios.');
 const allowed=['game','action',...(['install','configure'].includes(body.action)?['settings']:[]),...(body.action==='install'&&Object.hasOwn(body,'ftp')?['ftp']:[]),...(body.action==='uninstall'?['erase_data']:[]),...(apply?['revision','confirm',...(body.action==='configure'?['restart_confirmed']:[])]:[])];
 if(Object.keys(body).length!==allowed.length||Object.keys(body).some(key=>!allowed.includes(key)))throw new Error('Parámetros del juego no válidos.');
 if(body.ftp!==undefined){
  const ftp=body.ftp;
  if(!ftp||Array.isArray(ftp)||typeof ftp!=='object'||Object.keys(ftp).sort().join(',')!=='enabled,username'||typeof ftp.enabled!=='boolean'||typeof ftp.username!=='string'||(ftp.enabled&&(!/^[a-z][a-z0-9_-]{2,31}$/.test(ftp.username)||['root','debian','admin','anonymous','ftp','spftp'].includes(ftp.username)))||(!ftp.enabled&&ftp.username!==''))throw new Error('Configuración de la cuenta FTP no válida.');
 }
 if(body.settings!==undefined){
  const s=body.settings,keys=['hostname','port','maxplayers','gamemode','query','chatlogging'],optional=['filterscripts','plugins'];
  if(!s||Array.isArray(s)||typeof s!=='object'||keys.some(key=>!Object.hasOwn(s,key))||Object.keys(s).some(key=>![...keys,...optional].includes(key)))throw new Error('Configuración incompleta.');
  for(const key of optional)if(Object.hasOwn(s,key)){
   const names=s[key],pattern=key==='plugins'?/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\.so$/:/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/;
   if(!Array.isArray(names)||names.length>(key==='plugins'?32:15)||names.some(name=>typeof name!=='string'||name==='sm_panel_stats'||name.includes('..')||!pattern.test(name))||new Set(names).size!==names.length)throw new Error('Selección de filterscripts o plugins no válida.');
   if(body.action==='install'&&names.length)throw new Error('La instalación inicial utiliza los componentes incluidos.');
  }
  if(typeof s.hostname!=='string'||s.hostname.length<1||s.hostname.length>80||/[\x00-\x1f\x7f\uD800-\uDFFF]/u.test(s.hostname))throw new Error('Nombre de servidor no válido.');
  if(!Number.isInteger(s.port)||s.port<1024||s.port>65535||!Number.isInteger(s.maxplayers)||s.maxplayers<1||s.maxplayers>1000)throw new Error('Puerto o cantidad de jugadores no válidos.');
  if(typeof s.gamemode!=='string'||!/^[A-Za-z0-9_-]{1,48}$/.test(s.gamemode)||typeof s.query!=='boolean'||typeof s.chatlogging!=='boolean')throw new Error('Gamemode u opciones no válidos.');
  if(body.action==='install'&&s.gamemode!=='grandlarc')throw new Error('La instalación inicial utiliza el gamemode incluido.');
 }
 if(body.action==='uninstall'&&body.erase_data!==true)throw new Error('Confirmá el borrado de los archivos del juego.');
 if(apply&&(body.confirm!==true||typeof body.revision!=='string'||!/^[a-f0-9]{64}$/.test(body.revision)))throw new Error('Primero revisá y confirmá la operación.');
 return structuredClone(body);
}
export function createGamesApi({securityCtl,requireActionToken,readJsonBody,sendJson,actionToken,authorizeGame=()=>{},otherBusy=()=>false,invalidate=()=>{},audit=()=>{},auth,hello,ftpVault,now=Date.now}){
 let cache=null,pending=null,job={status:'idle'},revealing=false,revealAfter=0;
 const busy=()=>job.status==='running'||revealing;
 function launch(command,payload){
  const id=randomBytes(12).toString('hex');
  job={id,action:payload.action,status:'running',message:command==='games-plan'?'Comprobando instalación, puerto y dependencias…':'Aplicando la operación confirmada…'};
  (async()=>{
   let credential;
   if(command==='games-apply'&&payload.action==='install'&&payload.ftp?.enabled){
    if(!ftpVault)throw new Error('No se encontró el almacén protegido de contraseñas FTP.');
    credential={id:randomBytes(16).toString('hex'),username:payload.ftp.username,password:randomBytes(24).toString('base64url')};
    await ftpVault.save(credential);
   }
   try{
    const result=await securityCtl(command,credential?{...payload,ftp_secret:{id:credential.id,password:credential.password}}:payload);
    if(result?.ok!==true)throw new Error('El servidor no confirmó la operación.');
    if(command==='games-apply'&&payload.action==='uninstall'&&ftpVault)await ftpVault.clear();
    return result;
   }catch(error){if(credential)await ftpVault.clear(credential.id).catch(()=>{});throw error;}
  })().then(result=>{
   if(result?.ok!==true)throw new Error('El servidor no confirmó la operación.');
   if(command==='games-apply'){cache=null;invalidate();audit('game-'+payload.action,'samp','Cambio de juego confirmado',true,'');}
   job={id,action:payload.action,status:'success',message:result.message||'Revisión completada.',...(command==='games-plan'?{plan:result}:{})};
  }).catch(error=>{cache=null;job={id,action:payload.action,status:'error',message:String(error.message||error).slice(0,2400)};});
  return {...job};
 }
 async function handle(req,res,url){
  if(!paths.has(url.pathname))return false;
  try{
   if(url.pathname==='/api/games/ftp/reveal'){
    if(req.method!=='POST'){sendJson(res,405,{error:'Método no permitido.'});return true;}
    if(url.search||!requireActionToken(req))throw Object.assign(new Error('Autorización local inválida.'),{status:403});
    authorizeGame(req,'ftp-reveal');
    const session=auth?.session(req);
    const current=()=>auth?.canAct(req)&&auth.session(req)===session&&session?.userId==='primary-admin'&&req.panelUser?.administrator===true&&!session.background&&res.destroyed!==true;
    if(!current())throw Object.assign(new Error('Sólo el administrador principal puede revelar la contraseña FTP.'),{status:403});
    if(Object.keys(await readJsonBody(req,512,5000)).length)throw new Error('La consulta no acepta parámetros.');
    if(busy()||otherBusy()||now()<revealAfter)throw Object.assign(new Error('Esperá la respuesta y tres segundos antes de volver a intentar.'),{status:429});
    revealing=true;const abort=new AbortController(),closed=()=>abort.abort();res.once?.('close',closed);
    try{
     const row=await securityCtl('games-status',{}),ftp=row?.ftp;
     if(!ftp?.enabled||!ftpVault||!hello)throw new Error('Este juego no tiene una cuenta FTP configurada.');
     if(await hello.verify(abort.signal,'game-ftp')!==true||!current())throw Object.assign(new Error('Windows Hello no autorizó mostrar la contraseña.'),{status:403});
     const value=await ftpVault.load({id:ftp.id,username:ftp.username});
     if(!current()||value.id!==ftp.id||value.username!==ftp.username)throw Object.assign(new Error('La autorización dejó de estar vigente.'),{status:403});
     res.setHeader?.('Cache-Control','no-store');
     audit('game-ftp-reveal','samp','Contraseña FTP mostrada tras verificar Windows Hello',true,'');
     sendJson(res,200,{ok:true,password:value.password,hide_after_ms:30000});
    }finally{res.removeListener?.('close',closed);revealing=false;revealAfter=now()+3000;}
    return true;
   }
   if(req.method==='GET'){
    if(url.pathname==='/api/games'){
     if(url.search)throw new Error('La consulta no acepta parámetros.');
     if((!cache||Date.now()-cache.time>3000)&&!busy()&&!otherBusy()){
      pending||=securityCtl('games-status',{}).then(data=>{cache={data,time:Date.now()};return data;}).finally(()=>pending=null);await pending;
     }
     sendJson(res,200,{ok:true,...cache?.data,job,action_token:actionToken});return true;
    }
    if(url.pathname==='/api/games/console'){
     authorizeGame(req,'console');
     const cursor=url.searchParams.get('cursor')??'';
     if([...url.searchParams.keys()].some(key=>key!=='cursor')||!/^(?:[0-9]{1,20}:[0-9]{1,20})?$/.test(cursor))throw new Error('Posición de consola no válida.');
     if(busy()||otherBusy()){sendJson(res,200,{ok:true,text:'',cursor,reset:false,waiting:true});return true;}
     sendJson(res,200,await securityCtl('games-console',{cursor}));return true;
    }
   }
   if(req.method!=='POST'||!['/api/games/plan','/api/games/apply'].includes(url.pathname)){sendJson(res,405,{error:'Método no permitido.'});return true;}
   if(url.search)throw new Error('La operación no acepta parámetros en la dirección.');
   if(!requireActionToken(req)){sendJson(res,403,{error:'Autorización local inválida.'});return true;}
   const apply=url.pathname.endsWith('/apply'),body=gamePayload(await readJsonBody(req,8192,5000),apply);
   authorizeGame(req,body.action);
   if(busy()||otherBusy()){sendJson(res,409,{error:'Hay otra operación en curso. Esperá su respuesta.'});return true;}
   sendJson(res,202,{ok:true,job:launch(apply?'games-apply':'games-plan',body)});return true;
  }catch(error){sendJson(res,error.status||400,{error:String(error.message||error)});return true;}
 }
 return {handle,busy};
}
