// Server Security Monitor v3.0
// Created by FacuSecX
// https://github.com/FacuSecX/
export const AVATARS=Object.freeze(['astronaut','robot','ninja','fox','cat','owl','bear','panda','explorer','pilot']);
export function createProfileApi({db,readJsonBody,sendJson,canAct=()=>true,clock=Date.now}){
 db.exec('CREATE TABLE IF NOT EXISTS panel_profiles(user_id TEXT PRIMARY KEY,avatar TEXT NOT NULL)');
 const get=db.prepare('SELECT avatar FROM panel_profiles WHERE user_id=?'),save=db.prepare('INSERT INTO panel_profiles VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET avatar=excluded.avatar');
 const attempts=new Map();
 async function handle(req,res,url){
  if(url.pathname!=='/api/profile/avatar')return false;
  try{
   const user=req.panelUser;if(!user||!/^(?:primary-admin|[a-f0-9]{32})$/.test(user.id||''))throw Object.assign(new Error('Ingresá para configurar tu avatar.'),{status:401});
   if(url.search)throw new Error('La preferencia no admite parámetros en la dirección.');
   if(req.method==='GET'){const selected=get.get(user.id)?.avatar;sendJson(res,200,{ok:true,avatar:AVATARS.includes(selected)?selected:null});return true;}
   if(req.method!=='POST')throw Object.assign(new Error('Método no permitido.'),{status:405});
   const until=attempts.get(user.id)||0;if(clock()<until){res.setHeader('Retry-After',String(Math.ceil((until-clock())/1000)));throw Object.assign(new Error('Esperá tres segundos antes de volver a guardar.'),{status:429});}
   if(attempts.size>=100&&!attempts.has(user.id))attempts.delete(attempts.keys().next().value);attempts.set(user.id,clock()+3000);
   const body=await readJsonBody(req,256,3000);
   if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).length!==1||!AVATARS.includes(body.avatar))throw new Error('Elegí uno de los avatares disponibles.');
   if(!canAct(req))throw Object.assign(new Error('La sesión ya no está activa.'),{status:401});
   save.run(user.id,body.avatar);sendJson(res,200,{ok:true,avatar:body.avatar});return true;
  }catch(error){sendJson(res,error.status||400,{error:error.message});return true;}
 }
 return {handle};
}
