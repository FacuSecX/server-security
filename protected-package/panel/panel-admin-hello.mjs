import {randomBytes,timingSafeEqual} from 'node:crypto';
const fail=(text,status=403)=>Object.assign(new Error(text),{status});
export function createAdminHello({hello,now=Date.now}){
 const grants=new WeakMap(),attempts=new WeakMap(),epochs=new WeakMap();let pending=null;
 const epoch=s=>epochs.get(s)||0;
 function revoke(s){if(!s)return;grants.delete(s);epochs.set(s,epoch(s)+1);if(pending?.session===s)pending.abort.abort();}
 function allowed(s,token){
  const grant=grants.get(s);
  return !!grant&&now()<grant.until&&grant.epoch===epoch(s)&&typeof token==='string'&&/^[a-f0-9]{64}$/.test(token)&&timingSafeEqual(Buffer.from(token),Buffer.from(grant.token));
 }
 async function unlock(s,isCurrent){
  if(pending)throw fail('Ya hay una verificación de Windows Hello en curso.',429);
  if(now()<(attempts.get(s)||0))throw fail('Esperá tres segundos antes de volver a verificar.',429);
  revoke(s);const version=epoch(s),abort=new AbortController();pending={session:s,abort};
  try{
   if(await hello.verify(abort.signal,'users')!==true||!isCurrent()||version!==epoch(s))throw fail('La autorización de administración dejó de estar vigente.');
   const grant={token:randomBytes(32).toString('hex'),until:now()+300000,epoch:version};grants.set(s,grant);
   return {ok:true,grant:grant.token,expires_at:grant.until};
  }catch(error){if(!error.status)error.status=403;throw error;}finally{pending=null;attempts.set(s,now()+3000);}
 }
 async function status(s){const value=await hello.availability(),grant=grants.get(s);return {ok:true,available:value.available===true,unlocked:!!grant&&now()<grant.until,expires_at:grant?.until||0};}
 return {revoke,allowed,unlock,status,busy:()=>pending!==null};
}