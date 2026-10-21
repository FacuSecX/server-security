import {randomBytes} from 'node:crypto';
import {accountName,accountPassword,passwordHash,secretEqual,validateAccounts} from './panel-credentials.mjs';
const fail=(message,status=400)=>Object.assign(new Error(message),{status});
export function createEnrollment({vault,hello,now=()=>Date.now(),cooldown=3000,ready=false,onReady}){
  const tickets=new Map();let busy=false,next=0,failed=0,lockedUntil=0;
  async function state(){if(vault.protected===true&&typeof vault.status==='function'){const result=await vault.status();if(!['ready','setup','recovery'].includes(result.mode))throw fail('Estado de instalación no válido.',503);return result.mode;}return ready?'ready':'installation-required';}
  function prune(){for(const [id,v] of tickets)if(now()>v.until)tickets.delete(id);while(tickets.size>=16)tickets.delete(tickets.keys().next().value);}
  return {
    state,
    busy:()=>busy,
    async status(tab){const mode=await state();if(mode==='ready')return {mode};if(!/^[a-f0-9]{32}$/.test(tab))throw fail('Ventana de configuración no válida.');if(mode==='installation-required')return {mode};prune();const token=randomBytes(32).toString('hex');tickets.set(token,{tab,mode,until:now()+300000});return {mode,challenge:token,hello_required:true};},
    async submit(mode,body,tab,stillConnected=()=>true){
      if(busy||now()<next||now()<lockedUntil)throw fail('Esperá antes de volver a intentar.',429);
      busy=true;next=now()+cooldown;
      try{
        const fields=mode==='setup'?['challenge','username','password','confirm']:['challenge','password'];
        if(!body||Object.keys(body).some(k=>!fields.includes(k)))throw fail('Campos de configuración no válidos.');
        const ticket=tickets.get(body.challenge);tickets.delete(body.challenge);
        if(!ticket||!secretEqual(ticket.tab,tab)||ticket.mode!==mode||now()>ticket.until||await state()!==mode)throw fail('La solicitud venció. Volvé a cargar esta ventana.',409);
        let accounts;
        if(mode==='setup'){
          const username=accountName(body.username);if(!username)throw fail('El usuario debe tener entre 3 y 32 letras, números, puntos, guiones o guiones bajos.');
          const value=accountPassword(body.password);if(!secretEqual(value,body.confirm))throw fail('Las contraseñas no coinciden.');
          accounts={version:1,users:[{id:'primary-admin',username,primary:true,must_change:false,...await passwordHash(value)}]};
        }else{
          const snapshot=validateAccounts(await vault.recoverySnapshot());
          const master=snapshot.users.find(u=>u.primary),value=accountPassword(body.password);
          if(!secretEqual((await passwordHash(value,master.salt)).hash,master.hash)){
            failed++;lockedUntil=now()+(failed>=5?Math.min(900000,30000*2**Math.min(failed-5,5)):0);throw fail('No se pudo verificar la contraseña actual del administrador.',401);
          }
          accounts=structuredClone(snapshot);
        }
        // The native broker verifies a signed, single-use challenge from the original owner's key.
        // A caller-supplied boolean, SID or public key is never accepted by these endpoints.
        if(await hello.verify(undefined,mode)!==true)throw fail('Windows Hello no autorizó la operación.',403);
        if(!stillConnected()||await state()!==mode)throw fail('La configuración cambió antes de completar la operación.',409);
        if(mode==='setup')await vault.initialize(accounts);else await vault.recover();
        const stored=validateAccounts(await vault.load());
        if(JSON.stringify(stored)!==JSON.stringify(accounts))throw fail('No se pudo comprobar el almacén guardado.',503);
        ready=true;failed=0;tickets.clear();await onReady(stored);return {ok:true,login_required:true};
      }finally{busy=false;next=Math.max(next,now()+cooldown);}
    }
  };
}
