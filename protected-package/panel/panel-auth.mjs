import {randomBytes} from 'node:crypto';
import {createWindowsVault} from './panel-vault.mjs';
import {readJsonBody} from './http-input.mjs';
import {createWindowsHello} from './windows-hello.mjs';
import {createAdminHello} from './panel-admin-hello.mjs';
import {createEnrollment} from './panel-enrollment.mjs';
import {validateAccounts,accountName as name,accountPassword as password,passwordHash as hash,secretEqual as equal} from './panel-credentials.mjs';
import {MENU_PERMISSIONS,permissionsFor,validatePermissions,routeAllowed,routeTarget,ACCESS_TARGETS} from './panel-permissions.mjs';
const IDLE=300000,GRACE=20000,LEASE=45000;
const random=()=>randomBytes(32).toString('hex');
const error=(message,status=400)=>Object.assign(new Error(message),{status});
export async function createPanelAuth({root,serverIdentity='',serverLabel='',vault:providedVault,hello:providedHello,now=()=>Date.now(),cooldown=3000,onDenied=()=>{}}={}) {
  const vault=providedVault||await createWindowsVault(root);
  let accounts=await vault.load();
  if(accounts)validateAccounts(accounts);
  const hello=providedHello||createWindowsHello(root);
  const adminHello=createAdminHello({hello,now});
  const enrollment=createEnrollment({vault,hello,now,cooldown,ready:!!accounts,onReady:async value=>{accounts=value;}});
  const dummy=await hash(random()),sessions=new Map(),failures=new Map();let busy=false,nextAttempt=0,usersNext=0;
  const cookieName='ssm_session',publicFiles=new Set(['/login','/login.html','/auth.js','/auth.css','/personalization.js','/personalization.css','/styles.css','/server-eye.svg']);
  const userFor=session=>accounts?.users.find(u=>u.id===session?.userId);
  const redact=u=>({id:u.id,username:u.username,administrator:u.primary,must_change:u.must_change,permissions:permissionsFor(u)});
  const send=(res,status,data)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(serverIdentity?{...data,server_id:serverIdentity,server_label:serverLabel}:data));};
  function invalidate(id){for(const [key,s] of sessions)if(s.userId===id){adminHello.revoke(s);sessions.delete(key);}}
  function session(req){const token=String(req.headers.cookie||'').match(/(?:^|;\s*)ssm_session=([a-f0-9]{64})(?:;|$)/)?.[1],s=sessions.get(token);if(s&&(now()-s.activity>=IDLE||now()>s.lease||!userFor(s))){adminHello.revoke(s);sessions.delete(token);return null;}return s||null;}
  function tokenFor(req){return String(req.headers.cookie||'').match(/(?:^|;\s*)ssm_session=([a-f0-9]{64})(?:;|$)/)?.[1];}
  const tabFor=req=>String(req.headers['x-panel-tab']||'');
  function valid(req,s){return s&&equal(tabFor(req),s.tab)&&equal(String(req.headers['x-panel-csrf']||''),s.csrf);}
  function replySession(res,s){send(res,200,{ok:true,user:redact(userFor(s)),csrf:s.csrf,idle_ms:IDLE,idle_elapsed_ms:Math.max(0,now()-s.activity)});}
  async function commit(users){const next={version:1,users};await vault.save(next);accounts=next;}
  function denied(u,target,source='api'){try{onDenied(redact(u),target,source);}catch{}return error('No autorizado. Tu cuenta no tiene permiso para acceder a esta sección o función.',403);}
  async function handle(req,res,url){
    res.setHeader('Cache-Control','no-store');
    if(url.pathname==='/api/health'&&req.method==='GET')return false;
    if(publicFiles.has(url.pathname)&&(req.method==='GET'||req.method==='HEAD'))return false;
    const s=session(req);
    try{
      if(vault.protected&&accounts&&await enrollment.state()!=='ready'){accounts=null;for(const session of sessions.values())adminHello.revoke(session);sessions.clear();}
      if(url.pathname==='/api/auth/installation'&&req.method==='GET'){send(res,200,await enrollment.status(tabFor(req)));return true;}
      if(['/api/auth/setup','/api/auth/recover'].includes(url.pathname)&&req.method==='POST'){
        const body=await readJsonBody(req,2048,5000);const mode=url.pathname.endsWith('/setup')?'setup':'recovery';
        send(res,200,await enrollment.submit(mode,body,tabFor(req),()=>!res.destroyed));return true;
      }
      if(!accounts&&url.pathname.startsWith('/api/'))throw error('Completá la instalación o restaurá las cuentas desde el acceso protegido.',423);
      if(url.pathname==='/api/auth/login'&&req.method==='POST'){
        if(busy||now()<nextAttempt){res.setHeader('Retry-After',String(Math.max(1,Math.ceil((nextAttempt-now())/1000))));send(res,429,{error:'Esperá antes de volver a intentar.',retry_ms:Math.max(cooldown,nextAttempt-now())});return true;}
        busy=true;nextAttempt=now()+cooldown;
        try{
          const body=await readJsonBody(req,2048,5000),username=name(body.username),tab=body.tab;
          if(!username||typeof tab!=='string'||!/^[a-f0-9]{32}$/.test(tab)||Object.keys(body).some(k=>!['username','password','tab'].includes(k)))throw error('Usuario o contraseña incorrectos.',401);
          const value=password(body.password),failure=failures.get(username),u=accounts.users.find(u=>u.username===username);
          if(failure&&now()<failure.until){res.setHeader('Retry-After',String(Math.ceil((failure.until-now())/1000)));send(res,429,{error:'Esperá antes de volver a intentar.',retry_ms:failure.until-now()});return true;}
          const candidate=await hash(value,(u||dummy).salt);
          if(!equal(candidate.hash,(u||dummy).hash)||!u){const count=(failure?.count||0)+1;if(failures.size>=100&&!failures.has(username))failures.delete(failures.keys().next().value);failures.set(username,{count,until:now()+(count>=5?Math.min(900000,30000*2**Math.min(count-5,5)):0)});throw error('Usuario o contraseña incorrectos.',401);}
          failures.delete(username);if(s){adminHello.revoke(s);sessions.delete(tokenFor(req));}for(const [key,v] of sessions)if(now()-v.activity>=IDLE||now()>v.lease)sessions.delete(key);
          if(sessions.size>=32)sessions.delete(sessions.keys().next().value);
          const token=random(),created={userId:u.id,csrf:random(),tab,activity:now(),lease:now()+LEASE,background:false};sessions.set(token,created);
          res.setHeader('Set-Cookie',cookieName+'='+token+'; HttpOnly; SameSite=Strict; Path=/');replySession(res,created);return true;
        }finally{busy=false;nextAttempt=Math.max(nextAttempt,now()+cooldown);}
      }
      if(url.pathname==='/api/auth/session'&&req.method==='GET'){
        if(!s||!equal(tabFor(req),s.tab))throw error('Ingresá para continuar.',401);
        s.lease=now()+(s.background?IDLE:LEASE);replySession(res,s);return true;
      }
      if(url.pathname==='/api/auth/leave'&&req.method==='POST'){
        const body=await readJsonBody(req,512,3000);
        if(s&&equal(body.tab,s.tab)&&equal(body.csrf,s.csrf)){adminHello.revoke(s);s.lease=Math.min(s.lease,now()+GRACE);}
        send(res,200,{ok:true});return true;
      }
      if(!s){if(!url.pathname.startsWith('/api/')&&(req.method==='GET'||req.method==='HEAD')){res.writeHead(303,{Location:'/login'});res.end();return true;}throw error('La sesión se bloqueó. Ingresá para continuar.',401);}
      if(url.pathname==='/'||url.pathname==='/index.html')return false;
      if(!url.pathname.startsWith('/api/'))return false;
      if(!valid(req,s))throw error('La sesión no es válida para esta ventana.',401);
      if(url.pathname==='/api/auth/logout'&&req.method==='POST'){adminHello.revoke(s);sessions.delete(tokenFor(req));res.setHeader('Set-Cookie',cookieName+'=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');send(res,200,{ok:true});return true;}
      if(url.pathname==='/api/auth/pulse'&&req.method==='POST'){
        const body=await readJsonBody(req,512,3000);if(Object.keys(body).some(k=>!['active','background'].includes(k))||typeof body.active!=='boolean'||typeof body.background!=='boolean')throw error('Actividad no válida.');
        s.background=body.background;if(body.background)adminHello.revoke(s);if(body.active&&!body.background)s.activity=now();s.lease=now()+(s.background?IDLE:LEASE);send(res,200,{ok:true});return true;
      }
      if(url.pathname==='/api/auth/password'&&req.method==='POST'){
        if(busy||now()<usersNext)throw error('Esperá tres segundos antes de enviar otra acción.',429);busy=true;usersNext=now()+cooldown;
        try{const body=await readJsonBody(req,2048,5000),u=userFor(s);if(Object.keys(body).some(k=>!['current','password'].includes(k)))throw error('Campos no válidos.');
          const old=password(body.current),fresh=password(body.password);if(old===fresh)throw error('Elegí una contraseña diferente.');
          if(!equal((await hash(old,u.salt)).hash,u.hash))throw error('La contraseña actual no es correcta.',401);
          const digest=await hash(fresh);if(session(req)!==s||!valid(req,s))throw error('La sesión venció antes de guardar la contraseña.',401);await commit(accounts.users.map(v=>v.id===u.id?{...v,...digest,must_change:false}:v));
          invalidate(u.id);if(u.primary)await vault.clearWelcome();
          res.setHeader('Set-Cookie',cookieName+'=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');send(res,200,{ok:true,login_required:true});
        }finally{busy=false;usersNext=now()+cooldown;}
        return true;
      }
      const u=userFor(s);if(u.must_change)throw error('Cambiá tu contraseña temporal para acceder al panel.',403);
      if(url.pathname==='/api/auth/access-attempt'&&req.method==='POST'){
        const body=await readJsonBody(req,512,3000);
        if(Object.keys(body).length!==1||typeof body.view!=='string'||!Object.hasOwn(ACCESS_TARGETS,body.view)||body.view==='restricted-api')throw error('Sección no válida.');
        if(permissionsFor(u).includes(body.view))throw error('La sección está autorizada; no se registró ningún intento.');
        throw denied(u,body.view,'view');
      }
      if(url.pathname==='/api/auth/users/hello'||url.pathname.startsWith('/api/auth/users/hello/')){
        if(!u.primary)throw denied(u,'panel-users');
        if(url.pathname==='/api/auth/users/hello'&&req.method==='GET'){send(res,200,await adminHello.status(s));return true;}
        if(req.method!=='POST')throw error('Método no permitido.',405);
        const body=await readJsonBody(req,512,5000);if(Object.keys(body).length)throw error('La solicitud no admite parámetros.');
        if(url.pathname==='/api/auth/users/hello/lock'){adminHello.revoke(s);send(res,200,{ok:true});return true;}
        if(url.pathname==='/api/auth/users/hello/unlock'){send(res,200,await adminHello.unlock(s,()=>session(req)===s&&valid(req,s)&&userFor(s)?.primary&&!userFor(s)?.must_change));return true;}
        throw error('Ruta no encontrada.',404);
      }
      if(url.pathname==='/api/auth/users'){
        if(!u.primary)throw denied(u,'panel-users');
        if(req.method==='GET'){send(res,200,{ok:true,users:accounts.users.map(redact),menus:MENU_PERMISSIONS});return true;}
        if(req.method!=='POST')throw error('Método no permitido.',405);
        const body=await readJsonBody(req,8192,5000);
        if(!adminHello.allowed(s,body.hello_grant))throw error('Verificá tu identidad con Windows Hello para gestionar usuarios.',403);
        if(busy||now()<usersNext)throw error('Esperá tres segundos antes de enviar otra acción.',429);busy=true;usersNext=now()+cooldown;
        try{
          const fields=body.action==='permissions'?['action','username','permissions','hello_grant']:body.action==='create'?['action','username','password','permissions','hello_grant']:['action','username','password','hello_grant'];
          if(Object.keys(body).some(k=>!fields.includes(k)))throw error('Campos no válidos.');
          const stillAllowed=()=>{if(session(req)!==s||!valid(req,s)||!adminHello.allowed(s,body.hello_grant))throw error('La autorización de administración venció.',403);};
          const save=async users=>{stillAllowed();await commit(users);};
          const username=name(body.username),target=accounts.users.find(v=>v.username===username);if(!username)throw error('El usuario debe tener entre 3 y 32 letras, números, puntos, guiones o guiones bajos.');
          if(body.action==='create'){if(target)throw error('Ese usuario ya existe.');if(accounts.users.length>=100)throw error('Se alcanzó el máximo de 100 usuarios.');const permissions=validatePermissions(body.permissions??[]),digest=await hash(password(body.password));await save([...accounts.users,{id:randomBytes(16).toString('hex'),username,primary:false,must_change:true,permissions,...digest}]);}
          else if(['delete','reset'].includes(body.action)){if(!target||target.primary)throw error('El administrador principal se conserva. Para cambiar su contraseña usá Mi contraseña.');if(body.action==='delete')await save(accounts.users.filter(v=>v.id!==target.id));else{const digest=await hash(password(body.password));await save(accounts.users.map(v=>v.id===target.id?{...v,...digest,must_change:true}:v));}invalidate(target.id);}
          else if(body.action==='permissions'){if(!target||target.primary)throw error('Los permisos del administrador principal no se pueden modificar.');const permissions=validatePermissions(body.permissions);await save(accounts.users.map(v=>v.id===target.id?{...v,permissions}:v));invalidate(target.id);}
          else throw error('Acción no válida.');failures.delete(username);send(res,200,{ok:true,users:accounts.users.map(redact)});return true;
        }finally{busy=false;usersNext=now()+cooldown;}
      }
      if(url.pathname.startsWith('/api/auth/'))throw error('Ruta no encontrada.',404);
      if(!routeAllowed(u,url.pathname))throw denied(u,routeTarget(url.pathname));
      req.panelUser=redact(u);return false;
    }catch(failure){send(res,failure.status||500,{error:failure.status?failure.message:'No se pudo completar la operación local.'});return true;}
  }
  return {handle,session,ready:()=>!!accounts,sessionActive:s=>!!s&&[...sessions.values()].includes(s)&&now()-s.activity<IDLE&&now()<=s.lease&&!!userFor(s),busy:()=>adminHello.busy()||enrollment.busy(),canAct:req=>{const s=session(req);return valid(req,s)&&!userFor(s)?.must_change;},welcome:vault.welcome};
}
