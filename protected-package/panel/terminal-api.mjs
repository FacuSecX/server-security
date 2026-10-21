import {randomBytes,timingSafeEqual} from 'node:crypto';
import {readJsonBody} from './http-input.mjs';

const failure=(message,status=400)=>Object.assign(new Error(message),{status});
const matches=(a,b)=>typeof a==='string'&&typeof b==='string'&&/^[a-f0-9]{64}$/.test(a)&&a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));

export function createTerminalApi({auth,hello,execute,sendJson,clock=()=>Date.now()}) {
  const grants=new WeakMap(),attempts=new WeakMap(),epochs=new WeakMap();
  let verification=null,executing=false,nextCommand=0;
  function principal(request) {
    if(!auth.canAct(request))throw failure('Ingresá nuevamente al panel.',401);
    const session=auth.session(request),user=request.panelUser;
    if(!session||session.userId!=='primary-admin'||user?.id!=='primary-admin'||user.administrator!==true)
      throw failure('La terminal sólo está disponible para el administrador principal.',403);
    return session;
  }
  const epoch=s=>epochs.get(s)||0;
  function revoke(session) {
    if(!session)return;
    grants.delete(session);epochs.set(session,epoch(session)+1);
    if(verification?.session===session)verification.abort.abort();
  }
  function grantFor(session,token) {
    const grant=grants.get(session);
    if(!grant||clock()>=grant.until||grant.epoch!==epoch(session)||!matches(token,grant.token))return null;
    return grant;
  }
  function observe(request,response,url) {
    if(request.method!=='POST'||!['/api/auth/leave','/api/auth/logout','/api/auth/password','/api/auth/pulse'].includes(url.pathname))return;
    const session=auth.session(request);if(!session)return;
    response.once('finish',()=>{
      if(response.statusCode>=200&&response.statusCode<300&&(url.pathname!=='/api/auth/pulse'||session.background===true))revoke(session);
    });
  }
  async function empty(request) {
    const body=await readJsonBody(request,512,5000);
    if(Object.keys(body).length)throw failure('La solicitud no admite parámetros.');
  }
  async function handle(request,response,url) {
    if(url.pathname!=='/api/terminal'&&!url.pathname.startsWith('/api/terminal/'))return false;
    try {
      const session=principal(request);
      if(url.pathname==='/api/terminal'&&request.method==='GET') {
        const available=await hello.availability(),grant=grants.get(session);
        sendJson(response,200,{ok:true,available:available.available===true,availability_code:available.result,
          unlocked:!!grant&&clock()<grant.until,verifying:verification?.session===session,
          expires_at:grant?.until||0,cooldown_ms:Math.max(0,nextCommand-clock())});
        return true;
      }
      if(url.pathname==='/api/terminal/lock'&&request.method==='POST') {
        await empty(request);revoke(session);sendJson(response,200,{ok:true});return true;
      }
      if(url.pathname==='/api/terminal/unlock'&&request.method==='POST') {
        await empty(request);
        if(verification)throw failure('Ya hay una verificación de Windows Hello en curso.',429);
        if(clock()<(attempts.get(session)||0))throw failure('Esperá tres segundos antes de solicitar otra verificación.',429);
        revoke(session);const version=epoch(session),abort=new AbortController();
        verification={session,abort};attempts.set(session,clock()+3000);
        try {
          const verified=await hello.verify(abort.signal);
          if(verified!==true||principal(request)!==session||epoch(session)!==version)
            throw failure('La autorización de terminal dejó de estar vigente.',403);
          const grant={token:randomBytes(32).toString('hex'),until:clock()+300000,epoch:version,seen:new Set()};
          grants.set(session,grant);
          sendJson(response,200,{ok:true,grant:grant.token,expires_at:grant.until});
        } finally {verification=null;attempts.set(session,clock()+3000);}
        return true;
      }
      if(url.pathname==='/api/terminal/execute'&&request.method==='POST') {
        const body=await readJsonBody(request,16384,5000);
        const grant=grantFor(session,body.grant);
        if(!grant)throw failure('Verificá tu identidad con Windows Hello para abrir la terminal.',403);
        if(Object.keys(body).length!==3||Object.keys(body).some(k=>!['command','id','grant'].includes(k))||
          typeof body.id!=='string'||!/^[a-f0-9]{32}$/.test(body.id)||
          typeof body.command!=='string'||!body.command.trim()||Buffer.byteLength(body.command)>8192||
          /[\x00-\x08\x0b-\x1f\x7f]/.test(body.command))
          throw failure('Comando o identificador de solicitud no válido.');
        if(executing||clock()<nextCommand)throw failure('Esperá la respuesta y tres segundos antes de enviar otro comando.',429);
        if(principal(request)!==session||!grantFor(session,body.grant))throw failure('La terminal se bloqueó.',403);
        if(grant.seen.has(body.id))throw failure('Este comando ya fue recibido. No se ejecutó nuevamente.',409);
        if(grant.seen.size>=128)grant.seen.delete(grant.seen.values().next().value);
        grant.seen.add(body.id);executing=true;
        try {sendJson(response,200,{ok:true,id:body.id,...await execute(body.command,()=>{if(principal(request)!==session||!grantFor(session,body.grant))throw failure("La autorización de terminal venció antes de enviar el comando.",403);})});}
        finally {executing=false;nextCommand=clock()+3000;}
        return true;
      }
      throw failure('Ruta de terminal no disponible.',404);
    } catch(error) {sendJson(response,error.status||400,{error:error.message||'No se pudo completar la solicitud de terminal.'});return true;}
  }
  return {handle,observe,busy:()=>executing||verification!==null};
}