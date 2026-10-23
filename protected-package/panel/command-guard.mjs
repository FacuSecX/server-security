import {AsyncLocalStorage} from 'node:async_hooks';
import {performance} from 'node:perf_hooks';
import {isIP} from 'node:net';

const protectedPaths=new Set(['/api/games/zone/plan','/api/games/zone/apply','/api/games/zone/repair','/api/games/zone/forum-credentials','/api/cloudflare/plan','/api/cloudflare/apply','/api/games/plan','/api/games/apply','/api/games/ftp/reveal','/api/catalog-services/versions','/api/catalog-services/plan','/api/catalog-services/apply','/api/service-versions','/api/ports/plan','/api/ports/apply','/api/forwarding/plan','/api/forwarding/apply',
  '/api/services/plan','/api/services/apply','/api/mysql/plan','/api/mysql/apply','/api/mysql/structure','/api/mysql/login','/api/mysql/data',
  '/api/cleanup/plan','/api/cleanup/apply','/api/server/reboot/plan','/api/server/reboot',
  '/api/authorized-ips/plan','/api/authorized-ips/apply','/api/blocks/ip','/api/blocks/provider','/api/providers/evaluate',
  '/api/reports/ssh','/api/refresh','/api/alerts/configure','/api/terminal/execute']);
const readCommands=new Set(['zone-status','cloudflare-status','status','list','ports-status','forwarding-status','services-status','mysql-status','catalog-status','games-status','games-console',
  'cleanup-status','system-metrics','trusted-status','alerts-status']);

// One administrative operation across all routes/windows. No administrative queue.
export function createCommandGuard({authorize,revalidate=authorize,sendJson,clock=()=>performance.now(),cooldownMs=3000}={}){
  const context=new AsyncLocalStorage();
  let lease=null,nextAt=0,lastInterval=cooldownMs,activeRead=null,readTail=Promise.resolve();
  const pendingReads=new Map(),readCache=new Map(),readCacheMs=3000;
  function state(){return {busy:!!lease,cooldown_ms:lease?0:Math.max(0,Math.ceil(nextAt-clock())),minimum_interval_ms:lease?.interval||lastInterval};}
  function limited(message='Esperá la respuesta de la operación en curso.'){
    const error=Object.assign(new Error(message),{status:429,retry_after:Math.max(1,Math.ceil((nextAt-clock())/1000))});
    const scope=context.getStore();if(scope)scope.failure=error;return error;
  }
  function finish(token){
    if(token.refs||lease!==token)return;
    lease=null;if(token.used){lastInterval=token.interval;nextAt=clock()+token.interval;}
  }
  function admit(interval=cooldownMs){
    if(lease)throw limited();
    if(clock()<nextAt)throw limited('Esperá '+Math.ceil((nextAt-clock())/1000)+' segundos antes de enviar otra acción.');
    const token={refs:1,used:false,interval,request:context.getStore()?.request};lease=token;return token;
  }
  function checkCurrent(request){
    if(request&&!revalidate(request))throw Object.assign(new Error("La autorización venció. Ingresá nuevamente antes de enviar una acción."),{status:401});
  }
  async function owned(token,work){
    const scope={token,failure:null,request:token.request};
    return context.run(scope,async()=>{try{return await work();}finally{token.refs--;finish(token);}});
  }
  async function track(work){
    const scope=context.getStore();
    if(!scope?.token||scope.token!==lease){
      const token=admit();return owned(token,()=>track(work));
    }
    const token=scope.token;token.refs++;token.used=true;
    try{
      // A read already running may finish; new reads cannot overtake this action.
      if(activeRead)await activeRead.catch(()=>{});
      checkCurrent(token.request);
      return await work();
    }finally{token.refs--;finish(token);}
  }
  async function request(req,res,handler){
    let url;try{url=new URL(req.url,'http://localhost');}catch{return handler();}
    const protect=(req.method==='POST'&&protectedPaths.has(url.pathname))||(req.method==='GET'&&url.pathname==='/api/ip'&&isIP((url.searchParams.get('address')||'').trim()));
    if(!protect)return context.run({failure:null,request:req},handler);
    if(!authorize(req)){sendJson(res,403,{error:'Autorización local inválida. Recargá el panel.'});return;}
    let token;
    try{token=admit(cooldownMs);token.request=req;}catch(error){res.setHeader('Retry-After',error.retry_after);sendJson(res,429,{error:error.message,retry_after:error.retry_after});return;}
    return owned(token,handler);
  }
  function touch(){const token=context.getStore()?.token;if(token&&token===lease)token.used=true;}
  function invalidate(){readCache.clear();}
  function relay(promise){return promise.catch(error=>{const scope=context.getStore();if(scope&&error.status===429)scope.failure=error;throw error;});}
  function run(command,payload,execute){
    if(!readCommands.has(command))return track(async()=>{
      try{return await execute(command,payload);}finally{invalidate();}
    });
    if(context.getStore()?.token===lease&&lease)return track(()=>execute(command,payload));
    const key=JSON.stringify(payload??null),pending=pendingReads.get(command),cached=readCache.get(command);
    if(pending){
      if(pending.key===key)return relay(pending.promise);
      return Promise.reject(limited('Hay una consulta de este tipo en curso. Esperá su respuesta.'));
    }
    if(cached&&cached.key===key&&(clock()-cached.at<readCacheMs||lease))
      return cached.error?Promise.reject(cached.error):Promise.resolve(cached.data);
    if(lease)return Promise.reject(limited());
    if(cached&&clock()-cached.at<readCacheMs)return Promise.reject(limited('Esperá 3 segundos antes de consultar otro valor.'));
    if(pendingReads.size>=8)return Promise.reject(limited('Hay varias consultas pendientes. Esperá su respuesta.'));
    const request=context.getStore()?.request;
    const promise=readTail.then(async()=>{
      checkCurrent(request);
      if(lease)throw limited();
      const task=Promise.resolve().then(()=>execute(command,payload));activeRead=task;
      try{
        const data=await task;readCache.set(command,{key,data,at:clock()});return data;
      }catch(error){readCache.set(command,{key,error,at:clock()});throw error;}
      finally{if(activeRead===task)activeRead=null;}
    }).finally(()=>pendingReads.delete(command));
    pendingReads.set(command,{key,promise});readTail=promise.catch(()=>{});return relay(promise);
  }
  return {request,track,run,touch,state,invalidate,assertCurrent:()=>checkCurrent(context.getStore()?.request),failure:()=>context.getStore()?.failure||null};
}
