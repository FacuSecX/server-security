import {spawn} from 'node:child_process';
import {join,resolve} from 'node:path';
import {watch} from 'node:fs';
export const protectedRuntime=process.platform==='win32'&&!!process.env.SSM_PROTECTED_ROOT;
export function protectedPaths(){
  const data=join(process.env.ProgramData||'C:\\ProgramData','FacuSecX','ServerSecurityMonitor','ProtectedV2');
  const host=join(process.env.ProgramFiles||'C:\\Program Files','FacuSecX','ServerSecurityMonitor','native','FacuSecX.MonitorHost.exe');
  if(!protectedRuntime||resolve(process.env.SSM_PROTECTED_ROOT).toLowerCase()!==resolve(data).toLowerCase()||resolve(process.env.SSM_PROTECTED_HOST||'').toLowerCase()!==resolve(host).toLowerCase())throw new Error('Ubicación del servicio protegido no válida.');
  return {data,host};
}
export async function protectedCall(op,data={},signal){
  const {host}=protectedPaths();
  return new Promise((resolve,reject)=>{
    signal?.throwIfAborted();const child=spawn(host,['rpc'],{windowsHide:true,stdio:['pipe','pipe','pipe']});let output='',done=false;
    const finish=(err,value)=>{if(done)return;done=true;clearTimeout(timer);signal?.removeEventListener('abort',abort);err?reject(err):resolve(value);};
    const abort=()=>{child.kill();finish(new Error('Operación protegida cancelada.'));};
    const timer=setTimeout(abort,op==='hello-verify'?105000:20000);signal?.addEventListener('abort',abort,{once:true});
    child.stdout.on('data',chunk=>{output+=chunk;if(output.length>1500000)abort();});child.stderr.resume();child.stdin.on('error',()=>{});
    child.once('error',()=>finish(new Error('No se pudo iniciar el servicio de protección.')));
    child.once('close',code=>{try{const result=JSON.parse(output);if(code!==0||result.ok!==true)throw new Error();finish(null,result);}catch{finish(new Error(op==='game-ftp-save'||op==='game-ftp-clear'?'No se pudo actualizar la credencial FTP protegida de este servidor.':'No se pudo completar la operación protegida. Abrí el panel desde su acceso directo y verificá Windows Hello.'));}});
    child.stdin.end(JSON.stringify({op,...data}));
  });
}
export function createProtectedVault(){
  let cached=null,pending=null;const {data}=protectedPaths();
  const invalidate=()=>{cached=null;};
  const watcher=watch(data,{persistent:false},(event,name)=>{if(!name||/^(accounts|checkpoint)\./.test(String(name)))invalidate();});watcher.on('error',invalidate);
  async function status(){if(cached&&Date.now()-cached.at<10000)return cached.value;if(pending)return pending;pending=protectedCall('vault-status').then(value=>{cached={at:Date.now(),value};return value;}).finally(()=>{pending=null;});return pending;}
  async function mutate(op,accounts){invalidate();try{return await protectedCall(op,accounts?{accounts}:{});}finally{invalidate();}}
  return {
  welcome:null,protected:true,
  status,
  load:async()=>(await protectedCall('vault-load')).accounts,
  recoverySnapshot:async()=>(await protectedCall('vault-backup')).accounts,
  initialize:accounts=>mutate('vault-enroll',accounts),
  recover:()=>mutate('vault-recover'),
  save:accounts=>mutate('vault-save',accounts),
  clearWelcome:async()=>{}
};}
export function createProtectedHello(){let cache=null;return {
  availability:async()=>{if(cache&&Date.now()-cache.at<(cache.value.available?30000:2000))return cache.value;try{const value=await protectedCall('hello-check');cache={at:Date.now(),value};return value;}catch{return {available:false,verified:false,result:-1};}},
  verify:async(signal,purpose='terminal')=>{const result=await protectedCall('hello-verify',{purpose},signal);if(!result.verified||result.result!==0)throw new Error('Windows Hello no autorizó esta operación.');return true;}
};}
