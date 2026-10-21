import {spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {join} from 'node:path';
import {protectedRuntime,createProtectedHello} from './protected-runtime.mjs';
export function createWindowsHello(root,{spawnProcess=spawn,platform=process.platform}={}) {
  if(protectedRuntime&&spawnProcess===spawn)return createProtectedHello();
  let pending=false,cache=null;
  async function invoke(action,signal,purpose='terminal'){
    if(!['terminal','users'].includes(purpose))throw new Error('Solicitud de Windows Hello no válida.');
    if(platform!=='win32')throw new Error('Windows Hello requiere Windows.');
    if(pending)throw Object.assign(new Error('Ya hay una verificación de Windows Hello en curso.'),{status:429});
    signal?.throwIfAborted();pending=true;
    try{return await new Promise((resolve,reject)=>{
      const nonce=randomBytes(32).toString('hex');
      const child=spawnProcess('powershell.exe',['-NoProfile','-NonInteractive','-STA','-ExecutionPolicy','Bypass','-File',join(root,'windows-hello.ps1'),'-Purpose',purpose,'-Action',action],{windowsHide:true,stdio:['pipe','pipe','pipe']});
      let output='',settled=false;
      const finish=(error,result)=>{if(settled)return;settled=true;clearTimeout(timer);signal?.removeEventListener('abort',abort);error?reject(error):resolve(result);};
      const abort=()=>{child.kill();finish(new Error('Verificación de Windows Hello cancelada.'));};
      const timer=setTimeout(()=>{child.kill();finish(new Error('Windows Hello superó el tiempo de espera.'));},action==='verify'?100000:15000);
      signal?.addEventListener('abort',abort,{once:true});
      child.stdout.on('data',chunk=>{output+=chunk;if(output.length>4096){child.kill();finish(new Error('Respuesta de Windows Hello no válida.'));}});
      child.stderr.resume();child.stdin.on('error',()=>{});
      child.once('error',()=>finish(new Error('No se pudo iniciar Windows Hello.')));
      child.once('close',code=>{if(settled)return;try{const value=JSON.parse(output);if(code!==0||value.nonce!==nonce||!Number.isInteger(value.result)||typeof value.verified!=='boolean'||typeof value.available!=='boolean')throw new Error();finish(null,value);}catch{finish(new Error('Windows Hello no pudo comprobar la identidad.'));}});
      child.stdin.end(nonce);
    });}finally{pending=false;}
  }
  return {
    async availability(){if(cache&&Date.now()-cache.at<60000)return cache.value;try{const value=await invoke('check');cache={at:Date.now(),value};return value;}catch{return {available:false,verified:false,result:-1};}},
    async verify(signal,purpose='terminal'){const value=await invoke('verify',signal,purpose);if(!value.verified||value.result!==0)throw new Error(({1:'Windows Hello no está disponible en este equipo.',2:'Configurá Windows Hello en las opciones de inicio de sesión de Windows.',3:'La política de Windows impide usar Hello.',4:'Windows Hello está ocupado. Intentá nuevamente.',5:'Windows agotó los intentos de verificación.',6:'Verificación de Windows Hello cancelada.'})[value.result]||'Windows Hello no autorizó el acceso.');return true;}
  };
}
