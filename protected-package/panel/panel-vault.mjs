import {spawn} from 'node:child_process';
import {createHash,randomBytes} from 'node:crypto';
import {mkdir,readFile,writeFile,rename,lstat,unlink} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {protectedRuntime,createProtectedVault} from './protected-runtime.mjs';

function powershell(script,action,directory,input='') {
  return new Promise((resolve,reject)=>{
    const child=spawn('powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',script,'-Action',action,...(directory?['-Directory',directory]:[])],{windowsHide:true,stdio:['pipe','pipe','pipe']});
    let result='',failed=false;
    const timer=setTimeout(()=>{failed=true;child.kill();reject(new Error('El almacén protegido no respondió.'));},15000);
    child.stdout.on('data',chunk=>{result+=chunk;if(result.length>1500000){failed=true;child.kill();}});
    child.stderr.resume();child.stdin.on('error',()=>{});
    child.once('error',()=>{clearTimeout(timer);reject(new Error('No se pudo iniciar la protección de Windows.'));});
    child.once('close',code=>{clearTimeout(timer);if(code||failed)reject(new Error('No se pudo abrir el almacén de cuentas protegido de Windows.'));else resolve(result.trim());});
    child.stdin.end(input);
  });
}
export async function createWindowsVault(root) {
  if(protectedRuntime)return createProtectedVault();
  if(process.platform!=='win32'||!process.env.LOCALAPPDATA)throw new Error('El acceso local protegido requiere Windows y DPAPI.');
  const id=createHash('sha256').update(resolve(root).toLowerCase()).digest('hex').slice(0,20);
  const directory=join(process.env.LOCALAPPDATA,'FacuSecX','ServerSecurityMonitor',id),script=join(root,'panel-vault.ps1');
  await mkdir(directory,{recursive:true});
  await powershell(script,'prepare',directory);
  const file=join(directory,'accounts.dpapi'),marker=join(root,'data','.panel-auth-initialized'),welcome=join(directory,'Primer-acceso.txt');
  async function safe(path){try{const stat=await lstat(path);if(stat.isSymbolicLink()||!stat.isFile()||stat.size>1048576)throw new Error('Archivo de cuentas no válido.');return true;}catch(error){if(error.code==='ENOENT')return false;throw error;}}
  const protect=async value=>Buffer.from(await powershell(script,'protect',null,Buffer.from(value).toString('base64')),'base64');
  const unprotect=async value=>Buffer.from(await powershell(script,'unprotect',null,value.toString('base64')),'base64').toString('utf8');
  return {
    directory,welcome,
    async load(){
      if(!await safe(file)){if(await safe(marker))throw new Error('Falta el almacén de cuentas. Restaurá tu respaldo; no se creará otro administrador.');return null;}
      try{return JSON.parse(await unprotect(await readFile(file)));}catch{throw new Error('El almacén de cuentas está dañado o pertenece a otro usuario de Windows.');}
    },
    async save(value){
      await safe(file);const encrypted=await protect(JSON.stringify(value));
      const temp=join(directory,'accounts-'+randomBytes(8).toString('hex')+'.tmp');
      try{await writeFile(temp,encrypted,{flag:'wx',mode:0o600});await rename(temp,file);}finally{await unlink(temp).catch(()=>{});}
      await mkdir(join(root,'data'),{recursive:true});await safe(marker);await writeFile(marker,'Windows DPAPI account store initialized\n',{mode:0o600});
    },
    async clearWelcome(){await unlink(welcome).catch(error=>{if(error.code!=='ENOENT')throw error;});}
  };
}
