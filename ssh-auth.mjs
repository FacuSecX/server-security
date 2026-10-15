/*
Server Security Monitor v2.0
Created by FacuSecX
https://github.com/FacuSecX/
*/
import {createHash,randomBytes} from 'node:crypto';
import {isIP} from 'node:net';
import {domainToASCII,fileURLToPath} from 'node:url';
import {dirname,isAbsolute,join,resolve} from 'node:path';
import {existsSync,mkdtempSync,writeFileSync,unlinkSync,rmdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';

const protectedVariables=new Set(['PATH','HOME','USERPROFILE','SYSTEMROOT','WINDIR','COMSPEC','TEMP','TMP','PATHEXT','NODE_OPTIONS','PSMODULEPATH','CODEX_HOME']);
const privateAclScript=fileURLToPath(new URL('./protect-ssh-secret.ps1',import.meta.url));
const connectionNamespaces=new WeakMap();

export function normalizeSshConfig(value,root=process.cwd()){
  if(!value||typeof value!=='object'||Array.isArray(value))throw new Error('Completá la sección ssh de config.json.');
  const mode=value.authMode??'key';
  if(!['key','password'].includes(mode))throw new Error('ssh.authMode debe ser key o password.');
  if(Object.hasOwn(value,'password'))throw new Error('No guardes la contraseña en config.json. Usá ssh.passwordEnv o ingresala oculta al iniciar.');
  const host=typeof value.host==='string'?value.host.trim():'';
  if(/[\x00-\x20\x7f]/.test(host))throw new Error('ssh.host contiene caracteres no válidos.');
  const ascii=domainToASCII(host);
  if(!isIP(host)&&(!ascii||ascii.length>253||!ascii.split('.').every(label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))))
    throw new Error('ssh.host debe ser una IP o un nombre de servidor válido.');
  if(typeof value.user!=='string'||!/^[a-z_][a-z0-9_.-]{0,63}\$?$/i.test(value.user))throw new Error('ssh.user no es válido.');
  const port=value.port??22;
  if(!Number.isInteger(port)||port<1||port>65535)throw new Error('ssh.port debe ser un número entre 1 y 65535.');
  if(typeof value.hostKeyFingerprint!=='string'||!/^SHA256:[A-Za-z0-9+/]{43}=?$/.test(value.hostKeyFingerprint))
    throw new Error('Configurá la huella SHA256 real del servidor en ssh.hostKeyFingerprint.');
  const passwordEnv=value.passwordEnv??'SERVER_MONITOR_SSH_PASSWORD';
  if(typeof passwordEnv!=='string'||!/^[A-Z][A-Z0-9_]{0,63}$/.test(passwordEnv)||protectedVariables.has(passwordEnv))throw new Error('ssh.passwordEnv debe nombrar una variable propia para la contraseña.');
  const programFiles=process.env.ProgramFiles||'C:\\Program Files';
  function executable(raw,fallback){
    const name=raw??fallback;
    if(typeof name!=='string'||!name||/[\x00-\x1f\x7f]/.test(name))throw new Error('Ruta de PuTTY no válida.');
    return isAbsolute(name)||!/[\\/]/.test(name)?name:resolve(root,name);
  }
  const plinkPath=executable(value.plinkPath,join(programFiles,'PuTTY','plink.exe'));
  const pageantPath=mode==='password'&&!value.pageantPath?'':executable(value.pageantPath,/[\\/]/.test(plinkPath)?join(dirname(plinkPath),'pageant.exe'):join(programFiles,'PuTTY','pageant.exe'));
  if(value.keyPath!==undefined&&(typeof value.keyPath!=='string'||/[\x00-\x1f\x7f]/.test(value.keyPath)))throw new Error('ssh.keyPath no es válido.');
  const keyPath=value.keyPath?resolve(root,value.keyPath):'';
  return {...value,host:isIP(host)?host:ascii,user:value.user,port,authMode:mode,passwordEnv,plinkPath,pageantPath,keyPath};
}

export function sshConfigurationId(ssh){
  return createHash('sha256').update(JSON.stringify([ssh.host,ssh.port,ssh.user,ssh.authMode,ssh.keyPath,ssh.plinkPath,ssh.pageantPath,ssh.hostKeyFingerprint,ssh.passwordEnv])).digest('hex');
}

export function connectionArgs(ssh,{authenticate=false,passwordFile=null}={}){
  const args=['-batch',authenticate&&ssh.authMode==='key'?'-agent':'-noagent','-ssh','-P',String(ssh.port),'-hostkey',ssh.hostKeyFingerprint];
  if(ssh.authMode==='password'){
    
    
    if(!connectionNamespaces.has(ssh))connectionNamespaces.set(ssh,'server-monitor-password-'+randomBytes(12).toString('hex')+'.invalid');
    args.push('-loghost',connectionNamespaces.get(ssh));
  }
  if(authenticate){
    args.push('-no-trivial-auth');
    if(ssh.authMode==='key'&&ssh.keyPath){
      if(!existsSync(ssh.keyPath))throw new Error('No se encontró la llave indicada en ssh.keyPath.');
      args.push('-i',ssh.keyPath);
    }else if(ssh.authMode==='password'){
      if(typeof passwordFile!=='string'||!passwordFile)throw new Error('Falta preparar la contraseña SSH. Iniciá el panel con iniciar-panel.bat.');
      args.push('-pwfile',passwordFile);
    }
  }
  return args;
}

export function createSshAuthentication(ssh,{environment=process.env,platform=process.platform,temporaryRoot=tmpdir(),restrictDirectory}={}){
  let password=ssh.authMode==='password'?environment[ssh.passwordEnv]:undefined;
  if(ssh.authMode==='password')delete environment[ssh.passwordEnv];
  const files=new Set();
  const redact=value=>password?String(value).split(password).join('[contraseña oculta]'):String(value);
  function prepare(){
    if(ssh.authMode!=='password')return {path:null,cleanup(){}};
    if(typeof password!=='string'||!password.length||password.length>1024||/[\r\n\x00]/.test(password))
      throw new Error('Falta una contraseña SSH válida. Usá iniciar-panel.bat o la variable '+ssh.passwordEnv+'.');
    const folder=mkdtempSync(join(temporaryRoot,'server-monitor-ssh-')),file=join(folder,'password');
    const cleanup=()=>{try{unlinkSync(file);}catch{}try{rmdirSync(folder);}catch{}files.delete(cleanup);};
    try{
      
      if(restrictDirectory)restrictDirectory(folder);
      else if(platform==='win32'){
        const result=spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',privateAclScript,'-Directory',folder],
          {windowsHide:true,encoding:'utf8',timeout:10000});
        if(result.error||result.status!==0)throw new Error('No se pudieron proteger los permisos de la contraseña temporal.');
      }
      writeFileSync(file,password+'\n',{encoding:'utf8',mode:0o600,flag:'wx'});files.add(cleanup);
      return {path:file,cleanup};
    }catch(error){cleanup();throw error;}
  }
  function dispose(){for(const cleanup of [...files])cleanup();password=undefined;}
  return {prepare,redact,dispose};
}
