/*
Server Security Monitor v2.0
Created by FacuSecX
https://github.com/FacuSecX/
*/
import {readFileSync,existsSync} from 'node:fs';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {normalizeSshConfig,sshConfigurationId,connectionArgs,createSshAuthentication} from './ssh-auth.mjs';
import {validateListen} from './local-security.mjs';

const root=dirname(fileURLToPath(import.meta.url));
const actions=new Set(['inspect','panel','check','install']);
const action=process.argv[2];
let auth=null;

async function run(file,args,options={}){
  return new Promise((resolve,reject)=>{
    const child=spawn(file,args,{windowsHide:true,stdio:'inherit',...options});
    child.once('error',()=>reject(new Error('No se pudo iniciar una dependencia. Revisá las rutas configuradas.')));
    child.once('close',code=>code===0?resolve():reject(new Error('La operación terminó con un error. Revisá la configuración y los permisos del servidor.')));
  });
}

async function main(){
  if(Number(process.versions.node.split('.')[0])<24)throw new Error('Se requiere Node.js 24 o posterior.');
  if(!actions.has(action))throw new Error('Acción de inicio no válida.');
  const config=JSON.parse(readFileSync(join(root,'config.json'),'utf8').replace(/^\uFEFF/,''));
  const ssh=normalizeSshConfig(config.ssh,root);
  const port=config.listenPort||8766,host=config.listenHost||'127.0.0.1';validateListen(host,port);
  const url='http://'+(host==='::1'?'[::1]':host)+':'+port;
  if(action==='inspect'){
    console.log(JSON.stringify({authMode:ssh.authMode,passwordEnv:ssh.passwordEnv,url,configId:sshConfigurationId(ssh),build:32}));return;
  }
  if(ssh.authMode==='key'){
    if(!ssh.keyPath||!existsSync(ssh.keyPath))throw new Error('Configurá una llave PPK existente en ssh.keyPath.');
    if(!existsSync(ssh.pageantPath))throw new Error('No se encontró Pageant. Revisá ssh.pageantPath.');
    const child=spawn(ssh.pageantPath,[ssh.keyPath],{detached:true,stdio:'ignore',windowsHide:false});
    await new Promise((resolve,reject)=>{child.once('spawn',resolve);child.once('error',()=>reject(new Error('No se pudo abrir Pageant.')));});child.unref();
    console.log('Desbloqueá la llave en Pageant si aparece la solicitud.');
    await new Promise(resolve=>setTimeout(resolve,1200));
  }
  if(action==='panel'){
    await run(process.execPath,[join(root,'server.mjs')]);return;
  }
  auth=createSshAuthentication(ssh);
  const credential=auth.prepare();
  try{
    const args=[...connectionArgs(ssh,{authenticate:true,passwordFile:credential.path}),'-share',ssh.user+'@'+ssh.host];
    if(action==='check'){
      args.push("printf 'Conexion SSH correcta\\n'; hostname; id");
      await run(ssh.plinkPath,args);return;
    }
    const files=['storypulse_trusted.py','storypulse_platform.py','storypulse_report.py','storypulse-securityctl.py',
      'storypulse_ports.py','storypulse_forwarding.py','storypulse_services.py','storypulse_mysql.py','storypulse_cleanup.py',
      'storypulse_system.py','storypulse_panel_alerts.py','server-monitor-alerts.service','storypulse-cleanup.service',
      'storypulse-cleanup.timer','instalar-forwarding.sh','instalar-control-bloqueos.sh'];
    for(const file of ['collector.py','ssh_security.ssh',...files.map(file=>join('vps',file))])
      if(!existsSync(join(root,file)))throw new Error('Faltan archivos del instalador del servidor.');
    
    args.push('umask 077; d=$(mktemp -d /tmp/storypulse-blocks.XXXXXX) || exit 1; tar -xf - -C "$d" && sudo -n sh "$d/instalar-control-bloqueos.sh" "$d/storypulse-securityctl.py"');
    const tar=spawn('tar.exe',['-cf','-','-C',root,'collector.py','ssh_security.ssh','-C',join(root,'vps'),...files],
      {windowsHide:true,stdio:['ignore','pipe','inherit']});
    const plink=spawn(ssh.plinkPath,args,{windowsHide:true,stdio:['pipe','inherit','inherit']});
    const completion=child=>new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',code=>code===0?resolve():reject(new Error('No se pudo instalar el controlador del servidor.')));});
    tar.stdout.on('error',()=>{});plink.stdin.on('error',()=>{});tar.stdout.pipe(plink.stdin);
    try{await Promise.all([completion(tar),completion(plink)]);}catch(error){tar.kill();plink.kill();throw error;}
  }finally{credential.cleanup();}
}
process.once('exit',()=>auth?.dispose());
main().catch(error=>{console.error(auth?auth.redact(error.message):error.message);process.exitCode=1;});
