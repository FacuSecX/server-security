import {createHash,timingSafeEqual} from 'node:crypto';
import {join} from 'node:path';
import {existsSync,lstatSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';

export function serverScope({base,root,config,metadata=null}){
  if(!metadata)return {id:'',label:'',data:join(base,'data'),reports:join(base,'Informes','SSH','archivos'),approvals:join(root,'provider-approvals.json'),preferences:join(base,'panel-preferences.db')};
  const profile=typeof metadata==='string'?JSON.parse(metadata):metadata;
  if(!/^[a-f0-9]{32}$/.test(profile?.id||'')||typeof profile.label!=='string'||profile.label.length>80||typeof profile.legacy!=='boolean'||!profile.ssh)throw new Error('El perfil del servidor no es válido. No se cargó otro historial.');
  const scoped=profile.legacy?base:join(base,'servers',profile.id);
  for(const path of [base,join(base,'servers'),scoped])if(existsSync(path)&&lstatSync(path).isSymbolicLink())throw new Error('La carpeta del servidor no admite redirecciones.');
  const data=join(scoped,'data');mkdirSync(data,{recursive:true});
  if(lstatSync(data).isSymbolicLink())throw new Error('La carpeta de datos no es válida.');
  const binding={id:profile.id,connection:createHash('sha256').update(JSON.stringify([profile.ssh.host,profile.ssh.port,profile.ssh.user,profile.ssh.hostKeyFingerprint])).digest('hex')};
  const marker=join(data,'.server-owner.json');
  if(existsSync(marker)){
    if(lstatSync(marker).isSymbolicLink()||JSON.stringify(JSON.parse(readFileSync(marker,'utf8')))!==JSON.stringify(binding))throw new Error('Este historial pertenece a otra conexión. No se cargaron sus estadísticas.');
  }else writeFileSync(marker,JSON.stringify(binding),{flag:'wx',mode:0o600});
  config.ssh={...profile.ssh};
  if(!profile.legacy)config.trustedSshIps=[];
  return {id:profile.id,label:profile.label,legacy:profile.legacy,data,reports:join(scoped,'Informes','SSH','archivos'),approvals:profile.legacy?join(root,'provider-approvals.json'):join(scoped,'provider-approvals.json'),preferences:join(base,'panel-preferences.db')};
}

export function createServerSwitch({token='',safe=()=>false}={}){
  let paused=false,posts=0;
  function track(req,res){if(req.method!=='POST')return;posts++;let done=false;const finish=()=>{if(!done){done=true;posts--;}};res.once('finish',finish);res.once('close',finish);}
  function suspend(value){
    if(!/^[a-f0-9]{64}$/.test(token)||typeof value!=='string'||value.length!==64||!timingSafeEqual(Buffer.from(token),Buffer.from(value)))return 403;
    if(paused)return 200;
    if(posts||!safe())return 409;
    paused=true;return 200;
  }
  function assert(){if(paused)throw Object.assign(new Error('El panel está cambiando de servidor. Volvé a ingresar desde el selector.'),{status:409});}
  return {track,suspend,assert,paused:()=>paused};
}
