import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {createHash} from 'node:crypto';

const names=['storypulse_webapps.py','storypulse_catalog.py'];
const actions=new Set(['install','upgrade','start','restart']);
export function needsWebappController(command,payload){
 return ['catalog-plan','catalog-apply'].includes(command)&&['phpmyadmin','wordpress'].includes(payload?.service)&&actions.has(payload?.action);
}
export function createWebappControllerFlow({root,runRemote,readFile=readFileSync}){
 async function ensure(command,payload){
  if(!needsWebappController(command,payload))return;
  // Never cache across actions: a VPS can be reinstalled at the same address.
  const modules=names.map(name=>{
   const source=Buffer.from(readFile(join(root,'vps',name),'utf8').replace(/\r\n/g,'\n'),'utf8');
   if(!source.length||source.length>384000)throw new Error('El paquete local del instalador web está incompleto.');
   return {name,sha256:createHash('sha256').update(source).digest('hex'),data:source.toString('base64')};
  });
  const script=readFile(join(root,'webapp-runtime-sync.py'),'utf8');
  const encoded=Buffer.from(JSON.stringify({modules}),'utf8').toString('base64');
  let result;
  try{
   const raw=await runRemote('sudo -n /usr/bin/python3 -I -',script+'\nmain('+JSON.stringify(encoded)+')\n',30000);
   result=JSON.parse(raw);
  }catch(error){
   let detail='';try{detail=JSON.parse(String(error.message)).error||'';}catch{}
   throw new Error('No se pudo preparar el instalador web actualizado. La instalación no comenzó.'+(detail?' '+detail:''));
  }
  if(result?.ok!==true||modules.some(row=>result.hashes?.[row.name]!==row.sha256))throw new Error('El servidor no confirmó la versión actual del instalador web. La instalación no comenzó.');
  return result;
 }
 return {ensure};
}
