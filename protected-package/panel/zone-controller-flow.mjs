// Server Security Monitor v3.0
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
const names=['storypulse_zone.py','storypulse_zone_web.py','storypulse_zone_compat.php','storypulse_games.py','storypulse_webapps.py','storypulse_uninstall.py','storypulse_game_cleanup.py'];
export function createZoneControllerFlow({root,runRemote}){
 return {async execute(command,body){
  if(!['zone-status','zone-plan','zone-apply','zone-repair','zone-forum-credentials','zone-runtime-check'].includes(command))throw new Error('Acción Zone no permitida.');
  const previous=JSON.parse(readFileSync(join(root,'zone-runtime-previous.json'),'utf8'));
  const modules=names.map(name=>{
   const source=Buffer.from(readFileSync(join(root,'vps',name),'utf8').replace(/\r\n/g,'\n'));
   if(source.length>450000)throw new Error('El componente Zone supera el tamaño permitido.');
   return {name,sha256:createHash('sha256').update(source).digest('hex'),data:source.toString('base64'),previous:previous[name]||[]};
  });
  const data=Buffer.from(JSON.stringify({modules,command,body})).toString('base64');
  const script=readFileSync(join(root,'zone-runtime.py'),'utf8')+'\nmain('+JSON.stringify(data)+')\n';
  let result;
  try{result=JSON.parse(await runRemote('sudo -n /usr/bin/python3 -I -',script,['zone-apply','zone-repair'].includes(command)?30*60*1000:90000));}
  catch(error){try{throw new Error(JSON.parse(String(error.message)).error);}catch(parsed){if(!(parsed instanceof SyntaxError))throw parsed;throw error;}}
  if(result?.ok!==true)throw new Error(result?.error||'No se pudo confirmar el estado de Zone.');
  return result;
 }};
}
