import {createHash} from 'node:crypto';
import {protectedRuntime,protectedCall} from './protected-runtime.mjs';
export function createGameFtpVault(ssh,{call=protectedCall,available=protectedRuntime,serverId=''}={}){
 if(serverId&&!/^[a-f0-9]{32}$/.test(serverId))throw new Error('Perfil de servidor no válido.');
 const scope=createHash('sha256').update([ssh?.host,ssh?.port??22,ssh?.user,ssh?.hostKeyFingerprint,...(serverId?[serverId]:[])].join('\n')).digest('hex');
 const check=()=>{if(!available)throw new Error('El FTP de juegos requiere el almacén protegido local. Abrí el panel desde su acceso directo.');};
 return {
  save:async value=>{check();await call('game-ftp-save',{entry:{scope,...value}});},
  load:async value=>{check();return (await call('game-ftp-load',{scope,...value})).entry;},
  clear:async id=>{if(available)await call('game-ftp-clear',{scope,...(id?{id}:{})});}
 };
}
