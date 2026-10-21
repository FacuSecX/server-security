import {DatabaseSync,backup} from 'node:sqlite';
import {readdir,mkdir,lstat,copyFile,open} from 'node:fs/promises';
import {resolve,join,relative,isAbsolute} from 'node:path';
const source=resolve(process.argv[2]||''),destination=resolve(process.argv[3]||'');
const inside=relative(source,destination);
if(source===destination||(!inside.startsWith('..')&&!isAbsolute(inside))||!isAbsolute(source)||!isAbsolute(destination))throw new Error('Rutas de respaldo no válidas.');
async function copy(from,to){
 const info=await lstat(from);if(info.isSymbolicLink())throw new Error('El respaldo no admite enlaces.');
 if(info.isDirectory()){await mkdir(to,{recursive:true});for(const name of await readdir(from)){if(name.endsWith('-wal')||name.endsWith('-shm')||name==='.panel-auth-initialized')continue;await copy(join(from,name),join(to,name));}return;}
 if(!info.isFile())throw new Error('Archivo de respaldo no válido.');
 const file=await open(from,'r');let header=Buffer.alloc(16);try{await file.read(header,0,16,0);}finally{await file.close();}
 if(header.toString()==='SQLite format 3\0'){const db=new DatabaseSync(from,{readOnly:true});try{await backup(db,to);}finally{db.close();}}
 else await copyFile(from,to);
}
try{await copy(source,destination);}catch(error){if(error.code!=='ENOENT')throw error;}
