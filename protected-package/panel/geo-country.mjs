// Server Security Monitor v3.0
// Created by FacuSecX
// https://github.com/FacuSecX/
import {DatabaseSync} from 'node:sqlite';
import {isMainThread,parentPort,workerData,Worker} from 'node:worker_threads';
import {createReadStream,existsSync,readdirSync,unlinkSync,renameSync,chmodSync} from 'node:fs';
import {open,mkdir,unlink} from 'node:fs/promises';
import {join} from 'node:path';
import {createGunzip} from 'node:zlib';
import {createInterface} from 'node:readline';
import {randomBytes,createHash} from 'node:crypto';
import {countryName,ipKey} from './geo-ip.mjs';

export async function importCountryCsv(gzipPath,target,month,{minimum=10000}={}){
 const db=new DatabaseSync(target);let rows=0,total=0;
 try{
  db.exec('PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; CREATE TABLE ranges(version INTEGER,start BLOB,finish BLOB,code TEXT,PRIMARY KEY(version,start)) WITHOUT ROWID; CREATE TABLE metadata(month TEXT,count INTEGER); BEGIN');
  const insert=db.prepare('INSERT INTO ranges VALUES(?,?,?,?)');
  const input=createReadStream(gzipPath),stream=input.pipe(createGunzip());input.on('error',error=>stream.destroy(error));
  stream.on('data',data=>{total+=data.length;if(total>160*1024*1024)stream.destroy(new Error('La base de países supera el tamaño permitido.'));});
  const lines=createInterface({input:stream,crlfDelay:Infinity});
  stream.on('error',()=>lines.close());
  for await(const raw of lines){
   const line=raw.trim();if(!line)continue;if(line.length>220)throw new Error('Fila geográfica demasiado larga.');
   const match=/^"?([^",]+)"?,"?([^",]+)"?,"?([A-Z]{2})"?$/.exec(line);if(!match)throw new Error('Formato geográfico no válido.');
   const first=ipKey(match[1]),last=ipKey(match[2]);if(!first||!last||first.version!==last.version||Buffer.compare(first.key,last.key)>0)throw new Error('Intervalo de direcciones no válido.');
   if(!countryName(match[3]))continue;
   insert.run(first.version,first.key,last.key,match[3]);if(++rows>2000000)throw new Error('Demasiados intervalos geográficos.');
  }
  if(stream.errored)throw stream.errored;
  if(rows<minimum)throw new Error('La descarga geográfica está incompleta.');
  db.prepare('INSERT INTO metadata VALUES(?,?)').run(month,rows);db.exec('COMMIT; PRAGMA optimize;');return rows;
 }catch(error){try{db.exec('ROLLBACK');}catch{}throw error;}finally{db.close();}
}

export function createCountryDatabase(directory){
 let db=null,statement=null,month='',pending=null,nextCheck=0;
 function load(path){
  const candidate=new DatabaseSync(path,{readOnly:true});
  try{const meta=candidate.prepare('SELECT month,count FROM metadata').get();if(!/^\d{4}-\d{2}$/.test(meta?.month)||meta.count<10000)throw new Error('Base de países no válida.');
   const query=candidate.prepare('SELECT finish,code FROM ranges WHERE version=? AND start<=? ORDER BY start DESC LIMIT 1');
   const previous=db;db=candidate;statement=query;month=meta.month;previous?.close();
  }catch(error){candidate.close();throw error;}
 }
 for(const name of (existsSync(directory)?readdirSync(directory):[]).filter(name=>/^geo-country-\d{4}-\d{2}\.sqlite$/.test(name)).sort().reverse()){
  try{load(join(directory,name));break;}catch{}
 }
 function lookup(ip){const value=ipKey(ip);if(!statement||!value)return null;const row=statement.get(value.version,value.key);return row&&Buffer.compare(value.key,Buffer.from(row.finish))<=0?{country_code:row.code,country:countryName(row.code)}:null;}
 async function update(){
  const wanted=new Date().toISOString().slice(0,7);if(month===wanted||Date.now()<nextCheck)return false;if(pending)return pending;nextCheck=Date.now()+6*3600000;
  await mkdir(directory,{recursive:true});const temporary=join(directory,'geo-country-build-'+randomBytes(8).toString('hex'));
  pending=new Promise((resolve,reject)=>{
   const worker=new Worker(new URL(import.meta.url),{workerData:{temporary,month:wanted}});let settled=false;
   worker.on('message',data=>{if(settled)return;settled=true;if(!data.ok){reject(new Error(data.error));return;}
    try{const destination=join(directory,'geo-country-'+wanted+'.sqlite');renameSync(temporary+'.sqlite',destination);load(destination);resolve(true);
     for(const name of readdirSync(directory))if(/^geo-country-\d{4}-\d{2}\.sqlite$/.test(name)&&name!==('geo-country-'+wanted+'.sqlite'))try{unlinkSync(join(directory,name));}catch{}
    }catch(error){reject(error);}
   });
   worker.on('error',error=>{if(!settled){settled=true;reject(error);}});worker.on('exit',code=>{if(!settled){settled=true;reject(new Error('No se completó la actualización de países.'));}});
  }).finally(()=>{pending=null;});return pending;
 }
 return {lookup,update,ready:()=>!!db,month:()=>month,close:()=>{db?.close();db=null;statement=null;}};
}

if(!isMainThread&&workerData?.temporary){
 const {temporary,month}=workerData;
 try{
  if(!/^\d{4}-\d{2}$/.test(month))throw new Error('Mes no permitido.');
  const response=await fetch('https://download.db-ip.com/free/dbip-country-lite-'+month+'.csv.gz',{redirect:'error',signal:AbortSignal.timeout(120000)});
  if(!response.ok||!response.body)throw new Error('No se pudo descargar la base de países.');
  const file=await open(temporary+'.gz','wx',0o600);let size=0;const hash=createHash('sha256');
  try{for await(const chunk of response.body){size+=chunk.length;if(size>40*1024*1024)throw new Error('La descarga de países excede su límite.');hash.update(chunk);await file.write(chunk);}}finally{await file.close();}
  const count=await importCountryCsv(temporary+'.gz',temporary+'.sqlite',month);chmodSync(temporary+'.sqlite',0o600);parentPort.postMessage({ok:true,count,sha256:hash.digest('hex')});
 }catch(error){await unlink(temporary+'.sqlite').catch(()=>{});parentPort.postMessage({ok:false,error:String(error.message).slice(0,200)});}
 finally{await unlink(temporary+'.gz').catch(()=>{});}
}
