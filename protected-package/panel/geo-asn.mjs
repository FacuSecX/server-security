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
import {ipKey} from './geo-ip.mjs';


export function csvFields(line){
 const result=[];let field='',quoted=false,closed=false;
 for(let i=0;i<line.length;i++){
  const char=line[i];
  if(char==='"'){
   if(quoted&&line[i+1]==='"'){field+='"';i++;}
   else if(quoted){quoted=false;closed=true;}
   else if(field||closed)throw new Error('CSV de proveedores no válido.');
   else quoted=true;
  }else if(char===','&&!quoted){result.push(field);field='';closed=false;}
  else{if(closed)throw new Error('CSV de proveedores no válido.');field+=char;}
 }
 if(quoted)throw new Error('CSV de proveedores incompleto.');result.push(field);return result;
}

export async function importAsnCsv(gzipPath,target,month,{minimum=10000,format="csv"}={}){
 const db=new DatabaseSync(target);let rows=0,total=0,input,stream;
 try{
  db.exec('PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; CREATE TABLE ranges(version INTEGER,start BLOB,finish BLOB,asn INTEGER,organization TEXT,PRIMARY KEY(version,start)) WITHOUT ROWID; CREATE TABLE metadata(month TEXT,count INTEGER); BEGIN');
  const insert=db.prepare('INSERT INTO ranges VALUES(?,?,?,?,?)');
  input=createReadStream(gzipPath);stream=input.pipe(createGunzip());input.on('error',error=>stream.destroy(error));
  stream.on('data',data=>{total+=data.length;if(total>160*1024*1024)stream.destroy(new Error('La base de proveedores supera el tamaño permitido.'));});
  const lines=createInterface({input:stream,crlfDelay:Infinity});
  stream.on('error',()=>lines.close());
  for await(const raw of lines){
   const line=raw.trim();if(!line)continue;if(line.length>8192)throw new Error('Fila de proveedores demasiado larga.');
   const rawFields=format==='tsv'?line.split('\t'):csvFields(line);if((format==='tsv'&&rawFields.length!==5)||(format!=='tsv'&&rawFields.length!==4))throw new Error('Formato de proveedores no válido.');
   const fields=format==='tsv'?[rawFields[0],rawFields[1],rawFields[2],rawFields[4]]:rawFields;if(fields.length!==4)throw new Error('Formato de proveedores no válido.');
   const first=ipKey(fields[0]),last=ipKey(fields[1]),asn=Number(fields[2]);
   if(!first||!last||first.version!==last.version||Buffer.compare(first.key,last.key)>0||!/^\d{1,10}$/.test(fields[2])||!Number.isSafeInteger(asn)||asn<0||asn>4294967295)throw new Error('Intervalo o ASN no válido.');
   if(asn===0)continue;
   if(!fields[3]||/[\x00-\x1f\x7f]/.test(fields[3]))throw new Error('Nombre de organización no válido.');
   insert.run(first.version,first.key,last.key,asn,fields[3].slice(0,240));if(++rows>2000000)throw new Error('Demasiados intervalos de proveedores.');
  }
  if(stream.errored)throw stream.errored;
  if(rows<minimum)throw new Error('La descarga de proveedores está incompleta.');
  db.prepare('INSERT INTO metadata VALUES(?,?)').run(month,rows);db.exec('COMMIT; PRAGMA optimize;');return rows;
 }catch(error){try{db.exec('ROLLBACK');}catch{}throw error;}finally{input?.destroy();stream?.destroy();db.close();}
}

export function createAsnDatabase(directory,{source='dbip'}={}){
 if(!['dbip','iptoasn'].includes(source))throw new Error('Fuente de proveedores no permitida.');
 const secondary=source==='iptoasn',prefix=secondary?'geo-asn-secondary-':'geo-asn-';
 const datePattern=secondary?/^\d{4}-\d{2}-\d{2}$/:/^\d{4}-\d{2}$/;
 const matches=name=>name.startsWith(prefix)&&name.endsWith('.sqlite')&&datePattern.test(name.slice(prefix.length,-7));
 let db=null,statement=null,month='',pending=null,nextCheck=0;
 function load(path){
  const candidate=new DatabaseSync(path,{readOnly:true});
  try{const meta=candidate.prepare('SELECT month,count FROM metadata').get();if(!datePattern.test(meta?.month)||meta.count<10000)throw new Error('Base de proveedores no válida.');
   const query=candidate.prepare('SELECT finish,asn,organization FROM ranges WHERE version=? AND start<=? ORDER BY start DESC LIMIT 1');
   const previous=db;db=candidate;statement=query;month=meta.month;previous?.close();
  }catch(error){candidate.close();throw error;}
 }
 for(const name of (existsSync(directory)?readdirSync(directory):[]).filter(name=>matches(name)).sort().reverse()){
  try{load(join(directory,name));break;}catch{}
 }
 function lookup(ip){const value=ipKey(ip);if(!statement||!value)return null;const row=statement.get(value.version,value.key);return row&&Buffer.compare(value.key,Buffer.from(row.finish))<=0?{asn:'AS'+row.asn,isp:row.organization}:null;}
 async function update(){
  const wanted=new Date().toISOString().slice(0,secondary?10:7);if(pending)return pending;if(month===wanted||Date.now()<nextCheck)return false;nextCheck=Date.now()+6*3600000;
  await mkdir(directory,{recursive:true});const temporary=join(directory,prefix+'build-'+randomBytes(8).toString('hex'));
  pending=new Promise((resolve,reject)=>{
   const worker=new Worker(new URL(import.meta.url),{workerData:{temporary,month:wanted,source}});let settled=false;
   worker.on('message',data=>{if(settled)return;settled=true;if(!data.ok){reject(new Error(data.error));return;}
    try{const destination=join(directory,prefix+wanted+'.sqlite');renameSync(temporary+'.sqlite',destination);load(destination);resolve(true);
     for(const name of readdirSync(directory))if(matches(name)&&name!==(prefix+wanted+'.sqlite'))try{unlinkSync(join(directory,name));}catch{}
    }catch(error){reject(error);}
   });
   worker.on('error',error=>{if(!settled){settled=true;reject(error);}});worker.on('exit',code=>{if(!settled){settled=true;reject(new Error('No se completó la actualización de proveedores.'));}});
  }).finally(()=>{pending=null;});return pending;
 }
 return {lookup,update,ready:()=>!!db,month:()=>month,close:()=>{db?.close();db=null;statement=null;}};
}

if(!isMainThread&&workerData?.temporary){
 const {temporary,month,source='dbip'}=workerData;
 try{
  if(!['dbip','iptoasn'].includes(source)||!(source==='iptoasn'?/^\d{4}-\d{2}-\d{2}$/:/^\d{4}-\d{2}$/).test(month))throw new Error('Fuente o fecha no permitida.');
  const response=await fetch(source==='iptoasn'?'https://iptoasn.com/data/ip2asn-combined.tsv.gz':'https://download.db-ip.com/free/dbip-asn-lite-'+month+'.csv.gz',{redirect:'error',signal:AbortSignal.timeout(120000)});
  if(!response.ok||!response.body)throw new Error('No se pudo descargar la base de proveedores.');
  const file=await open(temporary+'.gz','wx',0o600);let size=0;const hash=createHash('sha256');
  try{for await(const chunk of response.body){size+=chunk.length;if(size>40*1024*1024)throw new Error('La descarga de proveedores excede su límite.');hash.update(chunk);await file.write(chunk);}}finally{await file.close();}
  const count=await importAsnCsv(temporary+'.gz',temporary+'.sqlite',month,{format:source==='iptoasn'?'tsv':'csv'});chmodSync(temporary+'.sqlite',0o600);parentPort.postMessage({ok:true,count,sha256:hash.digest('hex')});
 }catch(error){await unlink(temporary+'.sqlite').catch(()=>{});parentPort.postMessage({ok:false,error:String(error.message).slice(0,200)});}
 finally{await unlink(temporary+'.gz').catch(()=>{});}
}
