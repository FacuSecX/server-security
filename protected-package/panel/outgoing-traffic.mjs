import {isIP} from 'node:net';

export function createOutgoingTraffic(db){
 db.exec(`CREATE TABLE IF NOT EXISTS outgoing_events(
  id TEXT PRIMARY KEY,timestamp INTEGER NOT NULL,source_ip TEXT NOT NULL,source_port TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL,port TEXT NOT NULL DEFAULT '',protocol TEXT NOT NULL,decision TEXT NOT NULL DEFAULT 'observed',
  UNIQUE(timestamp,source_ip,source_port,ip,port,protocol));
  CREATE INDEX IF NOT EXISTS outgoing_timestamp_idx ON outgoing_events(timestamp);
  CREATE INDEX IF NOT EXISTS outgoing_ip_idx ON outgoing_events(ip);`);
 const insert=db.prepare(`INSERT INTO outgoing_events(id,timestamp,source_ip,source_port,ip,port,protocol,decision)
  VALUES(?,?,?,?,?,?,?,?) ON CONFLICT DO UPDATE SET
  decision=CASE WHEN excluded.decision<>'observed' THEN excluded.decision ELSE outgoing_events.decision END`);
 const port=value=>value===''||value===undefined?'':/^\d{1,5}$/.test(String(value))&&Number(value)<=65535?String(Number(value)):null;
 function persist(event){
  const source=port(event.source_port),destination=port(event.port);
  if(!/^[a-f0-9]{32,64}$/.test(String(event.id))||!Number.isSafeInteger(event.timestamp)||event.timestamp<=0||
     !isIP(event.source_ip)||!isIP(event.ip)||source===null||destination===null||
     !/^[A-Z0-9]{1,12}$/.test(event.protocol)||!['observed','accepted','blocked'].includes(event.flow_status))return false;
  insert.run(event.id,event.timestamp,event.source_ip,source,event.ip,destination,event.protocol,event.flow_status);return true;
 }
 function query(params,now=Math.floor(Date.now()/1000)){
  const bad=()=>{throw Object.assign(new Error('Filtro de tráfico saliente no válido.'),{status:400});};
  const hours=Number(params.get('hours')||24);if(![24,168,720].includes(hours))bad();
  const where=['e.timestamp>=?'],values=[now-hours*3600];
  for(const [key,column]of [['source_port','e.source_port'],['port','e.port']]){
   const value=params.get(key)||'';if(value){const valid=port(value);if(valid===null)bad();where.push(`${column}=?`);values.push(valid);}
  }
  const protocol=params.get('protocol')||'',decision=params.get('decision')||'';
  if(protocol){if(!/^[A-Z0-9]{1,12}$/.test(protocol))bad();where.push('e.protocol=?');values.push(protocol);}
  if(decision){if(!['observed','accepted','blocked'].includes(decision))bad();where.push('e.decision=?');values.push(decision);}
  const literal=value=>'%'+value.replace(/[\\%_]/g,'\\$&')+'%';
  for(const [key,columns]of [['country',['g.country_code','g.country']],['isp',['g.isp','g.asn']],['q',['e.ip','e.source_ip','e.source_port','e.port','g.country','g.isp','g.asn']]]){
   const value=(params.get(key)||'').trim();if(value.length>180||/[\x00-\x1f]/.test(value))bad();
   if(value){
    if(key==='country'&&/^[A-Za-z]{2}$|^PRV$/.test(value)){where.push('g.country_code=?');values.push(value.toUpperCase());}
    else{where.push('('+columns.map(column=>`${column} LIKE ? ESCAPE '\\'`).join(' OR ')+')');values.push(...columns.map(()=>literal(value)));}
   }
  }
  const rows=db.prepare(`SELECT e.*,COALESCE(g.country_code,'') country_code,
   COALESCE(NULLIF(g.country,''),'Desconocido') country,COALESCE(g.isp,'') isp,COALESCE(g.asn,'') asn
   FROM outgoing_events e LEFT JOIN geo_cache g ON g.ip=e.ip WHERE ${where.join(' AND ')}
   ORDER BY e.timestamp DESC,e.id DESC LIMIT 1001`).all(...values);
  return {ok:true,hours,events:rows.slice(0,1000).map(row=>({...row,provider:row.isp||'Sin identificar'})),truncated:rows.length>1000};
 }
 return {persist,query};
}
