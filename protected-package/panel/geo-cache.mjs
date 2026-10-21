// Server Security Monitor v3.0 · Created by FacuSecX
// https://github.com/FacuSecX/
import {isIP} from 'node:net';
import {setImmediate as yieldTurn} from 'node:timers/promises';
import {countryName} from './geo-ip.mjs';
import {isGeoCandidate} from './local-security.mjs';

export function createGeoCache({db,countries,operators={lookup:()=>null},generation=()=>0}){
 const get=db.prepare('SELECT country_code,country,isp,asn,ok FROM geo_cache WHERE ip=?');
 const save=db.prepare(`INSERT INTO geo_cache(ip,country_code,country,isp,asn,updated_at,ok) VALUES(?,?,?,?,?,?,1)
  ON CONFLICT(ip) DO UPDATE SET country_code=excluded.country_code,country=excluded.country,isp=excluded.isp,asn=excluded.asn,updated_at=excluded.updated_at,ok=1`);
 function fill(addresses,{refresh=false}={}){
  let changed=0;const now=Math.floor(Date.now()/1000);
  for(const ip of new Set(addresses)){
   if(!isIP(ip))continue;
   const previous=get.get(ip);let value,operator;
   if(!isGeoCandidate(ip)){value={country_code:'PRV',country:'Red privada / reservada'};operator={isp:'',asn:''};}
   else{
    if(!refresh&&countryName(previous?.country_code))value={country_code:previous.country_code,country:countryName(previous.country_code)};
    else value=countries.lookup(ip)||(countryName(previous?.country_code)?{country_code:previous.country_code,country:countryName(previous.country_code)}:null);
    const network=operators.lookup(ip);
    operator=network?{asn:network.asn,isp:previous?.isp&&(!previous.asn||previous.asn===network.asn)?previous.isp:network.isp}:{isp:previous?.isp||'',asn:previous?.asn||''};
   }
   if(!value&&operator.asn)value={country_code:previous?.country_code||'',country:previous?.country||'Desconocido'};
   if(value&&(value.country_code!==previous?.country_code||value.country!==previous?.country||operator.isp!==previous?.isp||operator.asn!==previous?.asn||previous?.ok!==1)){
    save.run(ip,value.country_code,value.country,operator.isp,operator.asn,now);changed++;
   }
  }
  return changed;
 }
 async function repair({refresh=false}={}){
  const started=generation();let cursor='',changed=0;
  const hasOutgoing=!!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='outgoing_events'").get();
  const batch=db.prepare(hasOutgoing?'SELECT ip FROM (SELECT ip FROM events UNION SELECT ip FROM outgoing_events) WHERE ip>? ORDER BY ip LIMIT 250':'SELECT DISTINCT ip FROM events WHERE ip>? ORDER BY ip LIMIT 250');
  while(started===generation()){
   const rows=batch.all(cursor);if(!rows.length)break;cursor=rows.at(-1).ip;
   db.exec('BEGIN');try{changed+=fill(rows.map(row=>row.ip),{refresh});db.exec('COMMIT');}catch(error){db.exec('ROLLBACK');throw error;}
   await yieldTurn();
  }
  return changed;
 }
 return {fill,repair};
}
