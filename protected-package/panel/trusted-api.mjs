import {BlockList,isIP} from 'node:net';

export function createTrustedPolicy(initial=null){
  let current=null,matcher=new BlockList(),generation=0;
  function update(value){
    if(!value?.ready||!Array.isArray(value.authorized_ips)||value.authorized_ips.length>256||!/^[a-f0-9]{64}$/.test(value.revision||''))return false;
    const next=new BlockList();
    try{for(const raw of value.authorized_ips){
      if(typeof raw!=='string'||raw.includes('%'))return false;
      const [ip,mask,...rest]=raw.split('/'),family=isIP(ip);if(!family||rest.length)return false;
      const type=family===4?'ipv4':'ipv6';
      if(mask===undefined)next.addAddress(ip,type);
      else{const bits=Number(mask);if(!/^\d+$/.test(mask)||!Number.isInteger(bits)||bits<1||bits>(family===4?32:128))return false;next.addSubnet(ip,bits,type);}
    }}catch{return false;}
    if(current?.revision!==value.revision)generation++;
    matcher=next;current={ready:true,source:value.source,authorized_ips:[...value.authorized_ips],authorized_count:value.authorized_ips.length,revision:value.revision};return true;
  }
  function has(ip){const family=isIP(ip||'');return Boolean(family&&matcher.check(ip,family===4?'ipv4':'ipv6'));}
  update(initial);
  return {update,has,current:()=>current,generation:()=>generation};
}

export function createTrustedApi({securityCtl,requireActionToken,readJsonBody,sendJson,actionToken,onPolicy,otherBusy}){
  let pending=null,changing=false,version=0;
  async function status(){
    if(pending)return pending;
    const generation=version;
    pending=securityCtl('trusted-status',{}).then(value=>{if(generation===version&&!changing)onPolicy(value);return value;});
    try{return await pending;}finally{pending=null;}
  }
  function validate(body,apply){
    const keys=Object.keys(body||{}).sort().join(',');
    if(keys!==(apply?'action,confirm,ip,revision':'action,ip')||!['add','remove'].includes(body.action)||
      typeof body.ip!=='string'||body.ip.length>80||body.ip.includes('%'))throw new Error('Indicá una acción y una IPv4 o IPv6 válida.');
    const [ip,mask,...rest]=body.ip.split('/');
    if(!isIP(ip)||rest.length||(mask!==undefined&&(body.action!=='remove'||!/^\d{1,3}$/.test(mask))))throw new Error('Usá una IP concreta, sin comandos ni comodines.');
    if(apply&&(body.confirm!==true||!/^[a-f0-9]{64}$/.test(body.revision||'')))throw new Error('Confirmá una vista previa vigente.');
    return body;
  }
  async function handle(request,response,url){
    if(url.pathname==='/api/authorized-ips'&&request.method==='GET'){
      try{sendJson(response,200,{...await status(),action_token:actionToken});}
      catch{sendJson(response,502,{error:'No se pudo leer la lista de IP autorizadas del servidor.'});}return true;
    }
    if(!['/api/authorized-ips/plan','/api/authorized-ips/apply'].includes(url.pathname)||request.method!=='POST')return false;
    if(!requireActionToken(request)){sendJson(response,403,{error:'Autorización local inválida. Recargá el panel.'});return true;}
    let body;const apply=url.pathname.endsWith('/apply');
    try{body=validate(await readJsonBody(request),apply);}catch(error){sendJson(response,400,{error:error.message.replace(/\bVPS\b/g,'servidor')});return true;}
    if(changing||otherBusy()){sendJson(response,409,{error:'Hay otro cambio en curso. Esperá su resultado.'});return true;}
    changing=true;version++;
    try{const value=await securityCtl(apply?'trusted-apply':'trusted-plan',body);if(apply)onPolicy(value);sendJson(response,200,value);}
    catch(error){sendJson(response,409,{error:error.message.replace(/\bVPS\b/g,'servidor')});}finally{changing=false;version++;}return true;
  }
  return {handle,busy:()=>changing};
}
