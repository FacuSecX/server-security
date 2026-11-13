const BOOT_ID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const keyOf=row=>row.pid+':'+row.start_ticks;
const processId=(pid,start_ticks,boot_id)=>
  Number.isInteger(pid)&&pid>0&&pid<=2147483647&&Number.isSafeInteger(start_ticks)&&start_ticks>=0&&BOOT_ID.test(boot_id);

function processMetrics(snapshot,previous){
  const interval=previous?.boot_id===snapshot.boot_id?snapshot.sample_at-previous.sample_at:0;
  const comparable=interval>0&&interval<=15;
  const priorRows=new Map(comparable?previous.processes.map(row=>[keyOf(row),row]):[]);
  const previousSockets=new Map(comparable&&previous.tcp_available?
    previous.sockets.filter(socket=>socket.key).map(socket=>[socket.key,socket]):[]);
  const rates=new Map(),connections=new Map();
  const rateReady=comparable&&previous.tcp_available&&snapshot.tcp_available;
  for(const socket of snapshot.sockets){
    const shared=socket.pids.length>1,old=previousSockets.get(socket.key);
    const rateKnown=rateReady&&socket.key&&!shared&&(!old||old.pids.length===1&&old.pids[0]===socket.pids[0]);
    const rx_bps=rateKnown?Math.max(0,socket.rx_bytes-(old?.rx_bytes??0))/interval:null;
    const tx_bps=rateKnown?Math.max(0,socket.tx_bytes-(old?.tx_bytes??0))/interval:null;
    const {protocol,state,local_ip,local_port,ip,port}=socket;
    for(const pid of socket.pids){
      const list=connections.get(pid)||[];
      list.push({protocol,state,local_ip,local_port,ip,port,shared,rx_bps,tx_bps});
      connections.set(pid,list);
      if(rx_bps!==null){
        const rate=rates.get(pid)||{rx_bps:0,tx_bps:0};
        rate.rx_bps+=rx_bps;
        rate.tx_bps+=tx_bps;
        rates.set(pid,rate);
      }
    }
  }
  const processes=snapshot.processes.map(row=>{
    const prior=priorRows.get(keyOf(row));
    const sockets=connections.get(row.pid)||[];
    const rate=rates.get(row.pid);
    const shared=sockets.some(socket=>socket.shared&&socket.protocol==='TCP'&&socket.ip);
    const hasTcp=sockets.some(socket=>socket.protocol==='TCP'&&socket.ip);
    return {
      pid:row.pid,start_ticks:row.start_ticks,name:row.name,state:row.state,user:row.user,unit:row.unit,
      rss_bytes:row.rss_bytes,host_network:row.host_network,
      can_stop:row.can_stop,can_restart:row.can_restart,learning:row.learning??null,
      learning_status:row.learning_status||'',learning_reason:row.learning_reason||'',
      cpu_percent:prior?Math.max(0,row.cpu_ticks-prior.cpu_ticks)/snapshot.clock_ticks/interval*100:null,
      rx_bps:rate?.rx_bps??(rateReady&&row.host_network&&!hasTcp?0:null),
      tx_bps:rate?.tx_bps??(rateReady&&row.host_network&&!hasTcp?0:null),
      connections:sockets.filter(socket=>socket.ip).length,shared
    };
  });
  return {processes,connections};
}

export function createProcessesApi({securityCtl,requireActionToken,readJsonBody,sendJson,actionToken,geo,otherBusy,memoryTotal=()=>null,notifications=null}){
  let latest=null,metrics=null,historyCache=null,detailCache=null,eventsBusy=false,lastEvents=0;
  async function syncEvents(){
    if(!notifications||eventsBusy||Date.now()-lastEvents<30000||otherBusy())return;
    eventsBusy=true;
    try{
      const cursor=notifications.processCursor();
      const feed=await securityCtl('processes-history',{event_after:cursor.after,server_id:cursor.server_id});
      notifications.ingestProcessFeed(feed);
      lastEvents=Date.now();
    }catch{}finally{eventsBusy=false;}
  }

  async function processHistory(selected,hours,connectionOffset){
    const key=`${selected.boot_id}:${keyOf(selected)}:${hours}:${connectionOffset}`;
    const now=Date.now();
    if(historyCache?.key===key&&now-historyCache.at<8000)return historyCache.result;
    let result;
    try{
      const history=await securityCtl('processes-history',{...selected,hours,connection_offset:connectionOffset});
      const connections=(history.connections||[]).map(connection=>({...connection,...geo(connection.ip)}));
      history.connections=connections;
      result={history,history_error:''};
    }catch(error){
      const unsupported=/invalid choice|not allowed|No module named/i.test(String(error.message));
      result={history:null,history_error:unsupported?
        'Actualizá el controlador del VPS para habilitar el historial de procesos.':
        'No se pudo consultar el historial del VPS. Se reintentará automáticamente.'};
    }
    historyCache={key,at:Date.now(),result};
    return result;
  }

  async function processDetail(selected,window){
    const key=`${selected.boot_id}:${keyOf(selected)}:${window}`;
    if(detailCache?.key===key&&Date.now()-detailCache.at<8000)return detailCache.result;
    let result;
    try{result={detail_history:await securityCtl('processes-history',{...selected,window}),detail_error:''};}
    catch{result={detail_history:null,detail_error:'No se pudo leer el detalle de este VPS. Se reintentará automáticamente.'};}
    detailCache={key,at:Date.now(),result};return result;
  }

  async function handle(request,response,url){
    const path=url.pathname;
    if(path!=='/api/processes'&&path!=='/api/processes/action')return false;
    const reading=path==='/api/processes';
    if(request.method!==(reading?'GET':'POST')){
      sendJson(response,405,{error:'Método no permitido.'});
      return true;
    }
    try{
      if(reading){
        const params=url.searchParams;
        const hours=params.has('hours')?Number(params.get('hours')):null;
        const offset=params.get('connection_offset');
        const detailWindow=params.get('detail_window');
        const keys=[...params.keys()];
        if(new Set(keys).size!==keys.length||keys.some(key=>!['pid','start_ticks','boot_id','hours','connection_offset','detail_window'].includes(key))||
          (hours!==null&&!['24','168','720'].includes(params.get('hours')))||
          (detailWindow!==null&&!['15m','1h','6h','24h','48h','7d'].includes(detailWindow))||
          (offset!==null&&(hours===null||!/^(0|[1-9]\d{0,5})$/.test(offset)||Number(offset)>100000))){
          sendJson(response,400,{error:'Período o parámetros de proceso no válidos.'});
          return true;
        }
        const selected=params.size?{
          pid:Number(params.get('pid')),start_ticks:Number(params.get('start_ticks')),boot_id:params.get('boot_id')
        }:null;
        if(selected&&(!params.get('pid')||!params.get('start_ticks')||!selected.boot_id||
          !processId(selected.pid,selected.start_ticks,selected.boot_id))){
          sendJson(response,400,{error:'Selección de proceso no válida.'});
          return true;
        }
        const sample=await securityCtl('processes-snapshot',{});
        const scope=sample.learning_server_id||sample.boot_id;
        if(latest&&(latest.learning_server_id||latest.boot_id)!==scope){
          latest=null;metrics=null;historyCache=null;detailCache=null;
        }
        if(!latest||sample.boot_id!==latest.boot_id||sample.sample_at>latest.sample_at){
          metrics=processMetrics(sample,latest);
          latest=sample;
        }
        const current=latest,currentMetrics=metrics;
        const match=selected&&selected.boot_id===current.boot_id?
          currentMetrics.processes.find(row=>keyOf(row)===keyOf(selected)):null;
        const sockets=match?currentMetrics.connections.get(match.pid)||[]:[];
        const places=new Map([...new Set(sockets.map(socket=>socket.ip).filter(Boolean))].map(ip=>[ip,geo(ip)]));
        const historical=selected&&hours!==null?await processHistory(selected,hours,Number(offset??0)):{};
        const detailed=selected&&detailWindow!==null?await processDetail(selected,detailWindow):{};
        const total=current.memory_total_bytes??memoryTotal();
        sendJson(response,200,{ok:true,boot_id:current.boot_id,sample_at:current.sample_at,
          memory_total_bytes:Number.isFinite(total)&&total>0?total:null,...historical,...detailed,
          observed_at_ms:current.observed_at_ms??Date.now(),
          tcp_available:current.tcp_available,udp_available:current.udp_available,processes:currentMetrics.processes,
          selected:match?{...match,sockets:sockets.map(socket=>({...socket,...places.get(socket.ip)}))}:null,
          learning_server_id:current.learning_server_id,learning_error:current.learning_error||'',
          can_manage:request.panelUser?.administrator===true,action_token:actionToken});
      }else{
        if(request.panelUser?.administrator!==true||!requireActionToken(request)){
          sendJson(response,403,{error:'Solo el administrador principal puede gestionar procesos.'});
          return true;
        }
        const body=await readJsonBody(request);
        if(!body||typeof body!=='object'||Object.keys(body).length!==5||
          typeof body.boot_id!=='string'||!processId(body.pid,body.start_ticks,body.boot_id)||
          body.confirm!==true||!['stop','restart','learning_finish','learning_restart'].includes(body.action)){
          sendJson(response,400,{error:'Revisá el proceso y confirmá la acción.'});
          return true;
        }
        if(otherBusy()){
          sendJson(response,409,{error:'Hay una operación en curso. Esperá a que termine.'});
          return true;
        }
        const result=await securityCtl('processes-action',body);
        latest=null;metrics=null;historyCache=null;detailCache=null;
        sendJson(response,200,result);
      }
    }catch(error){
      const raw=String(error.message||'');
      const missing=reading&&(/invalid choice|not allowed|a password is required/i.test(raw)&&raw.includes('processes-snapshot')||
        /No module named ['"]storypulse_processes/i.test(raw));
      sendJson(response,error.status||(missing?503:502),{error:missing?
        'Actualizá el controlador de Server Monitor en este servidor para habilitar Procesos.':
        raw||'No se pudo consultar o gestionar el proceso.'});
    }
    return true;
  }
  return {handle,syncEvents};
}
