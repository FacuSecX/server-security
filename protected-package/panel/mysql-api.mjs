import {randomBytes} from 'node:crypto';
import {isIP} from 'node:net';
const actions=new Set(['install','upgrade','uninstall','start','stop','restart','create-database','create-user','update-user','delete-user','network','create-table','add-column','modify-column','drop-column','drop-table','create-index','create-relation','rename-table','rename-column','drop-index','drop-relation']);
const privileges=new Set(['SELECT','INSERT','UPDATE','DELETE','CREATE','ALTER','INDEX','DROP','REFERENCES']);
const names=/^[A-Za-z][A-Za-z0-9_]{0,47}$/;
function name(value){if(typeof value!=='string'||!names.test(value))throw new Error('Nombre inválido. Usá letras, números y guiones bajos.');return value;}
function user(value){if(typeof value!=='string'||!/^[a-z][a-z0-9_]{2,23}$/.test(value)||['root','mysql','debian','admin'].includes(value))throw new Error('Usuario MySQL inválido.');return value;}
function secret(value){if(typeof value!=='string'||value.length<12||value.length>128||/[\x00-\x1f\x7f]/.test(value)||!value.isWellFormed())throw new Error('Contraseña inválida: 12 a 128 caracteres sin caracteres de control.');return value;}
function bool(value){if(typeof value!=='boolean')throw new Error('Opción inválida.');return value;}
function field(value){
  if(!value||typeof value!=='object'||Array.isArray(value))throw new Error('Campo inválido.');
  const types=['INT','BIGINT','VARCHAR','TEXT','DECIMAL','DATE','DATETIME','BOOLEAN'];
  if(!types.includes(value.type))throw new Error('Tipo de campo no permitido.');
  const result={name:name(value.name),type:value.type,nullable:bool(value.nullable),primary:bool(value.primary),auto:bool(value.auto)};
  for(const key of ['length','precision','scale'])if(value[key]!==undefined){if(!Number.isInteger(value[key]))throw new Error('Tamaño de campo inválido.');result[key]=value[key];}
  if(value.default!==undefined&&value.default!==null){if(!['string','number','boolean'].includes(typeof value.default))throw new Error('Valor predeterminado inválido.');result.default=value.default;}
  return result;
}
export function adminPayload(body,apply=false){
  if(!body||!actions.has(body.action))throw new Error('Acción MySQL no permitida.');
  const allowedFields=['action','confirm','revision','selection','erase_data','enabled','database','username','privileges','ips','password','table','fields','field','column','name','columns','unique','target_table','target_column','new_name'];
  if(Object.keys(body).some(k=>!allowedFields.includes(k)))throw new Error('Parámetros MySQL no permitidos.');
  const result={action:body.action};
  if(['install','upgrade'].includes(body.action)){
    const allowed=new Set(['action','selection',...(apply?['confirm','revision']:[])]);
    if(typeof body.selection!=='string'||!/^[a-f0-9]{64}$/.test(body.selection)||Object.keys(body).some(k=>!allowed.has(k)))throw new Error('Elegí una versión del catálogo actualizado.');
    result.selection=body.selection;
  }
  if(body.action==='uninstall'){
    const allowed=new Set(['action','erase_data',...(apply?['confirm','revision']:[])]);
    if(body.erase_data!==true||Object.keys(body).some(k=>!allowed.has(k)))throw new Error('Confirmá el borrado permanente de los datos del servicio.');
    result.erase_data=true;
  }
  if(['network'].includes(body.action))result.enabled=bool(body.enabled);
  if(['create-database','create-user','update-user','create-table','add-column','modify-column','drop-column','drop-table','create-index','create-relation','rename-table','rename-column','drop-index','drop-relation'].includes(body.action))result.database=name(body.database);
  if(body.action.endsWith('-user')){
    result.username=user(body.username);
    if(body.action!=='delete-user'){
      if(!Array.isArray(body.privileges)||!body.privileges.length||body.privileges.some(p=>!privileges.has(p))||new Set(body.privileges).size!==body.privileges.length)throw new Error('Permisos MySQL inválidos.');
      if(!Array.isArray(body.ips)||body.ips.length>8||body.ips.some(ip=>typeof ip!=='string'||isIP(ip)!==4))throw new Error('Indicá direcciones IPv4 concretas.');
      Object.assign(result,{privileges:[...body.privileges],ips:[...body.ips],enabled:bool(body.enabled)});
      if(apply&&(body.action==='create-user'||body.password))result.password=secret(body.password);
    }
  }
  if(['create-table','add-column','modify-column','drop-column','drop-table','create-index','create-relation','rename-table','rename-column','drop-index','drop-relation'].includes(body.action))result.table=name(body.table);
  if(body.action==='create-table'){
    if(!Array.isArray(body.fields)||!body.fields.length||body.fields.length>32)throw new Error('Definí entre 1 y 32 campos.');
    result.fields=body.fields.map(field);
  }
  if(['add-column','modify-column'].includes(body.action))result.field=field(body.field);
  if(['drop-column','create-relation','rename-column'].includes(body.action))result.column=name(body.column);
  if(['create-index','create-relation','drop-index','drop-relation'].includes(body.action))result.name=name(body.name);
  if(body.action==='create-index'){
    if(!Array.isArray(body.columns)||!body.columns.length||body.columns.length>4)throw new Error('Índice inválido.');
    result.columns=body.columns.map(name);result.unique=bool(body.unique);
  }
  if(body.action==='create-relation'){result.target_table=name(body.target_table);result.target_column=name(body.target_column);}
  if(['rename-table','rename-column'].includes(body.action))result.new_name=name(body.new_name);
  return result;
}
export function createMysqlApi({panelSession=()=>null,sessionActive=()=>false,authorizeService=()=>{},securityCtl,requireActionToken,readJsonBody,sendJson,actionToken,networkBusy,invalidate,audit}){
  let cache=null,loading=null,planning=false,job={status:'idle'},queries=0;
  const sessions=new Map(),failures=[];
  function expire(){const now=Date.now();for(const [id,s]of sessions)if(now>s.expires||now>s.absolute||!sessionActive(s.owner))sessions.delete(id);while(failures[0]<now-60000)failures.shift();}
  const timer=setInterval(expire,60000);timer.unref();
  const busy=()=>job.status==='running';
  async function status(){
    if(busy()&&cache)return cache.data;
    if(cache&&Date.now()-cache.time<3000)return cache.data;
    if(!loading)loading=securityCtl('mysql-status',{}).then(data=>{cache={data,time:Date.now()};return data;}).finally(()=>loading=null);
    return loading;
  }
  function start(payload){
    job={id:randomBytes(8).toString('hex'),status:'running',action:payload.action,message:payload.action==='uninstall'?'Eliminando MySQL/MariaDB y sus datos. Puede demorar varios minutos…':payload.action==='upgrade'?'Respaldando y actualizando MySQL. Puede demorar varios minutos…':payload.action==='install'?'Instalando MySQL. Puede demorar varios minutos…':'Aplicando cambio MySQL…'};
    if(['uninstall','upgrade'].includes(payload.action))sessions.clear();
    securityCtl('mysql-apply',payload).then(result=>{
      job={...job,status:'success',message:'Cambio MySQL aplicado correctamente.'};cache=null;invalidate();
      if(payload.action.endsWith('-user'))for(const [id,s] of sessions)if(s.username===payload.username)sessions.delete(id);
      audit('mysql-'+result.action,payload.database||payload.username||'mysql','Cambio confirmado de MySQL',true,'');
    }).catch(error=>{job={...job,status:'error',message:String(error.message||error)};cache=null;try{audit('mysql-'+payload.action,'mysql','Operación MySQL',false,'Operación no completada');}catch{}});
    return job;
  }
  async function handle(request,response,url){
    if(!url.pathname.startsWith('/api/mysql'))return false;
    try{
      if(url.pathname==='/api/mysql'&&request.method==='GET'){
        sendJson(response,200,{...await status(),job,action_token:actionToken});return true;
      }
      if(request.method!=='POST'){sendJson(response,405,{error:'Método no permitido.'});return true;}
      if(!requireActionToken(request)){sendJson(response,403,{error:'Autorización local inválida.'});return true;}
      const body=await readJsonBody(request,131072);expire();
      if(['/api/mysql/plan','/api/mysql/apply'].includes(url.pathname)){
        authorizeService(request,body.action);
        const apply=url.pathname.endsWith('/apply'),payload=adminPayload(body,apply);
        if(busy()||planning||networkBusy()){sendJson(response,409,{error:'Hay otro cambio en curso.'});return true;}
        if(apply){
          if(body.confirm!==true||!/^[a-f0-9]{64}$/.test(body.revision||''))throw new Error('Revisá y confirmá la vista previa.');
          sendJson(response,202,{ok:true,job:start({...payload,confirm:true,revision:body.revision})});
        }else{
          planning=true;try{sendJson(response,200,await securityCtl('mysql-plan',payload));}finally{planning=false;}
        }return true;
      }
      const owner=panelSession(request);
      if(['/api/mysql/logout','/api/mysql/login','/api/mysql/data'].includes(url.pathname)&&!owner)throw Object.assign(new Error('Ingresá nuevamente al panel.'),{status:401});
      if(url.pathname==='/api/mysql/logout'){if(sessions.get(body.session)?.owner===owner)sessions.delete(body.session);sendJson(response,200,{ok:true});return true;}
      if(url.pathname==='/api/mysql/structure'){
        const payload={database:name(body.database)};
        if(body.table)payload.table=name(body.table);
        sendJson(response,200,await securityCtl('mysql-structure',payload));return true;
      }
      if(busy()&&['uninstall','upgrade'].includes(job.action)){sendJson(response,409,{error:'El servicio se está actualizando o desinstalando. Esperá su resultado.'});return true;}
      if(!['/api/mysql/login','/api/mysql/data'].includes(url.pathname)){sendJson(response,404,{error:'Ruta no encontrada.'});return true;}
      if(queries>=3){sendJson(response,429,{error:'Hay varias consultas en curso. Esperá un momento.'});return true;}
      queries++;
      try{
        if(url.pathname.endsWith('/login')){
          if(failures.length>=5){sendJson(response,429,{error:'Demasiados intentos fallidos. Esperá un minuto.'});return true;}
          const credentials={database:name(body.database),username:user(body.username),password:secret(body.password)};
          let result;try{result=await securityCtl('mysql-data',{...credentials,operation:'login'});}catch(error){failures.push(Date.now());throw error;}
          if(sessions.size>=8){const oldest=[...sessions].reduce((a,b)=>a[1].expires<=b[1].expires?a:b);sessions.delete(oldest[0]);}
          const id=randomBytes(32).toString('hex');sessions.set(id,{...credentials,owner,expires:Date.now()+15*60000,absolute:Date.now()+60*60000});
          sendJson(response,200,{...result,session:id,expires_seconds:900});
        }else{
          const session=sessions.get(body.session);
          if(!session||session.owner!==owner){sendJson(response,401,{error:'La sesión venció. Volvé a autenticarte.'});return true;}
          if(!['tables','table','rows','insert','update','delete'].includes(body.operation))throw new Error('Operación de datos no permitida.');
          const payload={database:session.database,username:session.username,password:session.password,operation:body.operation};
          for(const key of ['table','limit','offset','sort','descending','search','key','row_revision','values','confirm'])if(body[key]!==undefined)payload[key]=body[key];
          if(body.operation!=='tables')name(body.table);
          for(const key of ['values','key'])if(body[key]!==undefined){
            const values=body[key];if(!values||Array.isArray(values)||typeof values!=='object'||Object.keys(values).length>64)throw new Error('Campos de registro inválidos.');
            for(const [column,value]of Object.entries(values)){
              name(column);
              if(value!==null&&!['string','number','boolean'].includes(typeof value))throw new Error('Valor de celda inválido.');
              if(typeof value==='number'&&(!Number.isFinite(value)||(Number.isInteger(value)&&!Number.isSafeInteger(value))))throw new Error('Para números enteros grandes, enviá el valor como texto.');
              if(typeof value==='string'&&(value.length>65536||!value.isWellFormed()))throw new Error('Texto de celda inválido o demasiado largo.');
            }
          }
          const result=await securityCtl('mysql-data',payload);session.expires=Date.now()+15*60000;
          if(['insert','update','delete'].includes(body.operation))audit('mysql-data-'+body.operation,session.database,'Cambio de registros confirmado',true,'');
          sendJson(response,200,result);
        }
      }finally{queries--;}
    }catch(error){sendJson(response,error.status||400,{error:String(error.message||error)});}
    return true;
  }
  return {handle,busy};
}
