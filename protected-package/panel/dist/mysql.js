/* MySQL UI. Passwords and database sessions stay in memory, never localStorage. */
const mysqlState={data:null,loading:false,busy:false,pending:null,editing:null,last:0,finished:null,structure:null,structureRequest:0};
const mysqlLabels={SELECT:'Leer datos',INSERT:'Agregar registros',UPDATE:'Modificar registros',DELETE:'Eliminar registros',CREATE:'Crear tablas',ALTER:'Modificar estructura',INDEX:'Gestionar índices',DROP:'Eliminar tablas',REFERENCES:'Crear relaciones'};
const mysqlActionLabels={upgrade:'Actualizar MySQL conservando datos',uninstall:'Eliminar MySQL/MariaDB definitivamente',install:'Instalar MySQL',start:'Iniciar MySQL',stop:'Detener MySQL',restart:'Reiniciar MySQL','create-database':'Crear base de datos','create-user':'Crear usuario','update-user':'Modificar usuario','delete-user':'Eliminar usuario',network:'Configurar acceso externo','create-table':'Crear tabla','add-column':'Añadir campo','modify-column':'Modificar campo','drop-column':'Eliminar campo','drop-table':'Eliminar tabla','create-index':'Crear índice','create-relation':'Crear relación','rename-table':'Renombrar tabla','rename-column':'Renombrar campo','drop-index':'Eliminar índice','drop-relation':'Eliminar relación'};
function mysqlOptions(node,values,empty='Elegí una opción'){
  const selected=node.value;node.innerHTML='<option value="">'+esc(empty)+'</option>'+values.map(value=>'<option value="'+esc(value)+'">'+esc(value)+'</option>').join('');
  if(values.includes(selected))node.value=selected;
}
async function mysqlPost(path,body){
  const response=await fetch('/api/mysql/'+path,{method:'POST',headers:{'Content-Type':'application/json','X-StoryPulse-Token':state.actionToken},body:JSON.stringify(body),signal:AbortSignal.timeout(50000)});
  const result=await response.json();if(!response.ok){const error=new Error(result.error||'No se completó la operación.');error.status=response.status;throw error;}return result;
}
function mysqlServiceKind(kind){
  if(!['ftp','mysql'].includes(kind))kind='ftp';
  $$('[data-service-panel]').forEach(el=>el.hidden=el.dataset.servicePanel!==kind);
  $$('[data-service-kind]').forEach(el=>el.classList.toggle('active',el.dataset.serviceKind===kind));
  writePreference('storypulse-service-kind',kind);
  if(kind==='mysql')loadMysql();
}
function mysqlPermissions(){return $$('[data-mysql-permission]:checked').map(el=>el.dataset.mysqlPermission);}
function mysqlUserReset(){mysqlState.editing=null;$('#mysqlUserForm').reset();$('#mysqlUserTitle').textContent='Crear usuario';renderMysql();}
function renderMysql(){
  const data=mysqlState.data,busy=mysqlState.busy||data?.job?.status==='running',installed=!!data?.installed;
  const engine=data?.backend==='mariadb'?'MariaDB':'MySQL';
  const status=!data?'Consultando '+engine+'…':data?.job?.status==='running'||data?.job?.status==='error'?data.job.message:installed?engine+' '+(data.installed_version||'')+' · '+({active:'Activo',inactive:'Detenido',failed:'Con error'}[data.state]||data.state)+' · '+data.databases.length+' bases · '+data.users.length+' usuarios':data?.managed?'Instalación pendiente. Podés reintentar para completarla.':engine+' todavía no está instalado.';
  $$('.mysql-status').forEach(el=>{el.textContent=status;el.classList.toggle('error',data?.job?.status==='error');el.classList.toggle('status-warning',!!data&&data?.job?.status!=='running'&&(!installed||data.state!=='active'));});
  $('#mysqlUninstall').disabled=!data?.managed||busy;$('#mysqlUpgrade').hidden=!installed;$('#mysqlUpgrade').disabled=!installed||busy;
  $('#mysqlInstall').disabled=!data||installed||busy;$('#mysqlInstall').textContent=installed?engine+' instalado':'Revisar instalación '+engine;
  $$('[data-service-panel="mysql"] input,[data-service-panel="mysql"] select,[data-service-panel="mysql"] textarea,[data-service-panel="mysql"] button').forEach(el=>{el.disabled=!installed||busy;});
  $$('.mysql-tabs button,.mysql-refresh').forEach(el=>el.disabled=busy);
  $$('[data-mysql-service]').forEach(el=>el.disabled=!installed||busy||(el.dataset.mysqlService==='start'&&data.state==='active')||(el.dataset.mysqlService==='stop'&&data.state!=='active'));
  $('#mysqlUsername').disabled=!installed||busy||!!mysqlState.editing;$('#mysqlUserDatabase').disabled=!installed||busy||!!mysqlState.editing;
  $('#mysqlPassword').required=!mysqlState.editing;$('#mysqlPassword').placeholder=mysqlState.editing?'Vacía para conservar la contraseña':'Mínimo 12 caracteres';
  $('#mysqlUserCancel').hidden=!mysqlState.editing;
  for(const id of ['#mysqlUserDatabase','#mysqlStructureDatabase','#dbDatabase'])mysqlOptions($(id),data?.databases||[],'Elegí la base');
  if(mysqlState.editing)$('#mysqlUserDatabase').value=mysqlState.editing.database;
  $('#mysqlUsers').innerHTML=(data?.users||[]).map(u=>'<tr><td>'+esc(u.username)+'</td><td>'+esc(u.database)+'</td><td>'+u.privileges.map(p=>esc(mysqlLabels[p])).join(' · ')+'</td><td>'+esc(u.ips.join(', ')||'Sólo panel')+'</td><td><span class="port-status '+(u.enabled?'green':'gray')+'"><i></i>'+(u.enabled?'Habilitado':'Deshabilitado')+'</span></td><td><div class="port-actions"><button data-mysql-user="edit" data-name="'+esc(u.username)+'" '+(busy?'disabled':'')+'>Editar</button><button data-mysql-user="toggle" data-name="'+esc(u.username)+'" '+(busy?'disabled':'')+'>'+(u.enabled?'Deshabilitar':'Habilitar')+'</button><button data-mysql-user="delete" data-name="'+esc(u.username)+'" '+(busy?'disabled':'')+'>Eliminar</button></div></td></tr>').join('')||'<tr><td colspan="6">Todavía no hay usuarios.</td></tr>';
  if(document.activeElement!==$('#mysqlRemote'))$('#mysqlRemote').checked=!!data?.remote;
  $('#mysqlConnectionInfo').textContent=installed?'Servidor: '+data.host+':3306 · Estado externo: '+(data.remote?'habilitado para las IP autorizadas':'deshabilitado')+'. Desde el panel se usa SSH y conexión local.':'Instalá MySQL primero.';
  $('#mysqlFingerprint').textContent=data?.certificate_sha256?'Huella SHA-256: '+data.certificate_sha256:'';
  $('#mysqlCertificate').disabled=!data?.certificate||busy;
  if(data?.used_by?.length){
    $('#mysqlUninstall').disabled=true;
    $('#mysqlUninstall').title='Primero eliminá '+data.used_by.join(' y ')+': necesitan esta base de datos.';
    $$('.mysql-status').forEach(el=>el.textContent+=' · En uso por '+data.used_by.join(' y '));
  }else $('#mysqlUninstall').title='';
  dbUserOptions();
}
async function loadMysql(force=false){
  if(mysqlState.loading||mysqlState.busy)return;
  if(!force&&mysqlState.data&&mysqlState.data.job?.status!=='running'&&Date.now()-mysqlState.last<3000)return;
  mysqlState.loading=true;
  try{
    const response=await fetch('/api/mysql',{signal:AbortSignal.timeout(45000)}),data=await response.json();
    if(!response.ok)throw new Error(data.error||'No se pudo consultar MySQL.');
    mysqlState.data=data;mysqlState.last=Date.now();state.actionToken=data.action_token;
    if(data.job?.status==='success'&&mysqlState.finished!==data.job.id){mysqlState.finished=data.job.id;mysqlUserReset();showToast(data.job.message);if(['rename-table','drop-table'].includes(data.job.action))$('#mysqlExistingTable').value='';if($('#mysqlStructureDatabase').value)loadMysqlStructure();}
    renderMysql();
  }catch(error){$$('.mysql-status').forEach(el=>{el.textContent=error.message;el.classList.add('error');});}
  finally{mysqlState.loading=false;}
}
async function previewMysql(payload){
  if(mysqlState.busy||mysqlState.data?.job?.status==='running')return;mysqlState.busy=true;renderMysql();
  try{
    const {password,...safe}=payload,result=await mysqlPost('plan',safe);mysqlState.pending={...payload,revision:result.revision};
    $('#mysqlDialogTitle').textContent=mysqlActionLabels[payload.action];
    const details=[payload.database?'Base: '+payload.database:'',payload.username?'Usuario: '+payload.username:'',payload.table?'Tabla: '+payload.table:'',payload.column?'Campo: '+payload.column:'',payload.field?'Campo: '+payload.field.name:'',payload.fields?'Campos: '+payload.fields.map(f=>f.name+' ('+f.type+')').join(', '):'',payload.privileges?'Permisos: '+payload.privileges.map(p=>mysqlLabels[p]).join(', '):'',payload.ips?'IP externas: '+(payload.ips.join(', ')||'ninguna'):'',payload.action==='network'?'Acceso externo: '+(payload.enabled?'habilitar':'deshabilitar'):''];
    if(result.target_version)details.push('Versión elegida: '+result.target_version);if(result.installed_version)details.push('Versión instalada: '+result.installed_version);
    if(payload.name)details.push('Nombre: '+payload.name);if(payload.new_name)details.push('Nombre nuevo: '+payload.new_name);
    if(payload.field)details.push('Tipo: '+payload.field.type+(payload.field.type==='VARCHAR'?' ('+payload.field.length+')':payload.field.type==='DECIMAL'?' ('+payload.field.precision+','+payload.field.scale+')':'')+' · '+(payload.field.nullable?'Admite NULL':'Obligatorio'));
    if(payload.columns)details.push('Campos del índice: '+payload.columns.join(', ')+(payload.unique?' · Valores únicos':''));
    if(payload.target_table)details.push('Referencia: '+payload.target_table+'.'+payload.target_column);
    if(payload.action==='uninstall')details.push('Se borrarán todas las bases, usuarios y datos de esta instalación. Paquetes: '+(result.packages.join(', ')||'ya eliminados')+'. Reglas propias: '+result.firewall_rules+'.');
    $('#mysqlApply').textContent=payload.action==='uninstall'?'Eliminar definitivamente':'Aplicar cambio';$('#mysqlApply').classList.toggle('danger-button',payload.action==='uninstall');
    $('#mysqlNotice').classList.toggle('status-warning',payload.action==='uninstall');
    $('#mysqlSummary').textContent=details.filter(Boolean).join(' · ');$('#mysqlNotice').textContent=result.notice;
    $('#mysqlError').textContent='';$('#mysqlConfirm').checked=false;$('#mysqlApply').disabled=true;$('#mysqlDialog').showModal();
  }catch(error){$('#mysqlPassword').value='';showToast(error.message);}
  finally{mysqlState.busy=false;renderMysql();}
}
async function applyMysql(){
  if(mysqlState.busy||!mysqlState.pending||!$('#mysqlConfirm').checked)return;
  mysqlState.busy=true;$('#mysqlApply').disabled=true;renderMysql();
  try{
    const result=await mysqlPost('apply',{...mysqlState.pending,confirm:true});mysqlState.data.job=result.job;
    mysqlState.pending=null;$('#mysqlPassword').value='';$('#mysqlDialog').close();
  }catch(error){mysqlState.pending=null;$('#mysqlPassword').value='';$('#mysqlError').textContent=error.message+' Recargá la vista previa antes de reintentar.';}
  finally{mysqlState.busy=false;await loadMysql(true);}
}
function mysqlFieldMarkup(field={}){
  const kind=field.type||'VARCHAR';return '<div class="mysql-field"><div class="mysql-field-top"><label>Nombre<input data-field="name" value="'+esc(field.name||'')+'" required maxlength="48" pattern="[A-Za-z][A-Za-z0-9_]{0,47}"></label><label>Tipo<select data-field="type">'+['INT','BIGINT','VARCHAR','TEXT','DECIMAL','DATE','DATETIME','BOOLEAN'].map(t=>'<option '+(t===kind?'selected':'')+'>'+t+'</option>').join('')+'</select></label><label>Tamaño<input data-field="length" type="number" min="1" max="4096" value="'+esc(field.length||255)+'"></label></div><div class="mysql-field-checks"><label class="mysql-check"><input data-field="nullable" type="checkbox" '+(field.nullable!==false?'checked':'')+'> Admite NULL</label><label class="mysql-check"><input data-field="primary" type="checkbox" '+(field.primary?'checked':'')+'> Clave primaria</label><label class="mysql-check"><input data-field="auto" type="checkbox" '+(field.auto?'checked':'')+'> Automático</label></div><div class="mysql-inline"><label>Valor predeterminado (opcional)<input data-field="default" value="'+esc(field.default??'')+'"></label><label>DECIMAL: precisión<input data-field="precision" type="number" min="1" max="38" value="'+esc(field.precision||10)+'"></label><label>Decimales<input data-field="scale" type="number" min="0" max="12" value="'+esc(field.scale??2)+'"></label></div><button type="button" class="secondary-button remove-field">Quitar campo</button></div>';
}
function mysqlReadField(node){const get=k=>node.querySelector('[data-field="'+k+'"]');return {name:get('name').value,type:get('type').value,nullable:get('nullable').checked,primary:get('primary').checked,auto:get('auto').checked,length:Number(get('length').value),precision:Number(get('precision').value),scale:Number(get('scale').value),...(get('default').value!==''?{default:get('default').value}:{})};}
function mysqlSyncFields(){
  for(const node of $$('#mysqlFields .mysql-field')){
    const get=key=>node.querySelector('[data-field="'+key+'"]'),kind=get('type').value,creating=$('#mysqlStructureAction').value==='create-table';
    get('length').closest('label').hidden=kind!=='VARCHAR';
    get('precision').closest('label').hidden=kind!=='DECIMAL';get('scale').closest('label').hidden=kind!=='DECIMAL';
    get('primary').closest('label').hidden=!creating;get('auto').closest('label').hidden=!creating;
    if(!creating){get('primary').checked=false;get('auto').checked=false;}
    get('default').closest('label').hidden=kind==='TEXT'||get('auto').checked;
    if(kind==='TEXT'||get('auto').checked)get('default').value='';
  }
}
function mysqlStructureMode(){
  const action=$('#mysqlStructureAction').value;
  $('#mysqlNewTableLabel').hidden=action!=='create-table';$('#mysqlNewTable').required=action==='create-table';
  $('#mysqlExistingTableLabel').hidden=action==='create-table';$('#mysqlExistingTable').required=action!=='create-table';
  $('#mysqlExistingColumnLabel').hidden=!['modify-column','drop-column','create-relation','rename-column'].includes(action);
  $('#mysqlFields').hidden=!['create-table','add-column','modify-column'].includes(action);$('#mysqlAddField').hidden=action!=='create-table';
  $('#mysqlRenameLabel').hidden=!['rename-table','rename-column'].includes(action);$('#mysqlDropObjectLabel').hidden=!['drop-index','drop-relation'].includes(action);mysqlDropOptions();
  $('#mysqlIndexOptions').hidden=action!=='create-index';$('#mysqlRelationOptions').hidden=action!=='create-relation';
  // Hidden definitions must not block form validation for other operations.
  $('#mysqlFields').innerHTML=action==='create-table'?mysqlFieldMarkup({name:'id',type:'BIGINT',nullable:false,primary:true,auto:true})+mysqlFieldMarkup({name:'nombre'}):['add-column','modify-column'].includes(action)?mysqlFieldMarkup():'';
  if(action==='modify-column')mysqlPrefillColumn();
  mysqlSyncFields();
}
function mysqlPrefillColumn(){
  const column=mysqlState.structure?.columns?.find(c=>c.name===$('#mysqlExistingColumn').value);if(!column||$('#mysqlStructureAction').value!=='modify-column')return;
  const supported={int:'INT',bigint:'BIGINT',varchar:'VARCHAR',text:'TEXT',decimal:'DECIMAL',date:'DATE',datetime:'DATETIME',tinyint:'BOOLEAN'};
  const sizes=column.definition.match(/\((\d+)(?:,(\d+))?\)/);
  $('#mysqlFields').innerHTML=mysqlFieldMarkup({name:column.name,type:supported[column.type]||'TEXT',nullable:column.nullable==='YES',length:sizes?Number(sizes[1]):255,precision:sizes?Number(sizes[1]):10,scale:sizes?.[2]?Number(sizes[2]):2,default:column.default_value});
  $('#mysqlFields [data-field="name"]').readOnly=true;
  mysqlSyncFields();
}
function mysqlDropOptions(){const data=mysqlState.structure||{},action=$('#mysqlStructureAction').value,items=action==='drop-index'?(data.indexes||[]).filter(i=>i.name!=='PRIMARY'):(data.relations||[]);mysqlOptions($('#mysqlDropObject'),[...new Set(items.map(i=>i.name))],'Elegí el índice o relación');}
async function loadMysqlStructure(){
  const database=$('#mysqlStructureDatabase').value;if(!database)return;const id=++mysqlState.structureRequest;
  try{
    const table=$('#mysqlExistingTable').value,result=await mysqlPost('structure',{database,...(table?{table}:{})});if(id!==mysqlState.structureRequest)return;
    mysqlState.structure=result;mysqlOptions($('#mysqlExistingTable'),result.tables.map(t=>t.name),'Elegí la tabla');mysqlOptions($('#mysqlRelationTable'),result.tables.map(t=>t.name),'Elegí la tabla referenciada');
    mysqlOptions($('#mysqlExistingColumn'),(result.columns||[]).map(c=>c.name),'Elegí el campo');
    $('#mysqlStructureInfo').innerHTML=(result.columns||[]).map(c=>'<p><strong>'+esc(c.name)+'</strong> · '+esc(c.definition)+(c.column_key==='PRI'?' · Clave primaria':'')+'</p>').join('')||'Elegí una tabla para ver sus campos.';
    mysqlPrefillColumn();mysqlDropOptions();
  }catch(error){$('#mysqlStructureInfo').textContent=error.message;}
}
function mysqlStructurePayload(){
  const action=$('#mysqlStructureAction').value,result={action,database:$('#mysqlStructureDatabase').value,table:action==='create-table'?$('#mysqlNewTable').value:$('#mysqlExistingTable').value};
  if(action==='create-table')result.fields=$$('#mysqlFields .mysql-field').map(mysqlReadField);
  if(['add-column','modify-column'].includes(action))result.field=mysqlReadField($('#mysqlFields .mysql-field'));
  if(['drop-column','create-relation','rename-column'].includes(action))result.column=$('#mysqlExistingColumn').value;
  if(action==='create-index')Object.assign(result,{name:$('#mysqlIndexName').value,columns:$('#mysqlIndexColumns').value.split(',').map(v=>v.trim()),unique:$('#mysqlIndexUnique').checked});
  if(action==='create-relation')Object.assign(result,{name:$('#mysqlRelationName').value,target_table:$('#mysqlRelationTable').value,target_column:$('#mysqlRelationColumn').value});
  if(['rename-table','rename-column'].includes(action))result.new_name=$('#mysqlRename').value;
  if(['drop-index','drop-relation'].includes(action))result.name=$('#mysqlDropObject').value;
  return result;
}
const dbState={session:null,database:null,username:null,tables:[],table:null,data:null,offset:0,request:0,busy:false,record:null,last:0,absolute:0};
function dbUserOptions(){if(dbState.session)return;mysqlOptions($('#dbUsername'),(mysqlState.data?.users||[]).filter(u=>u.database===$('#dbDatabase').value&&u.enabled).map(u=>u.username),'Elegí el usuario');}
async function dbCall(operation,extra={}){
  try{const result=await mysqlPost('data',{session:dbState.session,operation,...extra});dbState.last=Date.now();return result;}
  catch(error){if(error.status===401)dbClear();throw error;}
}
function dbClear(){Object.assign(dbState,{session:null,database:null,username:null,tables:[],table:null,data:null,record:null});dbState.request++;$('#dbPassword').value='';$('#dbLogin').hidden=false;$('#dbWorkspace').hidden=true;$('#dbLogout').hidden=true;$('#dbRecordDialog').close();$('#dbRecordFields').innerHTML='';for(const id of ['#dbTables','#dbGridHead','#dbGridRows','#dbPageInfo'])$(id).innerHTML='';$('#dbTableTitle').textContent='Elegí una tabla';$('#dbInsert').disabled=true;$('#dbPrevious').disabled=true;$('#dbNext').disabled=true;$('#dbSort').innerHTML='';$('#dbSearch').value='';}
function dbRenderTables(){$('#dbTables').innerHTML=dbState.tables.map((t,index)=>'<button class="secondary-button '+(t.name===dbState.table?'active':'')+'" data-db-table="'+index+'">'+esc(t.name)+'</button>').join('')||'<p>No hay tablas visibles con estos permisos.</p>';}
async function dbLoadTable(reset=false){
  if(!dbState.session||!dbState.table)return;if(reset)dbState.offset=0;const id=++dbState.request;
  dbState.data=null;$('#dbGridRows').innerHTML='';$('#dbGridHead').innerHTML='';$('#dbInsert').disabled=true;$('#dbPrevious').disabled=true;$('#dbNext').disabled=true;
  $('#dbStatus').textContent='Consultando '+dbState.table+'…';
  try{
    const canRead=dbState.privileges.includes('SELECT'),result=await dbCall(canRead?'rows':'table',{table:dbState.table,offset:dbState.offset,limit:25,search:$('#dbSearch').value,sort:$('#dbSort').value||undefined,descending:$('#dbDescending').checked});
    if(id!==dbState.request)return;dbState.data=result;
    $('#dbStatus').textContent='Conectado como '+dbState.username+' · Base '+dbState.database+' · '+(canRead?'Datos actualizados':'Sin permiso para leer filas');
    $('#dbTableTitle').textContent=dbState.table;mysqlOptions($('#dbSort'),result.columns.map(c=>c.name),'Orden por defecto');
    $('#dbInsert').disabled=!result.privileges.includes('INSERT');
    $('#dbGridHead').innerHTML='<tr>'+result.columns.map(c=>'<th>'+esc(c.name)+'</th>').join('')+'<th>Acciones</th></tr>';
    $('#dbGridRows').innerHTML=(result.rows||[]).map((r,index)=>'<tr>'+result.columns.map(c=>'<td class="'+(r.values[c.name]===null?'db-null':'')+'">'+(r.values[c.name]===null?'NULL':esc(r.values[c.name]))+(r.truncated.includes(c.name)?'…':'')+'</td>').join('')+'<td><div class="port-actions"><button data-db-row="edit" data-index="'+index+'" '+(!result.privileges.includes('UPDATE')||!result.keys.length||result.keys.some(k=>r.truncated.includes(k))?'disabled':'')+'>Editar</button><button data-db-row="delete" data-index="'+index+'" '+(!result.privileges.includes('DELETE')||!result.keys.length||result.keys.some(k=>r.truncated.includes(k))?'disabled':'')+'>Eliminar</button></div></td></tr>').join('')||'<tr><td colspan="'+(result.columns.length+1)+'">Sin registros para mostrar.</td></tr>';
    $('#dbGridNotice').textContent=!result.keys.length?'Tabla sin clave única: edición y eliminación de filas deshabilitadas.':'Se muestran hasta 25 filas. Los campos muy grandes se abrevian y se mantienen sin editar.';
    $('#dbPrevious').disabled=!dbState.offset;$('#dbNext').disabled=!result.more;$('#dbPageInfo').textContent='Página '+(Math.floor(dbState.offset/25)+1);dbRenderTables();
  }catch(error){if(id===dbState.request)$('#dbStatus').textContent=error.message;}
}
function dbOpenRecord(index=null){
  const data=dbState.data,row=index===null?null:data.rows[index];dbState.record={row,index};
  $('#dbRecordTitle').textContent=row?'Editar registro':'Agregar registro';$('#dbRecordError').textContent='';
  const columns=data.columns.filter(c=>c.editable&&!c.extra.includes('GENERATED')&&(!row||(!data.keys.includes(c.name)&&!row.truncated.includes(c.name))));
  $('#dbRecordFields').innerHTML=columns.map((c,index)=>{
    const value=row?row.values[c.name]:null,optional=!row&&(c.nullable==='YES'||c.default_value!==null||c.extra.includes('auto_increment'));
    return '<div class="db-record-field" data-record-name="'+esc(c.name)+'"><label>'+esc(c.name)+' · '+esc(c.definition)+'</label><select data-record-mode><option value="value" '+(!optional&&value!==null?'selected':'')+'>Ingresar valor</option>'+(!row?'<option value="default" '+(optional?'selected':'')+'>Usar valor predeterminado / automático</option>':'')+(c.nullable==='YES'?'<option value="null" '+(row&&value===null?'selected':'')+'>NULL</option>':'')+'</select><textarea data-record-value maxlength="65536">'+esc(value??'')+'</textarea></div>';
  }).join('');$('#dbRecordDialog').showModal();
}
async function dbSaveRecord(event){
  event.preventDefault();if(dbState.busy)return;dbState.busy=true;
  $$('#dbRecordForm button').forEach(button=>button.disabled=true);
  const values={};for(const node of $$('#dbRecordFields [data-record-name]')){
    const mode=node.querySelector('[data-record-mode]').value;if(mode==='default')continue;
    values[node.dataset.recordName]=mode==='null'?null:node.querySelector('[data-record-value]').value;
  }
  const record=dbState.record;
  if(record.row)for(const key of Object.keys(values))if(values[key]===record.row.values[key])delete values[key];
  try{
    if(record.row&&!Object.keys(values).length)throw new Error('No hay valores nuevos para guardar.');
    await dbCall(record.row?'update':'insert',{table:dbState.table,values,confirm:true,...(record.row?{key:record.row.key,row_revision:record.row.revision}:{})});
    $('#dbRecordDialog').close();$('#dbRecordFields').innerHTML='';await dbLoadTable();showToast('Registro guardado.');
  }catch(error){$('#dbRecordError').textContent=error.message;}finally{dbState.busy=false;$$('#dbRecordForm button').forEach(button=>button.disabled=false);}
}
$('#mysqlPermissions').innerHTML=Object.entries(mysqlLabels).map(([key,label])=>'<label><input type="checkbox" data-mysql-permission="'+key+'" '+(key==='SELECT'?'checked':'')+'> '+esc(label)+'</label>').join('');
$$('[data-service-kind]').forEach(button=>button.addEventListener('click',()=>mysqlServiceKind(button.dataset.serviceKind)));
$$('.mysql-refresh').forEach(button=>button.addEventListener('click',()=>void loadMysql(true)));
$('#mysqlUninstall').addEventListener('click',()=>previewMysql({action:'uninstall',erase_data:true}));
$('#mysqlInstall').addEventListener('click',()=>window.ServiceVersions.open('mysql','install'));
$$('[data-mysql-service]').forEach(button=>button.addEventListener('click',()=>previewMysql({action:button.dataset.mysqlService})));
$$('[data-mysql-tab]').forEach(button=>button.addEventListener('click',()=>{$$('[data-mysql-content]').forEach(el=>el.hidden=el.dataset.mysqlContent!==button.dataset.mysqlTab);$$('[data-mysql-tab]').forEach(el=>el.classList.toggle('active',el===button));if(button.dataset.mysqlTab==='structure')loadMysqlStructure();}));
$('#mysqlDatabaseForm').addEventListener('submit',event=>{event.preventDefault();previewMysql({action:'create-database',database:$('#mysqlDatabaseName').value});});
$('#mysqlUserForm').addEventListener('submit',event=>{event.preventDefault();previewMysql({action:mysqlState.editing?'update-user':'create-user',username:$('#mysqlUsername').value,database:$('#mysqlUserDatabase').value,password:$('#mysqlPassword').value,enabled:$('#mysqlUserEnabled').checked,ips:$('#mysqlUserIps').value.split(/[\s,]+/).filter(Boolean),privileges:mysqlPermissions()});});
$('#mysqlUserCancel').addEventListener('click',mysqlUserReset);
$$('[data-mysql-preset]').forEach(button=>button.addEventListener('click',()=>$$('[data-mysql-permission]').forEach(el=>el.checked=button.dataset.mysqlPreset==='all'||(button.dataset.mysqlPreset==='write'?['SELECT','INSERT','UPDATE','DELETE']:['SELECT']).includes(el.dataset.mysqlPermission))));
$('#mysqlUsers').addEventListener('click',event=>{
  const button=event.target.closest('[data-mysql-user]');if(!button)return;const user=mysqlState.data.users.find(u=>u.username===button.dataset.name);if(!user)return;
  if(button.dataset.mysqlUser==='edit'){
    mysqlState.editing=user;$('#mysqlUserTitle').textContent='Editar '+user.username;$('#mysqlUsername').value=user.username;$('#mysqlUserDatabase').value=user.database;$('#mysqlPassword').value='';$('#mysqlUserEnabled').checked=user.enabled;$('#mysqlUserIps').value=user.ips.join('\n');$$('[data-mysql-permission]').forEach(el=>el.checked=user.privileges.includes(el.dataset.mysqlPermission));renderMysql();$('#mysqlUserForm').scrollIntoView({behavior:'smooth'});
  }else previewMysql(button.dataset.mysqlUser==='delete'?{action:'delete-user',username:user.username}:{...user,action:'update-user',enabled:!user.enabled});
});
$('#mysqlNetworkForm').addEventListener('submit',event=>{event.preventDefault();previewMysql({action:'network',enabled:$('#mysqlRemote').checked});});
$('#mysqlCertificate').addEventListener('click',()=>{if(!mysqlState.data?.certificate)return;const url=URL.createObjectURL(new Blob([mysqlState.data.certificate],{type:'application/x-pem-file'})),a=document.createElement('a');a.href=url;a.download='storypulse-mysql-server.crt';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
$('#mysqlConfirm').addEventListener('change',()=>$('#mysqlApply').disabled=mysqlState.busy||!mysqlState.pending||!$('#mysqlConfirm').checked);
$('#mysqlApply').addEventListener('click',applyMysql);$('#mysqlCancel').addEventListener('click',()=>{if(!mysqlState.busy)$('#mysqlDialog').close();});
$('#mysqlDialog').addEventListener('cancel',event=>{if(mysqlState.busy)event.preventDefault();});$('#mysqlDialog').addEventListener('close',()=>{mysqlState.pending=null;$('#mysqlPassword').value='';});
$('#mysqlStructureAction').addEventListener('change',mysqlStructureMode);
$('#mysqlStructureDatabase').addEventListener('change',()=>{$('#mysqlExistingTable').value='';loadMysqlStructure();});
$('#mysqlExistingTable').addEventListener('change',loadMysqlStructure);$('#mysqlExistingColumn').addEventListener('change',mysqlPrefillColumn);
$('#mysqlAddField').addEventListener('click',()=>{if($$('#mysqlFields .mysql-field').length<32){$('#mysqlFields').insertAdjacentHTML('beforeend',mysqlFieldMarkup());mysqlSyncFields();}});
$('#mysqlFields').addEventListener('click',event=>{if(event.target.closest('.remove-field'))event.target.closest('.mysql-field').remove();});
$('#mysqlFields').addEventListener('change',event=>{
  const node=event.target.closest('.mysql-field');if(!node)return;
  const get=key=>node.querySelector('[data-field="'+key+'"]');
  if(event.target.dataset.field==='auto'&&get('auto').checked){get('primary').checked=true;get('nullable').checked=false;if(!['INT','BIGINT'].includes(get('type').value))get('type').value='BIGINT';}
  if(event.target.dataset.field==='primary'){if(get('primary').checked)get('nullable').checked=false;else get('auto').checked=false;}
  mysqlSyncFields();
});
$('#mysqlStructureForm').addEventListener('submit',event=>{event.preventDefault();previewMysql(mysqlStructurePayload());});
$('#mysqlRelationTable').addEventListener('change',async()=>{try{const data=await mysqlPost('structure',{database:$('#mysqlStructureDatabase').value,table:$('#mysqlRelationTable').value});mysqlOptions($('#mysqlRelationColumn'),data.columns.map(c=>c.name),'Elegí el campo');}catch(error){showToast(error.message);}});
$('#dbDatabase').addEventListener('change',dbUserOptions);
$('#dbLogin').addEventListener('submit',async event=>{
  event.preventDefault();if(dbState.busy)return;dbState.busy=true;
  try{
    const database=$('#dbDatabase').value,username=$('#dbUsername').value,result=await mysqlPost('login',{database,username,password:$('#dbPassword').value});
    Object.assign(dbState,{session:result.session,database,username,tables:result.tables,privileges:result.privileges,table:null,data:null,offset:0,last:Date.now(),absolute:Date.now()+60*60000});
    $('#dbLogin').hidden=true;$('#dbWorkspace').hidden=false;$('#dbLogout').hidden=false;$('#dbStatus').textContent='Conectado como '+username+' · Base '+database;dbRenderTables();
  }catch(error){$('#dbStatus').textContent=error.message;}finally{$('#dbPassword').value='';dbState.busy=false;}
});
$('#dbLogout').addEventListener('click',async()=>{const session=dbState.session;dbClear();$('#dbStatus').textContent='Sesión cerrada.';try{await mysqlPost('logout',{session});}catch{}});
$('#dbTables').addEventListener('click',event=>{const button=event.target.closest('[data-db-table]');if(!button)return;dbState.table=dbState.tables[Number(button.dataset.dbTable)].name;$('#dbSearch').value='';$('#dbSort').value='';dbLoadTable(true);});
$('#dbSearchForm').addEventListener('submit',event=>{event.preventDefault();dbLoadTable(true);});$('#dbReload').addEventListener('click',async()=>{
  if(!dbState.session)return;
  try{const result=await dbCall('tables');dbState.tables=result.tables;dbState.privileges=result.privileges;dbRenderTables();await dbLoadTable();}
  catch(error){$('#dbStatus').textContent=error.message;}
});
$('#dbPrevious').addEventListener('click',()=>{dbState.offset=Math.max(0,dbState.offset-25);dbLoadTable();});$('#dbNext').addEventListener('click',()=>{dbState.offset+=25;dbLoadTable();});
$('#dbInsert').addEventListener('click',()=>dbOpenRecord());$('#dbRecordForm').addEventListener('submit',dbSaveRecord);$('#dbRecordCancel').addEventListener('click',()=>{if(!dbState.busy)$('#dbRecordDialog').close();});
$('#dbRecordDialog').addEventListener('cancel',event=>{if(dbState.busy)event.preventDefault();});
$('#dbRecordDialog').addEventListener('close',()=>{$('#dbRecordFields').innerHTML='';dbState.record=null;});
$('#dbGridRows').addEventListener('click',async event=>{
  const button=event.target.closest('[data-db-row]');if(!button||button.disabled||dbState.busy)return;const index=Number(button.dataset.index),row=dbState.data.rows[index];
  if(button.dataset.dbRow==='edit'){dbOpenRecord(index);return;}
  if(!confirm('¿Eliminar este registro de '+dbState.table+'? Esta operación borra sus datos.'))return;
  dbState.busy=true;try{await dbCall('delete',{table:dbState.table,key:row.key,row_revision:row.revision,confirm:true});await dbLoadTable();}catch(error){$('#dbStatus').textContent=error.message;}finally{dbState.busy=false;}
});
window.addEventListener('storypulse-view',event=>{if(event.detail.startsWith('services-')||event.detail==='databases')loadMysql();});
window.addEventListener('storypulse-services-changed',()=>void loadMysql(true));
setInterval(()=>{if(document.visibilityState==='visible'&&(state.view.startsWith('services-')||state.view==='databases'||mysqlState.data?.job?.status==='running')&&(mysqlState.data?.job?.status==='running'||Date.now()-mysqlState.last>30000))loadMysql();},2500);
setInterval(()=>{if(dbState.session&&(Date.now()-dbState.last>15*60000||Date.now()>dbState.absolute)){const session=dbState.session;dbClear();$('#dbStatus').textContent='La sesión venció. Volvé a autenticarte.';mysqlPost('logout',{session}).catch(()=>{});}},15000);
mysqlStructureMode();mysqlServiceKind(readPreference('storypulse-service-kind')||'ftp');
if(state.view.startsWith('services-')||state.view==='databases')loadMysql();
