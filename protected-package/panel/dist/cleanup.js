/* Cleanup controls use fixed actions. No server paths or shell text are accepted. */
const cleanupState={data:null,loading:false,busy:false,pending:null,finished:null};
const cleanupLabels={PENDING:'Pendiente',CANCELLED:'Cancelada',COMPLETED:'Finalizada',FAILED:'Error',RUNNING:'En curso'};
const cleanupDates=new Intl.DateTimeFormat('es-AR',{dateStyle:'short',timeStyle:'short'});
function cleanupDate(value){return value?cleanupDates.format(new Date(value*1000)):'—';}
function cleanupBytes(value){const n=Math.max(0,Number(value)||0);return n>=1024**3?(n/1024**3).toFixed(2)+' GB':(n/1024**2).toFixed(2)+' MB';}
async function cleanupPost(path,body){
  const response=await fetch('/api/cleanup/'+path,{method:'POST',headers:{'Content-Type':'application/json','X-StoryPulse-Token':state.actionToken},body:JSON.stringify(body),signal:AbortSignal.timeout(45000)});
  const result=await response.json();if(!response.ok)throw new Error(result.error||'No se pudo completar la operación.');return result;
}
function renderCleanup(){
  const d=cleanupState.data,busy=cleanupState.busy||d?.job?.status==='running';
  $('#cleanupRemoteSize').textContent=d?cleanupBytes(d.storage.total_bytes):'—';
  $('#cleanupLocalSize').textContent=d?cleanupBytes(d.local.total_bytes):'—';
  $('#cleanupDisk').textContent=d?cleanupBytes(d.storage.disk.free)+' libres':'—';
  $('#cleanupDiskTotal').textContent=d?'de '+cleanupBytes(d.storage.disk.total)+' · usados '+cleanupBytes(d.storage.disk.used):'Disco del servidor';
  $('#cleanupEventCount').textContent=d?fmt(d.local.events):'—';
  $('#cleanupSources').textContent=d?'Journal: '+cleanupBytes(d.storage.journal_bytes)+' · Logs y reportes: '+cleanupBytes(d.storage.files_bytes)+' · Base local: '+cleanupBytes(d.local.database_bytes):'Consultando el espacio ocupado…';
  $('#cleanupTimer').textContent=d?(d.timer_active?'Programador del servidor activo. Ejecuta las limpiezas aunque este panel esté cerrado.':'El programador del servidor está detenido: las limpiezas no podrán ejecutarse.'):'';
  $('#cleanupTimer').classList.toggle('error',!!d&&!d.timer_active);
  $('#cleanupStatus').textContent=d?.job?.status==='running'||d?.job?.status==='error'?d.job.message:d?.last_run?'Última ejecución: '+cleanupLabels[d.last_run.status]+' · '+cleanupDate(d.last_run.finished_at)+(d.last_run.error?' · '+d.last_run.error:''):'Todavía no se ejecutó ninguna limpieza.';
  $('#cleanupStatus').classList.toggle('error',d?.job?.status==='error'||d?.last_run?.status==='FAILED');
  $('#cleanupWarnings').textContent=(d?.local?.warnings||[]).join(' ');
  $('#cleanupRows').innerHTML=(d?.schedules||[]).slice().sort((a,b)=>b.created_at-a.created_at).map(row=>'<tr><td>'+cleanupDate(row.at)+'</td><td>'+(row.interval_days?'Cada '+row.interval_days+' día(s)':'Una sola vez')+'</td><td><span class="cleanup-status '+esc(row.status)+'">'+esc(cleanupLabels[row.status]||row.status)+'</span></td><td>'+(row.last_finished_at?'Última: '+cleanupDate(row.last_finished_at)+' · '+fmt(row.runs)+' ejecución(es)':row.finished_at?cleanupDate(row.finished_at):row.cancelled_at?cleanupDate(row.cancelled_at):'—')+(row.error?'<br>'+esc(row.error):'')+'</td><td><div class="port-actions">'+(row.status==='PENDING'?'<button data-cleanup-action="cancel" data-id="'+esc(row.id)+'" '+(busy?'disabled':'')+'>Cancelar</button>':'')+(row.status!=='RUNNING'?'<button data-cleanup-action="delete" data-id="'+esc(row.id)+'" '+(busy?'disabled':'')+'>Eliminar</button>':'')+'</div></td></tr>').join('')||'<tr><td colspan="5">No hay programaciones guardadas.</td></tr>';
  $('#cleanupNow').disabled=!d||busy;$('#cleanupSchedule').disabled=!d||busy||!d.timer_active;
  $('#cleanupRefresh').disabled=busy;
}
async function loadCleanup(){
  if(cleanupState.loading||cleanupState.busy)return;cleanupState.loading=true;
  try{
    const response=await fetch('/api/cleanup',{signal:AbortSignal.timeout(45000)}),data=await response.json();
    if(!response.ok)throw new Error(data.error||'No se pudo consultar la limpieza.');
    cleanupState.data=data;state.actionToken=data.action_token;
    if(data.job?.status==='success'&&cleanupState.finished!==data.job.id){cleanupState.finished=data.job.id;showToast(data.job.message);load();}
    renderCleanup();
  }catch(error){$('#cleanupStatus').textContent=error.message;$('#cleanupStatus').classList.add('error');}
  finally{cleanupState.loading=false;}
}
async function reviewCleanup(request){
  cleanupState.busy=true;renderCleanup();
  try{
    const plan=await cleanupPost('plan',request);cleanupState.pending={...plan.request,revision:plan.revision};
    const destructive=['clean','schedule'].includes(request.action);
    $('#cleanupConfirmTitle').textContent=({clean:'Limpiar todos los registros',schedule:'Programar limpieza automática',cancel:'Cancelar programación',delete:'Eliminar programación'})[request.action];
    $('#cleanupConfirmText').textContent=destructive?plan.warning:request.action==='cancel'?'La programación quedará cancelada y no se ejecutará.':'Se eliminará esta programación. Si estaba pendiente, ya no se ejecutará.';
    $('#cleanupConfirmDetail').textContent=request.action==='schedule'?'Primera limpieza: '+cleanupDate(request.at)+(request.interval_days?' · cada '+request.interval_days+' día(s)':' · una sola vez'):request.action==='clean'?'Se limpiarán aproximadamente '+cleanupBytes(plan.storage.total_bytes)+' en el servidor y el historial local. Los registros nuevos seguirán llegando.':'';
    $('#cleanupConfirmCheck').checked=false;$('#cleanupConfirmApply').disabled=true;
    $('#cleanupConfirm').showModal();
  }catch(error){showToast(error.message);}finally{cleanupState.busy=false;renderCleanup();}
}
$('#cleanupConfirmCheck').addEventListener('change',()=>$('#cleanupConfirmApply').disabled=!$('#cleanupConfirmCheck').checked);
$('#cleanupConfirmCancel').addEventListener('click',()=>$('#cleanupConfirm').close());
$('#cleanupConfirmApply').addEventListener('click',async()=>{
  if(!cleanupState.pending||!$('#cleanupConfirmCheck').checked)return;
  const request=cleanupState.pending;cleanupState.pending=null;cleanupState.busy=true;$('#cleanupConfirmApply').disabled=true;
  try{const result=await cleanupPost('apply',{...request,confirm:true});cleanupState.data.job=result.job;$('#cleanupConfirm').close();showToast('Operación enviada al servidor.');}
  catch(error){$('#cleanupConfirmDetail').textContent=error.message;$('#cleanupConfirmApply').disabled=false;cleanupState.pending=request;}
  finally{cleanupState.busy=false;renderCleanup();}
});
$('#cleanupConfirm').addEventListener('close',()=>cleanupState.pending=null);
$('#cleanupNow').addEventListener('click',()=>reviewCleanup({action:'clean'}));
$('#cleanupRefresh').addEventListener('click',loadCleanup);
$('#cleanupScheduleForm').addEventListener('submit',event=>{
  event.preventDefault();const at=Math.floor(new Date($('#cleanupAt').value).getTime()/1000);
  if(!Number.isSafeInteger(at)||at<Math.floor(Date.now()/1000)+60){showToast('Elegí una fecha al menos un minuto después de ahora.');return;}
  reviewCleanup({action:'schedule',at,interval_days:Number($('#cleanupInterval').value)});
});
$('#cleanupRows').addEventListener('click',event=>{const button=event.target.closest('[data-cleanup-action]');if(button)reviewCleanup({action:button.dataset.cleanupAction,id:button.dataset.id});});
$('#cleanupTimezone').textContent='Fecha y hora de tu computadora: '+Intl.DateTimeFormat().resolvedOptions().timeZone+'.';
window.addEventListener('storypulse-view',event=>{if(event.detail==='cleanup')loadCleanup();});
setInterval(()=>{if(state.view==='cleanup'&&!document.hidden)loadCleanup();},3000);
if(state.view==='cleanup')loadCleanup();
