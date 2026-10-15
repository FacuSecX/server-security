/*
Server Security Monitor v2.0
Created by FacuSecX
https://github.com/FacuSecX/
*/
(() => {
  'use strict';
  const preferenceKey='server-monitor-alert-sound', cursorPrefix='server-monitor-alert-heard:';
  const tones={chime:[[784,0,.16],[1046.5,.13,.22]],pulse:[[740,0,.12],[740,.19,.12],[988,.38,.18]],soft:[[523.25,0,.3],[659.25,.12,.3],[783.99,.24,.3]]};
  let config={enabled:true,tone:'chime'},audio=null,pending=null,running=false,contextBlocked=false,timer=null;
  const memory=new Map();let voices=[];
  try{const value=JSON.parse(localStorage.getItem(preferenceKey));if(value)config={enabled:value.enabled===true,tone:tones[value.tone]?value.tone:'chime'};}catch{}
  function render(){
    const enabled=document.getElementById('alertSoundEnabled'),tone=document.getElementById('alertSoundTone'),status=document.getElementById('alertSoundStatus');
    if(enabled)enabled.checked=config.enabled;if(tone)tone.value=config.tone;
    const preview=document.getElementById('alertSoundPreview');if(preview)preview.disabled=!config.enabled;
    if(status)status.textContent=contextBlocked?'Hay una alerta nueva. Hacé clic en «Habilitar sonido» para escucharla.':config.enabled?'Se avisa una sola vez por cada lote de alertas nuevas.':'Avisos sonoros de alertas desactivados.';
    const unlock=document.getElementById('alertSoundUnlock');if(unlock)unlock.hidden=!contextBlocked;
    const banner=document.getElementById('alertSoundPending');if(banner)banner.hidden=!contextBlocked;
  }
  function persist(){try{localStorage.setItem(preferenceKey,JSON.stringify(config));}catch{}render();}
  function quiet(){clearTimeout(timer);for(const [osc,gain] of voices){try{osc.stop();}catch{}osc.disconnect();gain.disconnect();}voices=[];if(audio?.state==='running')audio.suspend().catch(()=>{});}
  async function play(preview=false){
    if(!config.enabled)return false;
    try{
      const Audio=window.AudioContext||window.webkitAudioContext;if(!Audio)return false;
      if(!audio||audio.state==='closed')audio=new Audio({latencyHint:'interactive'});
      
      if(audio.state!=='running'){
        const resumed=audio.resume().then(()=>audio.state==='running').catch(()=>false);
        if(!await Promise.race([resumed,new Promise(resolve=>setTimeout(()=>resolve(false),250))])){contextBlocked=true;render();return false;}
      }
      if(!config.enabled)return false;
      quiet();await audio.resume();contextBlocked=false;
      for(const [frequency,delay,duration] of tones[config.tone]){
        const osc=audio.createOscillator(),gain=audio.createGain(),start=audio.currentTime+.015+delay;
        osc.type='sine';osc.frequency.setValueAtTime(frequency,start);
        gain.gain.setValueAtTime(.0001,start);gain.gain.exponentialRampToValueAtTime(.065,start+.018);gain.gain.exponentialRampToValueAtTime(.0001,start+duration);
        osc.connect(gain);gain.connect(audio.destination);const voice=[osc,gain];voices.push(voice);
        osc.onended=()=>{osc.disconnect();gain.disconnect();voices=voices.filter(item=>item!==voice);};osc.start(start);osc.stop(start+duration+.01);
      }
      timer=setTimeout(quiet,900);render();return true;
    }catch{contextBlocked=true;render();return false;}
  }
  function cursor(key){try{return Math.max(memory.get(key)||0,Number(localStorage.getItem(key))||0);}catch{return memory.get(key)||0;}}
  function save(key,value){memory.set(key,value);try{localStorage.setItem(key,String(value));}catch{}}
  async function announce(){
    if(running||!pending)return;running=true;
    try{
      const execute=async()=>{
        const {key,through,latest}=pending;
        if(latest<=cursor(key)){pending=null;contextBlocked=false;render();return;}
        if(!config.enabled||await play()){save(key,through);contextBlocked=false;render();if(pending?.through<=through)pending=null;}
      };
      
      if(navigator.locks)await navigator.locks.request('server-monitor-alert-audio',execute);else await execute();
    }finally{running=false;}
  }
  function discover(value){
    if(typeof value.inbox_id!=='string'||!/^[a-f0-9]{32}$/.test(value.inbox_id)||!Number.isSafeInteger(value.latest_notice_id)||!Number.isSafeInteger(value.through_id))return;
    const key=cursorPrefix+value.inbox_id;
    if(value.latest_notice_id>cursor(key)){
      pending={key,through:value.through_id,latest:value.latest_notice_id};void announce();
    }else if(!value.latest_notice_id)save(key,value.through_id);
  }
  window.addEventListener('server-monitor-notifications',event=>discover(event.detail));
  window.addEventListener('storage',event=>{if(event.key===preferenceKey){try{const value=JSON.parse(event.newValue);config={enabled:value?.enabled===true,tone:tones[value?.tone]?value.tone:'chime'};}catch{}render();}if(event.key?.startsWith(cursorPrefix))void announce();});
  document.addEventListener('DOMContentLoaded',()=>{
    render();document.getElementById('alertSoundEnabled')?.addEventListener('change',event=>{config.enabled=event.target.checked;if(!config.enabled)quiet();persist();void announce();});
    document.getElementById('alertSoundTone')?.addEventListener('change',event=>{if(tones[event.target.value])config.tone=event.target.value;persist();});
    document.getElementById('alertSoundPreview')?.addEventListener('click',()=>{void play(true);});
    for(const id of ['alertSoundUnlock','alertSoundPending'])document.getElementById(id)?.addEventListener('click',()=>{void announce();});
    document.addEventListener('pointerdown',event=>{if(event.isTrusted&&pending&&contextBlocked)void announce();},{passive:true});
    window.addEventListener('pagehide',()=>{quiet();if(audio)audio.close().catch(()=>{});audio=null;});
  },{once:true});
})();
