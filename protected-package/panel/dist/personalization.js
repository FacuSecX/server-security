/* Apply saved appearance before styles load. Audio is lazy and user-initiated. */
(() => {
  'use strict';
  const key='storypulse-appearance';
  const defaults={mode:'dark',theme:'ocean',motion:'subtle',sound:false};
  const themes=new Set(['ocean','graphite','aurora','emerald','copper']);
  let preferences={...defaults},saved=true,audio=null,idleTimer=null,lastSound=-Infinity,soundError='';
  const voices=new Set();
  function normalize(value){
    return {motion:['off','subtle','fluid'].includes(value?.motion)?value.motion:defaults.motion,
      mode:['dark','light','ivory','pearl'].includes(value?.mode)?value.mode:defaults.mode,
      theme:themes.has(value?.theme)?value.theme:defaults.theme,sound:value?.sound===true};
  }
  let stored=null;
  try{stored=localStorage.getItem(key);}catch{saved=false;}
  try{preferences=normalize(JSON.parse(stored));}catch{}
  function quiet(){
    clearTimeout(idleTimer);
    for(const voice of voices){
      voice.osc.onended=null;
      try{voice.osc.stop();}catch{}
      voice.osc.disconnect();voice.gain.disconnect();
    }
    voices.clear();
    if(audio?.state==='running')audio.suspend().catch(()=>{});
  }
  function apply(){
    document.documentElement.dataset.colorMode=preferences.mode;
    document.documentElement.dataset.panelTheme=preferences.theme;
    document.documentElement.dataset.panelMotion=preferences.motion;
    document.documentElement.dataset.panelSound=preferences.sound?'on':'off';
    document.documentElement.style.colorScheme=preferences.mode==='dark'?'dark':'light';
    if(!preferences.sound)quiet();
    window.dispatchEvent(new Event('storypulse-appearance'));
  }
  function render(){
    for(const name of ['mode','theme','motion'])
      document.querySelectorAll(`input[name="panel-${name}"]`).forEach(input=>input.checked=input.value===preferences[name]);
    document.querySelectorAll('input[name="panel-sound"]').forEach(input=>input.checked=input.value===(preferences.sound?'on':'off'));
    document.querySelectorAll('[data-preview-sound]').forEach(button=>button.disabled=!preferences.sound);
    const status=document.getElementById('appearanceSaved'),soundStatus=document.getElementById('appearanceSoundStatus');
    const names={ocean:'Océano',graphite:'Grafito',aurora:'Aurora',emerald:'Esmeralda',copper:'Cobre'};
    if(status)status.textContent=(saved?'Guardado automáticamente':'Aplicado para esta ventana; el navegador no permite guardar la preferencia')+' · '+names[preferences.theme]+' / '+({dark:'Oscuro',light:'Claro',ivory:'Marfil',pearl:'Perla'}[preferences.mode]);
    if(soundStatus){
      soundStatus.textContent=soundError||(preferences.sound?'Sonidos activados: un clic suave para los botones y un tono distinto para la campanita.':'Los sonidos están desactivados.');
      soundStatus.classList.toggle('error',!!soundError);
    }
  }
  function change(next){
    preferences=normalize(next);saved=true;soundError='';
    try{localStorage.setItem(key,JSON.stringify(preferences));}catch{saved=false;}
    apply();render();
  }
  async function play(kind){
    if(!preferences.sound||document.hidden||performance.now()-lastSound<45||voices.size>6)return;
    lastSound=performance.now();clearTimeout(idleTimer);
    try{
      const Audio=window.AudioContext||window.webkitAudioContext;
      if(!Audio)throw new Error('audio unavailable');
      if(!audio||audio.state==='closed')audio=new Audio({latencyHint:'interactive'});
      const context=audio;
      if(context.state==='suspended')await context.resume();
      if(!preferences.sound||document.hidden||audio!==context||context.state!=='running')return;
      const notes=kind==='notification'?[[880,0,.095],[1174.66,.065,.095]]:[[660,0,.045]];
      for(const [frequency,delay,duration] of notes){
        const osc=context.createOscillator(),gain=context.createGain(),start=context.currentTime+.005+delay;
        osc.type='sine';osc.frequency.setValueAtTime(frequency,start);
        if(kind!=='notification')osc.frequency.exponentialRampToValueAtTime(440,start+duration);
        gain.gain.setValueAtTime(.0001,start);gain.gain.exponentialRampToValueAtTime(.035,start+.006);
        gain.gain.exponentialRampToValueAtTime(.0001,start+duration);
        osc.connect(gain);gain.connect(context.destination);
        const voice={osc,gain};voices.add(voice);
        osc.onended=()=>{osc.disconnect();gain.disconnect();voices.delete(voice);};
        osc.start(start);osc.stop(start+duration+.01);
      }
      // No audio processing remains active while the user is idle.
      idleTimer=setTimeout(()=>{if(audio===context&&context.state==='running')context.suspend().catch(()=>{});},400);
    }catch{
      quiet();soundError='Tu navegador no pudo reproducir el sonido. La navegación sigue disponible.';render();
    }
  }
  apply();
  document.addEventListener('DOMContentLoaded',()=>{
    render();
    document.getElementById('appearanceForm')?.addEventListener('change',event=>{
      const input=event.target;
      if(input.name==='panel-mode')change({...preferences,mode:input.value});
      if(input.name==='panel-motion')change({...preferences,motion:input.value});
      if(input.name==='panel-theme')change({...preferences,theme:input.value});
      if(input.name==='panel-sound'){
        change({...preferences,sound:input.value==='on'});
        if(event.isTrusted&&preferences.sound)void play('menu');
      }
    });
    document.getElementById('appearanceReset')?.addEventListener('click',()=>change(defaults));
    document.addEventListener('click',event=>{
      if(!event.isTrusted||!preferences.sound||!(event.target instanceof Element))return;
      const button=event.target.closest('button,summary');
      if(!button||button.disabled||button.getAttribute('aria-disabled')==='true'||button.closest('[inert]'))return;
      void play(button.id==='notificationBell'||button.dataset.previewSound==='notification'?'notification':'menu');
    },true);
    document.addEventListener('visibilitychange',()=>{if(document.hidden)quiet();});
    window.addEventListener('pagehide',()=>{
      quiet();if(audio&&audio.state!=='closed')audio.close().catch(()=>{});audio=null;
    });
  },{once:true});
})();
