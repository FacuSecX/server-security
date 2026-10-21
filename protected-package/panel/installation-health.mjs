// Only the inactive installation invokes this read-only SSH check. One shared
// promise prevents health polling from creating repeated login attempts.
export function createInstallationHealth({enabled,check}){
 let pending;
 return async()=>{
  if(!enabled)return {};
  pending??=Promise.resolve().then(check).then(value=>{
   if(value?.ready!==true||!['ready','setup'].includes(value.mode)||!/^[a-f0-9]{32}$/.test(value.installation||'')||!/^[A-F0-9]{64}$/.test(value.revision||''))throw new Error('Invalid installation proof');
   return {installation_ready:true,installation_id:value.installation,installation_revision:value.revision,installation_mode:value.mode};
  }).catch(()=>({installation_ready:false}));
  return pending;
 };
}
