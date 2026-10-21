// Installer-only verifier. Credentials arrive through stdin, never arguments or logs.
// Exit status: 0 verified, 2 mismatch, 3 invalid store, 4 invalid request, 5 runtime failure.
const fail=code=>{process.exitCode=code;};
let step='starting',diagnosticPort=null;
try {
  const {validateAccounts,accountPassword}=await import('./panel-credentials.mjs');
  const {checkMigrationAccount}=await import('./migration-account-check.mjs');
  const chunks=[];let size=0;
  for await(const chunk of process.stdin){size+=chunk.length;if(size>1100000)throw new Error('request');chunks.push(chunk);}
  let value;
  try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));}catch{fail(4);}
  if(process.exitCode===undefined){
    let accounts;
    try{accounts=validateAccounts(value?.accounts);}catch{fail(3);}
    if(accounts){
      let password;
      try{password=accountPassword(value.password);}catch{fail(2);}
      if(password!==undefined){
        diagnosticPort=value.port??null;
        const result=await checkMigrationAccount(accounts,password,value.port,{onStep:value=>{step=value;}});
        fail(result?0:2);if(result)process.stdout.write(JSON.stringify(result));
      }
    }
  }
}catch(error){fail(error.code==='STORE_MISMATCH'?6:5);}
// No credentials, hashes, usernames or session tokens are written to this status file.
try{
 const {fileURLToPath}=await import('node:url');const {resolve,dirname}=await import('node:path');
 const folder=dirname(fileURLToPath(import.meta.url));
 if(process.platform==='win32'&&folder.toLowerCase()===resolve(process.env.ProgramFiles,'FacuSecX','ServerSecurityMonitor','panel').toLowerCase()){
  const {writeFile}=await import('node:fs/promises');await writeFile(resolve(folder,'..','..','migration-verification-status.json'),JSON.stringify({time:new Date().toISOString(),code:process.exitCode,step,port:diagnosticPort}));
 }
}catch{}
