import {passwordHash,accountPassword,validateAccounts,secretEqual} from './panel-credentials.mjs';
import {permissionsFor} from './panel-permissions.mjs';
import {probeLogin} from './migration-login-probe.mjs';
// Migration of a mismatched single-owner store requires independent reauthentication
// against the running panel and an exact match of its account metadata. It does not
// grant installation: the elevated native installer must still verify Windows Hello.
export async function checkMigrationAccount(accounts,password,port,{probe=probeLogin,onStep=()=>{}}={}){
 validateAccounts(accounts);accountPassword(password);
 const primary=accounts.users.find(u=>u.primary);
 if(secretEqual((await passwordHash(password,primary.salt)).hash,primary.hash))return {accounts,refresh:false};
 onStep('local-mismatch');
 if(!Number.isInteger(port)||port<1||port>65535){onStep('no-valid-port');return null;}
 const live=await probe(port,primary.username,password,{inspectUsers:true});
 if(live?.result!=='accepted'){onStep('live-'+(typeof live==='string'?live:'invalid-response'));return null;}
 onStep('live-authenticated');
 // Never reconstruct another user's password from a stale or different account file.
 if(accounts.users.length!==1||live.users?.length!==1)throw Object.assign(new Error('store mismatch'),{code:'STORE_MISMATCH'});
 const expected={id:primary.id,username:primary.username,administrator:true,must_change:primary.must_change,permissions:permissionsFor(primary)};
 const same=record=>record&&['id','username','administrator','must_change'].every(key=>record[key]===expected[key])&&Array.isArray(record.permissions)&&record.permissions.length===expected.permissions.length&&expected.permissions.every(p=>record.permissions.includes(p));
 if(!same(live.user)||!same(live.users[0]))throw Object.assign(new Error('store mismatch'),{code:'STORE_MISMATCH'});
 const next=structuredClone(accounts);Object.assign(next.users[0],await passwordHash(password));
 onStep('verified-current-owner');
 return {accounts:next,refresh:true};
}
