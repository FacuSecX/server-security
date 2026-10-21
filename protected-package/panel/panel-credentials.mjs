import {randomBytes,scrypt as scryptCallback,timingSafeEqual} from 'node:crypto';
import {promisify} from 'node:util';
import {validatePermissions} from './panel-permissions.mjs';
const scrypt=promisify(scryptCallback);
export const accountName=value=>typeof value==='string'&&/^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,31}$/.test(value)?value.toLowerCase():null;
export function accountPassword(value){if(typeof value!=='string'||value.length<12||value.length>128||!value.isWellFormed()||/[\x00-\x1f\x7f]/.test(value))throw Object.assign(new Error('Usá una contraseña de 12 a 128 caracteres, sin caracteres de control.'),{status:400});return value;}
export const secretEqual=(a,b)=>{if(typeof a!=='string'||typeof b!=='string')return false;const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&timingSafeEqual(x,y);};
export async function passwordHash(value,salt=randomBytes(16).toString('hex')){return {salt,hash:(await scrypt(value,salt,32,{N:32768,r:8,p:3,maxmem:64*1024*1024})).toString('hex')};}
export function validateAccounts(accounts){
  if(!accounts||accounts.version!==1||!Array.isArray(accounts.users)||accounts.users.length<1||accounts.users.length>100||accounts.users.filter(u=>u.primary).length!==1||accounts.users.some(u=>!accountName(u.username)||accountName(u.username)!==u.username||!/^([a-f0-9]{32}|primary-admin)$/.test(u.id)||! /^[a-f0-9]{32}$/.test(u.salt)||! /^[a-f0-9]{64}$/.test(u.hash)||typeof u.primary!=='boolean'||typeof u.must_change!=='boolean'||(u.id==='primary-admin')!==u.primary)||!accounts.users.some(u=>u.primary&&u.id==='primary-admin')||new Set(accounts.users.map(u=>u.username)).size!==accounts.users.length||new Set(accounts.users.map(u=>u.id)).size!==accounts.users.length)throw new Error('El almacén de usuarios no es válido. Se bloqueó el acceso.');
  for(const u of accounts.users)if(u.permissions!==undefined){try{validatePermissions(u.permissions);}catch{throw new Error('El almacén de usuarios contiene permisos no válidos.');}}
  return accounts;
}
