// Server Security Monitor v3.0
// Created by FacuSecX
// https://github.com/FacuSecX/
import {isIP} from 'node:net';
const names=new Intl.DisplayNames(['en'],{type:'region'});
export function countryName(code){
 if(typeof code!=='string'||!/^[A-Z]{2}$/.test(code)||['XX','ZZ','EU','AP'].includes(code))return '';
 const name=names.of(code);return name===code?'':name;
}
export function ipKey(ip){
 const version=isIP(ip);if(!version||ip.includes('%'))return null;
 const key=Buffer.alloc(16);
 if(version===4){ip.split('.').forEach((part,index)=>key[index+12]=Number(part));return {version,key};}
 let value=ip.toLowerCase();
 if(value.includes('.')){const index=value.lastIndexOf(':'),parts=value.slice(index+1).split('.').map(Number);value=value.slice(0,index+1)+((parts[0]<<8)|parts[1]).toString(16)+':'+((parts[2]<<8)|parts[3]).toString(16);}
 const halves=value.split('::'),left=halves[0]?halves[0].split(':'):[],right=halves[1]?halves[1].split(':'):[];
 const groups=halves.length===2?[...left,...Array(8-left.length-right.length).fill('0'),...right]:left;
 if(groups.length!==8)return null;groups.forEach((part,index)=>key.writeUInt16BE(parseInt(part,16),index*2));return {version,key};
}
