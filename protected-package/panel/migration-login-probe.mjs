import http from 'node:http';
import {randomBytes} from 'node:crypto';
export async function probeLogin(port,username,password,{inspectUsers=false}={}){
 if(!Number.isInteger(port)||port<1||port>65535)return 'unavailable';
 const tab=randomBytes(16).toString('hex');
 function request(path,body,extra={},method='POST'){return new Promise((resolve,reject)=>{
  const value=body===undefined?'':JSON.stringify(body),req=http.request({host:'127.0.0.1',port,path,method,headers:{Host:'127.0.0.1:'+port,Origin:'http://127.0.0.1:'+port,'Content-Type':'application/json','Content-Length':Buffer.byteLength(value),'X-Panel-Tab':tab,...extra}},res=>{
   let size=0,chunks=[];res.on('data',chunk=>{size+=chunk.length;if(size>16384)req.destroy(new Error('Response too large'));else chunks.push(chunk);});
   res.on('error',reject);res.on('end',()=>{try{resolve({status:res.statusCode,body:JSON.parse(Buffer.concat(chunks).toString('utf8')),cookies:res.headers['set-cookie']||[]});}catch{reject(new Error('Invalid response'));}});
  });req.setTimeout(4000,()=>req.destroy(new Error('Timeout')));req.on('error',reject);req.end(value);
 });}
 try{
  const response=await request('/api/auth/login',{username,password,tab});
  if(response.status===429)return 'throttled';
  if(response.status===401||response.status===400)return 'rejected';
  if(response.status!==200||response.body?.user?.administrator!==true||response.body?.user?.username!==username)return 'unavailable';
  const csrf=response.body.csrf,cookie=response.cookies.map(x=>x.split(';',1)[0]).find(x=>/^ssm_session=[a-f0-9]{64}$/.test(x));
  if(typeof csrf!=='string'||!cookie)return 'unavailable';
  let users;
  try{
   if(inspectUsers){const listing=await request('/api/auth/users',undefined,{'X-Panel-CSRF':csrf,Cookie:cookie},'GET');if(listing.status!==200||!Array.isArray(listing.body.users))return 'unavailable';users=listing.body.users;}
   return inspectUsers?{result:'accepted',user:response.body.user,users}:'accepted';
  }finally{await request('/api/auth/logout',{}, {'X-Panel-CSRF':csrf,Cookie:cookie});}
 }catch{return 'unavailable';}
}
