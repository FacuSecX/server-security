/*
Server Security Monitor v2.0
Created by FacuSecX
https://github.com/FacuSecX/
*/
export function readJsonBody(request, limit = 16384, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    let size = 0, chunks = [], settled = false;
    const error = (message, status = 400) => Object.assign(new Error(message), {status});
    const finish = (failure, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      request.removeListener('data', data);
      request.removeListener('end', end);
      request.removeListener('aborted', aborted);
      request.removeListener('error', failed);
      chunks = [];
      if (failure) {
        
        request.resume();
        request.once('error', () => {});
        reject(failure);
      } else resolve(value);
    };
    const data = chunk => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buffer.length;
      if (size > limit) finish(error('La solicitud es demasiado grande.', 413));
      else chunks.push(buffer);
    };
    const end = () => {
      try {
        const body = size ? JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(Buffer.concat(chunks, size))) : {};
        if (!body || Array.isArray(body) || typeof body !== 'object') throw new Error();
        finish(null, body);
      } catch { finish(error('El cuerpo JSON no es válido.')); }
    };
    const aborted = () => finish(error('La solicitud se interrumpió.'));
    const failed = failure => finish(failure);
    const timer = setTimeout(() => finish(error('La solicitud superó el tiempo máximo.', 408)), timeoutMs);
    const type = String(request.headers?.['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (type !== 'application/json') { finish(error('Se requiere Content-Type application/json.', 415)); return; }
    const length = request.headers?.['content-length'];
    if (length !== undefined && (!/^\d+$/.test(String(length)) || Number(length) > limit)) {
      finish(error('La solicitud es demasiado grande.', 413)); return;
    }
    request.on('data', data);
    request.on('end', end);
    request.once('aborted', aborted);
    request.once('error', failed);
  });
}

export async function readResponseJson(response, limit=1024*1024) {
  const reader=response.body.getReader();
  let size=0;const chunks=[];
  try {
    while(true){
      const {done,value}=await reader.read();if(done)break;
      size+=value.byteLength;
      if(size>limit){await reader.cancel();throw new Error('La respuesta externa es demasiado grande.');}
      chunks.push(Buffer.from(value));
    }
  } finally {reader.releaseLock();}
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,size)));
}
