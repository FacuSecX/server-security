import {spawn} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {connectionArgs} from './ssh-auth.mjs';

export function createTerminalRunner({root,ssh,ensureConnection,redact=value=>value,spawnProcess=spawn}) {
  return async (command,verify=()=>{})=>{
    const program=readFileSync(join(root,'terminal-worker.py')).toString('base64');
    const fixedCommand="exec python3 -c 'import base64;exec(compile(base64.b64decode(\""+program+"\"),\"<server-monitor-terminal>\",\"exec\"))'";
    await ensureConnection();
    verify();
    return new Promise((resolve,reject)=>{
      const child=spawnProcess(ssh.plinkPath,[...connectionArgs(ssh),'-share','-no-trivial-auth',ssh.user+'@'+ssh.host,fixedCommand],
        {windowsHide:true,shell:false,stdio:['pipe','pipe','pipe']});
      let output='',stderr='',size=0,settled=false;
      const finish=(error,value)=>{if(settled)return;settled=true;clearTimeout(timer);error?reject(error):resolve(value);};
      const timer=setTimeout(()=>{child.kill();finish(new Error('La terminal superó el tiempo máximo. No se repetirá el comando automáticamente.'));},75000);
      child.stdout.setEncoding('utf8');child.stderr.setEncoding('utf8');
      child.stdout.on('data',chunk=>{size+=Buffer.byteLength(chunk);if(size>1024*1024){child.kill();finish(new Error('La respuesta de terminal superó el límite.'));}else output+=chunk;});
      child.stderr.on('data',chunk=>{stderr=redact(stderr+chunk).slice(-8192);});
      child.stdin.on('error',()=>{});
      child.once('error',()=>finish(new Error('No se pudo iniciar la conexión de terminal.')));
      child.once('close',code=>{
        if(settled)return;
        try {
          const value=JSON.parse(output);
          if(code!==0||value.ok!==true||typeof value.stdout!=='string'||typeof value.stderr!=='string'||
            Buffer.byteLength(value.stdout)+Buffer.byteLength(value.stderr)>512*1024||!Number.isInteger(value.exit_code)||
            typeof value.timed_out!=='boolean'||typeof value.truncated!=='boolean'||!Number.isFinite(value.duration_ms))
            throw new Error();
          finish(null,{stdout:redact(value.stdout),stderr:redact(value.stderr),exit_code:value.exit_code,
            timed_out:value.timed_out,truncated:value.truncated,duration_ms:value.duration_ms});
        } catch {finish(new Error(stderr||'El servidor no devolvió una respuesta de terminal válida. No se repetirá el comando.'));}
      });
      child.stdin.end(JSON.stringify({command}));
    });
  };
}