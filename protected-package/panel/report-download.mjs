import {mkdirSync,openSync,writeFileSync,closeSync} from 'node:fs';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';

export async function downloadReport({securityCtl,directory,openFile=true}) {
  const report = await securityCtl('report-download', {});
  if (!/^ssh_reporte_[A-Za-z0-9_-]+\.txt$/.test(report.name || '') ||
      !Number.isSafeInteger(report.size) || report.size < 0 || report.size > 16*1024*1024 ||
      typeof report.content !== 'string' || report.content.length > 24*1024*1024 ||
      report.content.length % 4 !== 0 || /[^A-Za-z0-9+/=]/.test(report.content)) {
    throw new Error('El servidor devolvió un reporte inválido.');
  }
  const content = Buffer.from(report.content, 'base64');
  if (content.length !== report.size || content.toString('base64') !== report.content) throw new Error('La descarga del reporte quedó incompleta.');
  mkdirSync(directory, {recursive:true});
  let saved = join(directory, report.name);
  // New files only: never follow a link or replace an unrelated local file.
  let descriptor;
  try { descriptor = openSync(saved, 'wx', 0o600); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    saved = join(directory, report.name.replace(/\.txt$/, '-' + Date.now() + '-' + randomBytes(4).toString('hex') + '.txt'));
    descriptor = openSync(saved, 'wx', 0o600);
  }
  // Use a stable unique name on every download, without executing a shell/BAT.
  try { writeFileSync(descriptor, content); } finally { closeSync(descriptor); }
  if (openFile && process.platform === 'win32') {
    // Opening text in Notepad cannot execute report contents as a command.
    await new Promise((resolve,reject)=>{
      const child = spawn(join(process.env.SystemRoot||'C:\\Windows','System32','notepad.exe'), [saved], {detached:true,stdio:'ignore',windowsHide:true});
      child.once('error',()=>reject(new Error('El reporte se guardó, pero no se pudo abrir en el Bloc de notas.')));
      child.once('spawn',()=>{child.unref();resolve();});
    });
  }
  return saved;
}
