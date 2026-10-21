"""Regenerar el instalador autónomo desde sus fuentes revisables; sólo usa la biblioteca estándar."""
import base64
import hashlib
import io
from pathlib import Path
import textwrap
import zipfile

root=Path(__file__).resolve().parent
names=['storypulse_cloudflare.py','storypulse_service_flow.py','storypulse_wordpress_db.py','storypulse_game_ftp.py','storypulse_games.py','storypulse_webapps.py','storypulse_catalog.py', 'storypulse_catalog_recipes.py', 'storypulse_catalog_archives.py','storypulse_archives.py','storypulse_versions.py','storypulse_uninstall.py','storypulse_panel_alerts.py','server-monitor-alerts.service','storypulse_trusted.py','storypulse_platform.py','storypulse-securityctl.py','storypulse_ports.py','storypulse_forwarding.py','storypulse_services.py',
       'storypulse_mysql.py','storypulse_cleanup.py','storypulse_system.py','storypulse_report.py',
       'storypulse-cleanup.service','storypulse-cleanup.timer','instalar-forwarding.sh','instalar-control-bloqueos.sh']
payload=io.BytesIO()
with zipfile.ZipFile(payload,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
    for name in sorted(names+['collector.py','ssh_security.ssh']):
        source=root/name if name in ('collector.py','ssh_security.ssh') else root/'vps'/name
        info=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0))
        info.compress_type=zipfile.ZIP_DEFLATED
        info.external_attr=0o644<<16
        archive.writestr(info,source.read_bytes().replace(b'\r\n',b'\n'),compresslevel=9)
encoded='\n'.join(textwrap.wrap(base64.b64encode(payload.getvalue()).decode(),100))+'\n'
encoded_hash=hashlib.sha256(encoded.encode()).hexdigest()
payload_hash=hashlib.sha256(payload.getvalue()).hexdigest()
install="""cat > "$WORK/payload.b64" <<'SERVER_MONITOR_PAYLOAD'
"""+encoded+"""SERVER_MONITOR_PAYLOAD
printf '%s  %s\\n' '"""+encoded_hash+"""' "$WORK/payload.b64" | sha256sum -c -
"""
extract="""python3 - "$WORK" <<'PY_EXTRACT'
import base64,hashlib,io,sys,zipfile
from pathlib import Path
root=Path(sys.argv[1])
data=base64.b64decode((root/'payload.b64').read_bytes().replace(b'\\n',b''),validate=True)
assert hashlib.sha256(data).hexdigest()=="""+repr(payload_hash)+""",'Paquete integrado dañado'
expected="""+'set('+repr(sorted(names+['collector.py','ssh_security.ssh']))+')'+"""
with zipfile.ZipFile(io.BytesIO(data)) as archive:
 assert set(archive.namelist())==expected and len(archive.infolist())==len(expected),'Paquete inesperado'
 for entry in archive.infolist():
  assert entry.filename in expected and entry.file_size<2*1024*1024,'Archivo inesperado'
  with (root/entry.filename).open('xb') as target:target.write(archive.read(entry))
print('Paquete integrado verificado y extraído.')
PY_EXTRACT
"""
template=(root/'vps/instalador-template.sh').read_text(encoding='utf-8')
if template.count('# PAYLOAD_INSTALLER')!=1 or template.count('# PAYLOAD_EXTRACTOR')!=1:raise RuntimeError('Faltan las marcas de construcción; se conserva el instalador anterior.')
result=template.replace('# PAYLOAD_INSTALLER',install).replace('# PAYLOAD_EXTRACTOR',extract)
(root/'instalar-servidor.sh').write_text(result,encoding='utf-8',newline='\n')
print('Instalador autónomo generado:',len(result.encode()),'bytes; SHA256',hashlib.sha256(result.encode()).hexdigest())
