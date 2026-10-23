"""Server Security Monitor v3.0 - preserve the owned Zone site when publishing phpMyAdmin."""
import json,stat
from pathlib import Path

def extend(text,apps):
 marker=Path('/var/lib/storypulse-security/games/zone-web.json')
 if not marker.exists():return text
 info=marker.lstat()
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077 or info.st_size>1024:raise RuntimeError('Registro del sitio Zone inseguro.')
 if json.loads(marker.read_text())!={'site':'/var/www/server-monitor-zone','phase':'installed'}:raise RuntimeError('Registro Zone no reconocido.')
 if 'wordpress' in apps:raise RuntimeError('La raíz de esta IP pertenece a Zone. No se reemplaza por WordPress.')
 needle='location / { return 404; }'
 if text.count(needle)!=1:raise RuntimeError('La configuración web no permite publicar Zone sin reemplazar otro sitio.')
 block='''root /var/www/server-monitor-zone;
index index.php;
location / { try_files $uri $uri/ =404; }
location = /FORO { return 301 /foro/; }
location ~* ^/foro/(?:Settings(?:_bak)?\\.php|install\\.php|upgrade\\.php)$ { deny all; }
location ~* ^/foro/(?:Sources|cache|attachments|custom_avatar)/.*\\.php$ { deny all; }
location /u/ { rewrite ^/u/(.*)$ /profile.php?p=$1 last; }
location ~ ^/(?:kev|sapd/kev|seguridad|recursos|admin/assets|admin/global_assets)/.*\\.php$ { deny all; }
location ~* \\.(?:sql|log|ini|bak|zip|pwn|amx)$ { deny all; }
location ~ \\.php$ {
include /etc/nginx/fastcgi_params;
fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
fastcgi_pass unix:/run/server-monitor-zone/php.sock;
}
'''
 return text.replace(needle,block)
