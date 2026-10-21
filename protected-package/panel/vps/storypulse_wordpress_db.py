"""Provision one local WordPress database/account; never publish its password."""
import os,secrets
from types import SimpleNamespace
import storypulse_mysql as mysql
import storypulse_versions as versions

def database_dependencies(c,p):
    mysql.configure_platform(p)
    saved=mysql.load();inventory=c.package_inventory(p)
    foreign=not mysql.STATE.exists() and any(name in inventory for name in ('mariadb-server','mariadb','mysql-server','mysql-community-server','mysql8.4-server'))
    if foreign:raise RuntimeError('Existe una base de datos ajena al panel. Se conserva; vinculala antes de instalar la aplicación.')
    return [] if saved['installed'] else list(mysql.LAYOUT['packages'])

def ensure_database(c,p):
    # Preserve a server already administered by the panel. On fresh Debian/Ubuntu
    # use their signed MariaDB packages, avoiding a second third-party repository.
    database_dependencies(c,p)
    saved=mysql.load()
    module=lambda:SimpleNamespace(**vars(mysql))
    if not saved['installed']:
        # c.apply already owns the global package lock.
        catalog=versions.refresh_locked('mysql',module())
        candidates=[row for row in catalog['versions'] if not row.get('archived')]
        if not candidates:raise RuntimeError('No hay una versión mantenida del servidor de base de datos.')
        mysql._install(candidates[0]['id'])
    else:
        c.run(['systemctl','enable','--now',mysql.SERVICE],timeout=120);mysql.wait_ready()

def prepare_database(c,p,site,user):
    ensure_database(c,p)
    config_path=site/'wp-config.php'
    if config_path.exists():
        if config_path.is_symlink() or not config_path.is_file():raise RuntimeError('Configuración WordPress insegura.')
        return
    name='wordpress_'+secrets.token_hex(4);account='wp_'+secrets.token_hex(5);password=secrets.token_urlsafe(36)
    for payload in [dict(action='create-database',database=name),dict(action='create-user',database=name,username=account,password=password,privileges=list(mysql.PRIVILEGES),ips=[],enabled=True)]:
        proposal=mysql.plan(payload);mysql.change({**payload,'revision':proposal['revision'],'confirm':True},c.flow.repair_monitors)
    # Credentials are only written inside the protected application's configuration.
    definitions={'DB_NAME':name,'DB_USER':account,'DB_PASSWORD':password,'DB_HOST':'localhost:'+mysql.SOCKET,'DB_CHARSET':'utf8mb4','DB_COLLATE':''}
    for key in ('AUTH_KEY','SECURE_AUTH_KEY','LOGGED_IN_KEY','NONCE_KEY','AUTH_SALT','SECURE_AUTH_SALT','LOGGED_IN_SALT','NONCE_SALT'):definitions[key]=secrets.token_urlsafe(48)
    text='<?php\n'+''.join("define('"+key+"', '"+value+"');\n" for key,value in definitions.items())
    text+="$table_prefix = 'wp_';\ndefine('WP_DEBUG', false);\ndefine('FS_METHOD', 'direct');\nif (!defined('ABSPATH')) { define('ABSPATH', __DIR__ . '/'); }\nrequire_once ABSPATH . 'wp-settings.php';\n"
    fd=os.open(config_path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'w',encoding='utf-8') as output:output.write(text);output.flush();os.fsync(output.fileno())
    os.chown(config_path,user.pw_uid,user.pw_gid)
    from storypulse_webapps import STATE,profile
    c.write(STATE/'wordpress-db.json',dict(profile=profile(p),database=name,username=account,socket=mysql.SOCKET))
