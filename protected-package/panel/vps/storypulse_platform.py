"""Fixed Linux distribution/package profiles. Never accept package names from HTTP."""
import json
import os
from pathlib import Path
import re
import shlex
import shutil

SAFE_PATH='/usr/sbin:/usr/bin:/sbin:/bin'
class PlatformError(RuntimeError):pass

def detect(path=Path('/etc/os-release')):
    values={}
    for line in path.read_text(encoding='utf-8').splitlines():
        if not re.match(r'^[A-Z_]+=',line):continue
        key,value=line.split('=',1)
        parts=shlex.split(value,comments=True)
        values[key]=parts[0] if len(parts)==1 else ''
    distro=values.get('ID','');version=values.get('VERSION_ID','')
    if distro not in ('debian','ubuntu','centos','arch'):raise PlatformError('Distribución no compatible: '+distro)
    if distro=='centos' and (not version.split('.')[0].isdigit() or int(version.split('.')[0])<9):
        raise PlatformError('CentOS requiere Stream 9 o posterior con repositorios activos; no se usan repositorios archivados.')
    return dict(id=distro,version=version,name=values.get('PRETTY_NAME',distro.title()+' '+version)[:160],codename=values.get('VERSION_CODENAME',''),architecture=__import__('platform').machine(),
                family='apt' if distro in ('debian','ubuntu') else 'rpm' if distro=='centos' else 'arch',
                ssh_service='ssh.service' if distro in ('debian','ubuntu') else 'sshd.service')

def executable(name):
    if not re.fullmatch(r'[a-zA-Z0-9_.+-]+',name):raise PlatformError('Nombre de herramienta inválido.')
    result=shutil.which(name,path=SAFE_PATH)
    if not result:raise PlatformError('Falta la herramienta del sistema: '+name)
    return result

def installed(run,profile,name):
    if not re.fullmatch(r'[a-zA-Z0-9_.+-]+',name):raise PlatformError('Paquete inválido.')
    if profile['family']=='apt':
        result=run(['dpkg-query','-W','-f=${db:Status-Status}',name],check=False)
        return result.returncode==0 and result.stdout.strip()=='installed'
    args=['rpm','-q',name] if profile['family']=='rpm' else ['pacman','-Q',name]
    return run(args,check=False).returncode==0

def package_commands(profile,packages):
    if any(not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.+-]*',p) for p in packages):raise PlatformError('Paquete inválido.')
    if profile['family']=='apt':return [['apt-get','-o','DPkg::Lock::Timeout=120','update'],
        ['apt-get','-o','DPkg::Lock::Timeout=120','install','-y','--no-install-recommends',*packages]]
    if profile['family']=='rpm':return [['dnf','-y','install',*packages]]
    # Arch does not support partial upgrades. This synchronizes the whole system.
    return [['pacman','-Syu','--needed','--noconfirm',*packages]]

def install_packages(run,profile,packages):
    missing=[name for name in packages if not installed(run,profile,name)]
    if missing:
        for command in package_commands(profile,missing):run(command,timeout=900)
    return missing

def ftp_packages(profile):
    common=['vsftpd','openssl','logrotate']
    if profile['family']=='apt':return common+['db5.3-util','python3-gdbm','libpam-modules']
    if profile['family']=='rpm':return common+(['libdb-utils'] if int(profile['version'].split('.')[0])<10 else [])+['python3','gdbm','pam','policycoreutils-python-utils']
    return common+['python','gdbm','pam']

def database_layout(profile,backend=None):
    # Keep the existing Oracle installer for Debian 12/13. Other Debian versions
    # and Arch use the distribution's maintained MariaDB package explicitly.
    oracle=profile['id']=='debian' and profile['codename'] in ('bookworm','trixie') and profile.get('architecture','x86_64') in ('x86_64','AMD64','amd64')
    backend=backend or ('mysql' if oracle or profile['id'] in ('ubuntu','centos') else 'mariadb')
    if backend not in ('mysql','mariadb'):raise PlatformError('Motor de base de datos inválido.')
    if backend=='mariadb':
        cnf='/etc/my.cnf.d/zz-storypulse.cnf' if profile['family']!='apt' else '/etc/mysql/mariadb.conf.d/zz-storypulse.cnf'
        service='mariadb.service';sock='/run/mysqld/mysqld.sock'
        packages=['mariadb','python-pymysql'] if profile['family']=='arch' else ['mariadb-server','python3-pymysql']
    elif profile['family']=='rpm':
        cnf='/etc/my.cnf.d/zz-storypulse.cnf';service='mysqld.service';sock='/var/lib/mysql/mysql.sock'
        packages=['mysql8.4-server' if int(profile['version'].split('.')[0])>=10 else 'mysql-server','python3-PyMySQL','python3-cryptography']
    else:
        cnf='/etc/mysql/mysql.conf.d/zz-storypulse.cnf';service='mysql.service';sock='/run/mysqld/mysqld.sock'
        packages=['mysql-community-server' if oracle else 'mysql-server','python3-pymysql','python3-cryptography']
    layout=dict(backend=backend,cnf=cnf,service=service,socket=sock,packages=packages,oracle=oracle and backend=='mysql')
    # Ubuntu 26.04's MariaDB package initializes and confines this native path.
    # Keep every existing distribution/backend layout unchanged.
    if profile['id']=='ubuntu' and profile['version']=='26.04' and backend=='mariadb':
        layout['datadir']='/var/lib/mariadb'
    return layout

def selinux_active(run):
    tool=shutil.which('getenforce',path=SAFE_PATH)
    return bool(tool and run([tool],check=False).stdout.strip() in ('Enforcing','Permissive'))

def label_path(run,kind,path):
    """Persist a narrowly scoped SELinux context; never disable enforcement."""
    expression=re.escape(str(path))+'(/.*)?'
    result=run(['semanage','fcontext','-a','-t',kind,expression],check=False)
    if result.returncode:run(['semanage','fcontext','-m','-t',kind,expression])
    run(['restorecon','-RF',str(path)])

def ftp_selinux(run,base,spool,logs):
    if not selinux_active(run):return
    label_path(run,'ftpd_etc_t',base)
    label_path(run,'public_content_t',spool)
    label_path(run,'xferlog_t',logs)
    # Only per-user writable child directories receive write labels.
    for directory in Path(spool).glob('*/archivos'):label_path(run,'public_content_rw_t',directory)
    for boolean in ('ftpd_anon_write','ftpd_use_passive_mode'):
        if run(['getsebool',boolean],check=False).returncode==0:run(['setsebool','-P',boolean,'on'])
    # semanage refuses a conflicting existing assignment; do not take it over.
    text=run(['semanage','port','-l']).stdout
    if not re.search(r'^ftp_port_t\s+tcp\s+.*\b50000-50019\b',text,re.M):
        run(['semanage','port','-a','-t','ftp_port_t','-p','tcp','50000-50019'])

def database_selinux(run,cnf,tls):
    if not selinux_active(run):return
    label_path(run,'mysqld_etc_t',cnf)
    label_path(run,'mysqld_etc_t',tls)
