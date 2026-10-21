"""Read live sockets/UFW and change one explicitly confirmed TCP/UDP port.

No shell interpolation, scans or service restarts. UFW owns persistence.
"""
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

CONFIG_FILES = (Path('/etc/ufw/user.rules'), Path('/etc/ufw/user6.rules'))
BACKUP_ROOT = Path('/var/lib/storypulse-security/port-backups')
COMMON_PORTS = {21:'FTP',22:'SSH',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',143:'IMAP',443:'HTTPS',
               465:'SMTP TLS',587:'SMTP',993:'IMAP TLS',995:'POP3 TLS',3306:'MySQL',3389:'RDP',
               5432:'PostgreSQL',5900:'VNC',6379:'Redis',8080:'HTTP alternativo',8443:'HTTPS alternativo',41641:'Tailscale'}

class PortsError(RuntimeError):
    pass

def command(args, *, input=None):
    result=subprocess.run(args,input=input,text=True,encoding='utf-8',errors='replace',
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,
        env={**os.environ,'LC_ALL':'C'})
    if result.returncode:
        raise PortsError((result.stderr or result.stdout or 'Falló la consulta del servidor').strip()[-1200:])
    return result.stdout

def validate_port(value):
    if isinstance(value,bool) or not isinstance(value,int) or not 1<=value<=65535:
        raise PortsError('El puerto debe ser un número entero entre 1 y 65535.')
    return value

def validate_protocol(value):
    if value not in ('tcp','udp'):
        raise PortsError('Seleccioná TCP o UDP.')
    return value

def parse_rules(text):
    rules=[]
    for line in text.splitlines():
        match=re.match(r'^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)\s+(.+?)\s*$',line)
        if not match:continue
        number,destination,action,direction,source=match.groups()
        source,_,comment=source.partition('#')
        family=6 if '(v6)' in destination or '(v6)' in source or ':' in source.split()[0] else 4
        destination=destination.replace('(v6)','').strip()
        source=source.replace('(v6)','').strip()
        base=destination.split(' on ')[0].strip()
        port_match=re.fullmatch(r'(\d+(?::\d+)?(?:,\d+(?::\d+)?)*)/(tcp|udp)',base)
        bare_match=re.fullmatch(r'\d+(?::\d+)?(?:,\d+(?::\d+)?)*',base)
        spec=port_match.group(1) if port_match else base if bare_match else ''
        spans=[]
        for item in spec.split(',') if spec else []:
            parts=item.split(':');spans.append((int(parts[0]),int(parts[-1])))
        rules.append({'number':int(number),'destination':destination,'source':source,'action':action,
            'direction':direction,'family':family,'protocol':port_match.group(2) if port_match else None,
            'spans':spans,'any_port':base=='Anywhere','any_source':source in ('Anywhere','0.0.0.0/0','::/0'),
            'interface':' on ' in destination or ' on ' in source,'comment':comment.strip()})
    return rules

def parse_sockets(text, protocol, family):
    result=[]
    for line in text.splitlines():
        parts=line.split()
        if len(parts)<5:continue
        endpoint=parts[3]
        try:
            address,port=endpoint.rsplit(':',1)
            port=int(port)
            if not 1<=port<=65535:continue
        except (ValueError,IndexError):continue
        address=address.strip('[]').split('%')[0]
        processes=sorted(set(re.findall(r'\("([^"\n]+)",pid=',line)))
        if address in ('*','0.0.0.0','::'):scope='Todas las interfaces'
        else:
            try:
                ip=ipaddress.ip_address(address)
                if ip.is_loopback:scope='Sólo local'
                elif ip in ipaddress.ip_network('100.64.0.0/10') or ip in ipaddress.ip_network('fd7a:115c:a1e0::/48'):scope='Tailscale'
                elif ip.is_multicast:scope='Multicast'
                else:scope='Interfaz específica'
            except ValueError:scope='Interfaz específica'
        result.append({'port':port,'protocol':protocol,'family':family,'address':address,
                       'processes':processes,'scope':scope})
    return result

def rule_matches(rule,port,protocol):
    return rule['direction']=='IN' and rule['protocol'] in (None,protocol) and (
        rule['any_port'] or any(start<=port<=end for start,end in rule['spans']))

def firewall_state(rules,port,protocol,family,default,active):
    if not active:return 'inactive'
    restricted_allow=False
    unknown=False
    for rule in rules:
        if rule['family']!=family or rule['direction']!='IN':continue
        if not rule['spans'] and not rule['any_port']:
            unknown=True
            continue
        if not rule_matches(rule,port,protocol):continue
        universal=rule['any_source'] and not rule['interface']
        if rule['action'] in ('ALLOW','LIMIT'):
            if universal:return 'unknown' if unknown else ('limited' if rule['action']=='LIMIT' else 'open')
            restricted_allow=True
        elif universal:
            if unknown:return 'unknown'
            return 'restricted' if restricted_allow else 'closed'
    if unknown:return 'unknown'
    if restricted_allow:return 'restricted'
    return 'open' if default=='allow' else 'closed' if default in ('deny','reject') else 'unknown'

def read_snapshot():
    verbose=command(['ufw','status','verbose'])
    numbered=command(['ufw','status','numbered'])
    rules=parse_rules(numbered)
    active=bool(re.search(r'^Status:\s+active\s*$',verbose,re.M))
    default_match=re.search(r'^Default:\s+(allow|deny|reject) \(incoming\)',verbose,re.M)
    default=default_match.group(1) if default_match else 'unknown'
    ipv6=bool(re.search(r'^IPV6\s*=\s*yes\s*$',Path('/etc/default/ufw').read_text(),re.M))
    sockets=[]
    for family in (4,6):
        for protocol,flag in (('tcp','t'),('udp','u')):
            sockets.extend(parse_sockets(command(['ss','-H',f'-ln{flag}p{family}']),protocol,family))
    # Fail closed for mutations when the real SSH configuration cannot be read.
    ssh_error=''
    try:
        ssh_config=command(['/usr/sbin/sshd','-T'])
        ssh_ports={int(p) for p in re.findall(r'^port (\d+)$',ssh_config,re.M)}
        if not ssh_ports:raise PortsError('No se pudieron identificar los puertos SSH.')
    except (PortsError,OSError,subprocess.TimeoutExpired) as exc:
        ssh_ports={22};ssh_error=str(exc)
    protected={(p,'tcp'):'Acceso SSH protegido' for p in ssh_ports}
    import storypulse_cloudflare as cloudflare
    if cloudflare.enabled():
        for port in (80,443):protected[(port,'tcp')]='Cloudflare protege este puerto. Modificá la protección desde Gestionar servicios → Nginx.'
    protected[(41641,'udp')]='Conexión Tailscale protegida'
    for item in sockets:
        if any(p.startswith(('sshd','tailscaled')) for p in item['processes']):
            protected[(item['port'],item['protocol'])]='Acceso administrativo protegido'
        if item['protocol']=='udp' and item['port'] in (68,546):
            protected[(item['port'],'udp')]='Configuración de red DHCP protegida'
    if Path('/etc/storypulse-ftp/state.json').exists() and any(s['port']==21 and 'vsftpd' in s['processes'] for s in sockets):
        for port in (21,*range(50000,50020)):
            protected[(port,'tcp')]='FTP administrado activo: detenelo desde Servicios antes de modificar estos puertos.'
    if Path('/etc/storypulse-mysql/state.json').exists():
        protected[(3306,'tcp')]='MySQL administrado: configurá el acceso externo desde Servicios → MySQL.'
    material=numbered+'\n'+verbose.split('To ')[0]+str(sorted(protected))+str(ipv6)
    for path in CONFIG_FILES:
        if path.exists():material+='\n'+path.read_text()
    return {'rules':rules,'sockets':sockets,'active':active,'default':default,'ipv6':ipv6,
            'protected':protected,'ssh_error':ssh_error,'revision':hashlib.sha256(material.encode()).hexdigest()}

def exact_global(rule,port,protocol):
    return (rule['direction']=='IN' and rule['spans']==[(port,port)] and rule['protocol']==protocol
            and rule['any_source'] and not rule['interface'] and rule['action'] in ('ALLOW','DENY','REJECT'))

def mutation_error(snapshot,port,protocol):
    if not snapshot['active']:return 'Activá UFW antes de gestionar puertos.'
    if snapshot['ssh_error']:return 'No se pudo verificar la protección del acceso SSH.'
    if (port,protocol) in snapshot['protected']:return snapshot['protected'][(port,protocol)]
    forwarding=Path('/etc/storypulse-security/forwarding.json')
    if forwarding.exists():
        try:
            config=json.loads(forwarding.read_text())
            if any(r['enabled'] and r['port']==port and r['protocol']==protocol for r in config['entries']):
                return 'Port Forwarding activo: pausá primero la redirección para modificar este puerto.'
        except (ValueError,KeyError,TypeError):return 'No se pudo verificar la configuración de Port Forwarding.'
    for rule in snapshot['rules']:
        if rule['direction']!='IN':continue
        if not rule['spans'] and not rule['any_port']:
            return 'Hay reglas UFW por nombre de aplicación que requieren revisión antes de cambiar puertos.'
        if rule_matches(rule,port,protocol) and rule['any_source'] and not rule['interface'] and not exact_global(rule,port,protocol):
            return 'Este puerto forma parte de una regla general o de varios puertos. Se conserva esa regla para no afectar otros servicios.'
    return ''

def inventory(snapshot, extra_port=None):
    keys={(port,'tcp') for port in COMMON_PORTS if port!=41641}
    keys.update({(53,'udp'),(80,'udp'),(443,'udp'),(41641,'udp')})
    keys.update((r['port'],r['protocol']) for r in snapshot['sockets'])
    for rule in snapshot['rules']:
        for start,end in rule['spans']:
            # Show range endpoints; an arbitrary port can always be inspected.
            for port in {start,end}:
                if 1<=port<=65535:
                    keys.update((port,p) for p in ([rule['protocol']] if rule['protocol'] else ('tcp','udp')))
    if extra_port:
        keys.update((validate_port(extra_port),p) for p in ('tcp','udp'))
    rows=[]
    for port,protocol in sorted(keys):
        listeners=[s for s in snapshot['sockets'] if s['port']==port and s['protocol']==protocol]
        states={str(f):firewall_state(snapshot['rules'],port,protocol,f,snapshot['default'],snapshot['active'])
                for f in ((4,6) if snapshot['ipv6'] else (4,))}
        values=set(states.values());state=next(iter(values)) if len(values)==1 else 'mixed'
        rows.append({'port':port,'protocol':protocol,'service':COMMON_PORTS.get(port,'Servicio personalizado'),
            'processes':sorted({p for s in listeners for p in s['processes']}),'listeners':listeners,
            'listening':bool(listeners),'firewall':state,'families':states,
            'protected':(port,protocol) in snapshot['protected'],'action_disabled':mutation_error(snapshot,port,protocol),
            'rules_count':sum(1 for r in snapshot['rules'] if r['spans'] and rule_matches(r,port,protocol))})
    return {'ok':True,'version':1,'timestamp':int(dt.datetime.now(dt.timezone.utc).timestamp()),
            'firewall_active':snapshot['active'],'default_incoming':snapshot['default'],'ipv6':snapshot['ipv6'],
            'revision':snapshot['revision'],'ports':rows,
            'notice':'Estado de UFW y servicios locales. Tailscale, IP de confianza y bloqueos de proveedores conservan sus reglas; no es un escaneo desde Internet.'}

def plan(snapshot,payload):
    port=validate_port(payload.get('port'));protocol=validate_protocol(payload.get('protocol'))
    action=payload.get('action')
    if action not in ('open','close'):raise PortsError('La acción debe ser abrir o cerrar.')
    error=mutation_error(snapshot,port,protocol)
    if error:raise PortsError(error)
    affected=[r for r in snapshot['rules'] if exact_global(r,port,protocol)]
    return {'ok':True,'port':port,'protocol':protocol,'action':action,'revision':snapshot['revision'],
        'replace_count':len(affected),'families':[4,6] if snapshot['ipv6'] else [4],
        'effect':('Permitir nuevas conexiones a este puerto desde cualquier IP no bloqueada. No inicia el servicio.' if action=='open'
                  else 'Bloquear nuevas conexiones a este puerto mediante UFW. No detiene el servicio ni corta conexiones ya establecidas.'),
        'exceptions':'Se conservan las excepciones previas de administración/Tailscale y los bloqueos de IP/proveedores.'}

def backup(snapshot):
    directory=BACKUP_ROOT/(dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+secrets.token_hex(4))
    directory.mkdir(parents=True,mode=0o700)
    os.chmod(BACKUP_ROOT,0o700)
    for path in CONFIG_FILES:
        if path.exists():(directory/path.name).write_bytes(path.read_bytes())
    for family,binary in ((4,'iptables-save'),(6,'ip6tables-save')):
        (directory/f'filter{family}.rules').write_text(command([binary,'-t','filter']))
    (directory/'revision').write_text(snapshot['revision'])
    return directory

def restore(directory):
    errors=[]
    for path in CONFIG_FILES:
        saved=directory/path.name
        if saved.exists():
            try:
                temporary=path.with_name(path.name+'.storypulse-restore')
                temporary.write_bytes(saved.read_bytes());os.chmod(temporary,0o640);os.replace(temporary,path)
            except OSError as exc:errors.append(str(exc))
    for family,binary in ((4,'iptables-restore'),(6,'ip6tables-restore')):
        try:command([binary,'--wait','5'],input=(directory/f'filter{family}.rules').read_text())
        except (PortsError,OSError,subprocess.TimeoutExpired) as exc:errors.append(str(exc))
    if errors:raise PortsError('Restauración incompleta; revisar el servidor: '+'; '.join(errors))

def verify_administration_rules(directory):
    # Existing provider, administration and Tailscale rules must survive UFW updates.
    def protected_lines(text):
        return {line for line in text.splitlines() if re.match(r'^-A (?:ts-\S+|ufw6?-before-input) ',line)}
    for family,binary in ((4,'iptables-save'),(6,'ip6tables-save')):
        previous=protected_lines((directory/f'filter{family}.rules').read_text())
        current=protected_lines(command([binary,'-t','filter']))
        if not previous.issubset(current):
            raise PortsError('Se detectó un cambio inesperado en las reglas de administración o proveedores.')


def apply(payload,repair_monitor):
    if payload.get('confirm') is not True:raise PortsError('Falta confirmar el cambio de puerto.')
    snapshot=read_snapshot();proposal=plan(snapshot,payload)
    if payload.get('revision')!=snapshot['revision']:
        raise PortsError('Las reglas cambiaron desde la vista previa. Actualizá y confirmá nuevamente.')
    directory=backup(snapshot)
    port=proposal['port'];protocol=proposal['protocol']
    try:
        # Exact, family-specific deletion preserves source restrictions and other ports.
        for rule in snapshot['rules']:
            if not exact_global(rule,port,protocol):continue
            any_address='::/0' if rule['family']==6 else '0.0.0.0/0'
            command(['ufw','--force','delete',rule['action'].lower(),'in','proto',protocol,
                     'from',any_address,'to',any_address,'port',str(port)])
        for family in proposal['families']:
            any_address='::/0' if family==6 else '0.0.0.0/0'
            verb=['allow'] if proposal['action']=='open' else ['prepend','deny']
            command(['ufw',*verb,'in','proto',protocol,'from',any_address,'to',any_address,'port',str(port),
                     'comment',f'StoryPulse port {protocol}/{port}'])
        for family in proposal['families']:repair_monitor(family)
        verify_administration_rules(directory)
        after=read_snapshot()
        expected='open' if proposal['action']=='open' else 'closed'
        for family in proposal['families']:
            actual=firewall_state(after['rules'],port,protocol,family,after['default'],after['active'])
            if actual!=expected:raise PortsError('El estado final de UFW no coincide con el cambio solicitado.')
    except (RuntimeError,OSError,subprocess.TimeoutExpired) as exc:
        try:restore(directory)
        except (PortsError,OSError) as recovery:
            raise PortsError(f'Falló el cambio: {exc}. {recovery}') from exc
        raise PortsError(f'No se aplicó el cambio; se restauraron las reglas anteriores. {exc}') from exc
    return {**inventory(after,port),'changed_port':port,'changed_protocol':protocol,
            'action':proposal['action'],'backup':str(directory)}
