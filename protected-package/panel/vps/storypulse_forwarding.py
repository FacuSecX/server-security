"""Bounded, root-owned IPv4 DNAT with the existing incoming source policy.

Only this module's chains are changed. Data-plane forwarding stays in the kernel.
The caller holds the shared controller lock for planning, changes and UFW hooks.
"""
import datetime as dt
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess

spec=importlib.util.spec_from_file_location('forwarding_ports',Path(__file__).with_name('storypulse_ports.py'))
ports=importlib.util.module_from_spec(spec);spec.loader.exec_module(ports)
CONFIG=Path('/etc/storypulse-security/forwarding.json')
BACKUPS=Path('/var/lib/storypulse-security/forwarding-backups')
FORWARD=Path('/proc/sys/net/ipv4/ip_forward')
APPLIED=Path('/var/lib/storypulse-security/forwarding-applied.json')
MAX_RULES=64
PREFIX='SPF_'
TAG='StoryPulseForwarding'
TABLES=('mangle','filter','nat')

class ForwardError(RuntimeError):pass

def run(args,*,input=None,timeout=20):
    result=subprocess.run(args,input=input,text=True,encoding='utf-8',errors='replace',
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,env={**os.environ,'LC_ALL':'C'})
    if result.returncode:raise ForwardError((result.stderr or result.stdout or 'Falló la operación de red').strip()[-1200:])
    return result.stdout

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)
def digest(value):return hashlib.sha256(value.encode()).hexdigest()
def now():return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()

def atomic(path,data,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    temp=path.with_name(path.name+'.'+secrets.token_hex(5))
    try:
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
        with os.fdopen(fd,'wb') as output:output.write(data);output.flush();os.fsync(output.fileno())
        os.replace(temp,path)
        directory=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:temp.unlink(missing_ok=True)

def public_ip(value):
    if not isinstance(value,str):raise ForwardError('La dirección IPv4 debe ser texto.')
    try:address=ipaddress.IPv4Address(value)
    except (ValueError,TypeError) as exc:raise ForwardError('El destino debe ser una IPv4 pública o un dominio válido.') from exc
    if not address.is_global or address.is_multicast or address.is_reserved:
        raise ForwardError('Sólo se permiten destinos IPv4 públicos; no redes internas, locales ni direcciones especiales.')
    return str(address)

def hostname(value):
    if not isinstance(value,str) or not value or len(value)>253 or value!=value.strip():raise ForwardError('Destino no válido.')
    try:return public_ip(value)
    except ForwardError:
        # An IP literal must never fall through to DNS as a numeric hostname.
        if re.fullmatch(r'[\d.]+',value):raise
    try:value=value.rstrip('.').encode('idna').decode('ascii').lower()
    except UnicodeError as exc:raise ForwardError('El dominio no es válido.') from exc
    if len(value)>253 or '.' not in value or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in value.split('.')):
        raise ForwardError('Ingresá sólo el dominio, sin https://, rutas, usuario ni puerto.')
    return value

def resolve(value):
    value=hostname(value)
    try:return value,[public_ip(value)]
    except ForwardError:pass
    # A separate, bounded resolver prevents libc DNS timeouts from holding the lock indefinitely.
    resolver="import json,socket,sys;print(json.dumps(sorted({r[4][0] for r in socket.getaddrinfo(sys.argv[1],None,socket.AF_INET,socket.SOCK_STREAM)})[:32]))"
    try:answers=json.loads(run(['/usr/bin/python3','-I','-c',resolver,value],timeout=6))
    except (RuntimeError,subprocess.TimeoutExpired,json.JSONDecodeError) as exc:
        raise ForwardError('No se pudo resolver el dominio en el servidor. Revisalo y reintentá.') from exc
    if not answers:raise ForwardError('El dominio no tiene una dirección IPv4 disponible.')
    return value,sorted({public_ip(address) for address in answers})

def validate_entry(item):
    if not isinstance(item,dict) or not re.fullmatch(r'[a-f0-9]{16}',str(item.get('id',''))):raise ForwardError('Configuración de forwarding inválida.')
    ports.validate_port(item.get('port'));ports.validate_port(item.get('target_port'));ports.validate_protocol(item.get('protocol'))
    public_ip(item.get('target_ip'));hostname(item.get('host'))
    if type(item.get('enabled')) is not bool:raise ForwardError('Estado de redirección inválido.')
    return item

def load():
    if not CONFIG.exists():return {'version':1,'entries':[]}
    try:config=json.loads(CONFIG.read_text())
    except (OSError,json.JSONDecodeError) as exc:raise ForwardError('No se pudo leer la configuración de Port Forwarding.') from exc
    if not isinstance(config,dict) or config.get('version')!=1 or not isinstance(config.get('entries'),list) or len(config['entries'])>MAX_RULES:
        raise ForwardError('Configuración de forwarding inválida.')
    keys=set();ids=set()
    for item in config['entries']:
        validate_entry(item);key=(item['port'],item['protocol'])
        if key in keys or item['id'] in ids:raise ForwardError('Hay reglas de forwarding duplicadas.')
        keys.add(key);ids.add(item['id'])
    return config

def normalized_table(text):
    return '\n'.join(re.sub(r'\[\d+:\d+\]','[0:0]',line) for line in text.splitlines() if line and not line.startswith('#'))

def snapshot():
    result={'ports':ports.read_snapshot(),'tables':{table:run(['iptables-save','-t',table]) for table in TABLES}}
    route=json.loads(run(['ip','-j','-4','route','get','1.1.1.1']))
    if not route or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',route[0].get('dev','')):raise ForwardError('No se pudo identificar la interfaz pública del servidor.')
    result['interface']=route[0]['dev'];result['source_ip']=public_ip(route[0].get('prefsrc',''))
    addresses=json.loads(run(['ip','-j','-4','address','show']))
    result['local_ips']={info['local'] for iface in addresses for info in iface.get('addr_info',[]) if info.get('family')=='inet'}
    result['forward_enabled']=FORWARD.read_text().strip()=='1'
    return result

def revision(s,config):
    return digest(canonical(config)+s['ports']['revision']+s['interface']+s['source_ip']+
        ''.join(normalized_table(s['tables'][t]) for t in TABLES))

def source_guards(text):
    """Preserve the actual ordered whitelist/provider/manual ipsets, not a stale list."""
    result=[];found_standard=False
    for line in text.splitlines():
        if line.startswith('-A INPUT '):
            tokens=shlex.split(line)
            if tokens[2:] not in [['-j',name] for name in ('ts-input','ufw-before-logging-input','ufw-before-input','ufw-after-input','ufw-after-logging-input','ufw-reject-input','ufw-track-input')]:
                raise ForwardError('Hay reglas INPUT personalizadas que requieren revisión antes de redirigir tráfico.')
        if not line.startswith('-A ufw-before-input '):continue
        tokens=shlex.split(line)[2:]
        if tokens==['-i','lo','-j','ACCEPT']:found_standard=True;continue
        if found_standard:
            allowed=(tokens in [
                ['-m','conntrack','--ctstate','RELATED,ESTABLISHED','-j','ACCEPT'],
                ['-m','conntrack','--ctstate','INVALID','-j','ufw-logging-deny'],
                ['-m','conntrack','--ctstate','INVALID','-j','DROP'],
                ['-p','udp','-m','udp','--sport','67','--dport','68','-j','ACCEPT'],
                ['-j','ufw-not-local'],['-j','ufw-user-input']]
                or (tokens[:2]==['-p','icmp'] and tokens[-2:] in (['-j','ACCEPT'],['-j','DROP']))
                or (tokens[:2] in (['-d','224.0.0.251/32'],['-d','239.255.255.250/32']) and tokens[-2:]==['-j','ACCEPT']))
            if not allowed:raise ForwardError('Hay reglas adicionales de entrada que requieren revisión antes de redirigir.')
            continue
        if '-j' in tokens and tokens[tokens.index('-j')+1]=='LOG':continue
        if '--comment' in tokens:
            i=tokens.index('--comment')
            if i<2 or tokens[i-2:i]!=['-m','comment']:raise ForwardError('Regla de seguridad no reconocida.')
            del tokens[i-2:i+2]
        if len(tokens)!=7 or tokens[:3]!=['-m','set','--match-set'] or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,31}',tokens[3]) or tokens[4:6]!=['src','-j'] or tokens[6] not in ('ACCEPT','DROP'):
            raise ForwardError('La política de entrada contiene una regla que no se puede trasladar con seguridad.')
        result.append(tokens)
    if not found_standard:raise ForwardError('No se pudo verificar la política de entrada UFW.')
    return result

def source_policy(s,item):
    policy=[]
    for rule in s['ports']['rules']:
        if rule['family']!=4 or rule['direction']!='IN':continue
        if not rule['spans'] and not rule['any_port']:raise ForwardError('Los perfiles UFW por aplicación requieren revisión antes de redirigir.')
        if not ports.rule_matches(rule,item['port'],item['protocol']):continue
        if rule['interface']:
            if ' on ' not in rule['destination']:raise ForwardError('Regla UFW de interfaz no reconocida.')
            if rule['destination'].split(' on ',1)[1]!=s['interface']:continue
        source='0.0.0.0/0' if rule['any_source'] else rule['source']
        try:source=str(ipaddress.IPv4Network(source,strict=False))
        except ValueError as exc:raise ForwardError('Hay una restricción de origen que no se puede trasladar con seguridad.') from exc
        if rule['action']=='LIMIT':raise ForwardError('Este puerto usa LIMIT en UFW. No se redirige para conservar esa protección.')
        policy.append(['-s',source,'-j','ACCEPT' if rule['action']=='ALLOW' else 'DROP'])
    policy.append(['-j','ACCEPT' if s['ports']['default']=='allow' else 'DROP'])
    return policy

def routing_error(s):
    if not s.get('forward_enabled',False) and re.search(r'^:FORWARD ACCEPT ',s['tables']['filter'],re.M):
        return 'La política FORWARD debe ser restrictiva antes de habilitar el reenvío IPv4.'
    for line in s['tables']['filter'].splitlines():
        if line.startswith('-A ufw-before-forward '):
            tokens=shlex.split(line)[2:]
            allowed=(tokens in (['-m','conntrack','--ctstate','RELATED,ESTABLISHED','-j','ACCEPT'],['-j','ufw-user-forward']) or (tokens[:2]==['-p','icmp'] and tokens[-2:]==['-j','ACCEPT']))
            if not allowed:return 'Hay reglas adicionales de tráfico enrutado que requieren revisión.'
        if any(line.startswith('-A '+name+' ') for name in ('ufw-before-logging-forward','ufw-after-forward','ufw-reject-forward')):
            return 'Hay reglas adicionales de tráfico enrutado que requieren revisión.'
        if line.startswith('-A ufw-user-forward ') and '-j LOG' not in line:
            return 'Hay reglas UFW de tráfico enrutado. Requieren revisión antes de añadir redirecciones.'
        if line.startswith('-A FORWARD '):
            tokens=shlex.split(line)
            if tokens[2:] in [['-j',name] for name in ('ts-forward','ufw-before-logging-forward','ufw-before-forward','ufw-after-forward','ufw-after-logging-forward','ufw-reject-forward','ufw-track-forward')]:continue
            if '--comment' in tokens and tokens[tokens.index('--comment')+1]==TAG and tokens[-2:]==['-j','SPF_FORWARD']:continue
            return 'Hay reglas FORWARD personalizadas que requieren revisión antes de redirigir.'
    return ''

def eligible(s,port,protocol):
    if not s['ports']['active']:return 'UFW debe estar activo.'
    if s['ports']['ssh_error']:return 'No se pudo verificar la protección de SSH.'
    if (port,protocol) in s['ports']['protected']:return s['ports']['protected'][(port,protocol)]
    state=ports.firewall_state(s['ports']['rules'],port,protocol,4,s['ports']['default'],True)
    if state not in ('open','restricted'):return 'El puerto debe estar abierto en Gestión de puertos (IPv4).'
    if routing_error(s):return routing_error(s)
    try:source_policy(s,{'port':port,'protocol':protocol});source_guards(s['tables']['filter'])
    except RuntimeError as exc:return str(exc)
    return ''

def plan(s,config,payload):
    action=payload.get('action')
    if action not in ('create','update','enable','disable','delete'):raise ForwardError('Acción de forwarding inválida.')
    existing=None
    if action!='create':
        existing=next((r for r in config['entries'] if r['id']==payload.get('id')),None)
        if existing is None:raise ForwardError('La redirección ya no existe. Actualizá el listado.')
    candidate=dict(existing or {})
    if action in ('create','update'):
        port=ports.validate_port(payload.get('port'));protocol=ports.validate_protocol(payload.get('protocol'))
        target_port=ports.validate_port(payload.get('target_port'));host,answers=resolve(payload.get('host'))
        candidate.update(port=port,protocol=protocol,target_port=target_port,host=host,target_ip=answers[0])
        candidate['enabled']=existing['enabled'] if existing else True
    elif action in ('enable','disable'):candidate['enabled']=action=='enable'
    if action=='create' and len(config['entries'])>=MAX_RULES:raise ForwardError(f'Se permiten hasta {MAX_RULES} redirecciones.')
    if action!='delete':
        if any(r['id']!=candidate.get('id') and (r['port'],r['protocol'])==(candidate['port'],candidate['protocol']) for r in config['entries']):
            raise ForwardError('Ya hay una redirección para este puerto y protocolo.')
        if candidate['target_ip'] in s['local_ips']:raise ForwardError('El destino es el propio servidor. Se evita un bucle de redirección.')
        if candidate['enabled']:
            error=eligible(s,candidate['port'],candidate['protocol'])
            if error:raise ForwardError(error)
            # Do not silently override another administrator's NAT/redirect rules.
            for line in s['tables']['nat'].splitlines():
                if line.startswith('-A ') and not line.split()[1].startswith(PREFIX) and any(target in shlex.split(line) for target in ('DNAT','REDIRECT')):
                    raise ForwardError('Existen otras redirecciones NAT. Revisalas antes de activar Port Forwarding.')
    listeners=[r for r in s['ports']['sockets'] if r['family']==4 and r['port']==candidate['port'] and r['protocol']==candidate['protocol'] and r['scope']!='Sólo local']
    return {'ok':True,'action':action,'id':candidate.get('id'),'candidate':candidate,'revision':revision(s,config),
      'interface':s['interface'],'source_ip':s['source_ip'],'processes':sorted({p for r in listeners for p in r['processes']}),
      'enable_routing':candidate.get('enabled',False) and not s['forward_enabled'] and action!='delete',
      'notice':'Se redirigen conexiones externas IPv4. Se conservan las restricciones de origen y bloqueos; el destino verá la IP del servidor. TLS/HTTPS se transmite sin descifrar. Los dominios se fijan a la IPv4 mostrada hasta que edites la regla. Los cambios afectan a conexiones nuevas.'}

def chain_names(table):return {line.split()[0][1:] for line in table.splitlines() if line.startswith(':'+PREFIX)}
def append(lines,chain,args):lines.append(shlex.join(['-A',chain,*args]))

def scripts(s,entries):
    active=[r for r in entries if r['enabled'] and (r['port'],r['protocol']) not in s['ports']['protected']]
    chains={'mangle':{'SPF_PRE'}|{'SPF_R_'+r['id'] for r in active},'filter':{'SPF_FORWARD'},'nat':{'SPF_DNAT','SPF_SNAT'}}
    hooks={'mangle':[('PREROUTING','SPF_PRE')],'filter':[('FORWARD','SPF_FORWARD')],'nat':[('PREROUTING','SPF_DNAT'),('POSTROUTING','SPF_SNAT')]}
    output={t:['*'+t] for t in TABLES}
    # --noflush updates owned chains without flushing UFW, VPN or other NAT rules.
    for table in TABLES:
        old=chain_names(s['tables'][table]);new=chains[table]
        for chain in sorted(old|new):output[table].extend([':'+chain+' - [0:0]','-F '+chain])
        for line in s['tables'][table].splitlines():
            if line.startswith('-A '):
                tokens=shlex.split(line)
                if tokens[1].startswith(PREFIX):continue
                if '-j' in tokens and tokens[tokens.index('-j')+1].startswith(PREFIX):
                    if '--comment' not in tokens or tokens[tokens.index('--comment')+1]!=TAG:raise ForwardError('Hay una referencia externa a las cadenas reservadas del panel.')
                    output[table].append(shlex.join(['-D',*tokens[1:]]))
        if active:
            for parent,chain in hooks[table]:output[table].append(shlex.join(['-I',parent,'1','-m','comment','--comment',TAG,'-j',chain]))
        for chain in sorted(old-new):output[table].append('-X '+chain)
    if active:
        try:
            if not s['ports']['active'] or routing_error(s):raise ForwardError('Política de entrada no disponible.')
            guards=source_guards(s['tables']['filter'])
        except ForwardError:guards=[['-j','DROP']] # Never keep an older permissive policy after UFW changes.
    for item in active:
        port=str(item['port']);proto=item['protocol'];destination=item['target_ip'];target=str(item['target_port']);chain='SPF_R_'+item['id']
        original=['-m','conntrack','--ctorigdst',s['source_ip'],'--ctorigdstport',port,'--ctproto',proto]
        incoming=['-i',s['interface'],'-d',s['source_ip']+'/32','-p',proto,'-m',proto,'--dport',port]
        # goto + RETURN resumes PREROUTING after our hook, preserving VPN/CONNMARK rules.
        # ACCEPT here would incorrectly skip the rest of the mangle table.
        append(output['mangle'],'SPF_PRE',incoming+['-m','conntrack','--ctdir','ORIGINAL','-g',chain])
        append(output['mangle'],chain,['-s','100.64.0.0/10','-j','DROP'])
        for args in guards:append(output['mangle'],chain,[*args[:-1],'RETURN' if args[-1]=='ACCEPT' else args[-1]])
        if not s['ports']['active'] or (item['port'],proto) in s['ports']['protected']:
            append(output['mangle'],chain,['-j','DROP'])
        else:
            try:policy=source_policy(s,item)
            except ForwardError:policy=[['-j','DROP']]
            for args in policy:append(output['mangle'],chain,[*args[:-1],'RETURN' if args[-1]=='ACCEPT' else args[-1]])
        append(output['nat'],'SPF_DNAT',incoming+['-m','comment','--comment','spf:'+item['id'],'-j','DNAT','--to-destination',destination+':'+target])
        append(output['nat'],'SPF_SNAT',['-p',proto,'-m',proto,'-d',destination+'/32','--dport',target,*original,'--ctdir','ORIGINAL','--ctstate','DNAT','-j','MASQUERADE'])
        append(output['filter'],'SPF_FORWARD',['-i',s['interface'],'-p',proto,'-m',proto,'-d',destination+'/32','--dport',target,*original,'--ctdir','ORIGINAL','--ctstate','DNAT','-j','ACCEPT'])
        append(output['filter'],'SPF_FORWARD',['-o',s['interface'],'-p',proto,'-m',proto,'-s',destination+'/32','--sport',target,*original,'--ctdir','REPLY','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT'])
    for table in TABLES:output[table].append('COMMIT')
    return '\n'.join('\n'.join(output[table]) for table in TABLES)+'\n'

def backup(s):
    directory=BACKUPS/(dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+secrets.token_hex(4))
    directory.mkdir(parents=True,mode=0o700);os.chmod(BACKUPS,0o700)
    for table,text in s['tables'].items():atomic(directory/(table+'.rules'),text.encode())
    for path in (CONFIG,APPLIED):
        if path.exists():atomic(directory/path.name,path.read_bytes())
    atomic(directory/'ip_forward',FORWARD.read_bytes())
    return directory

def rollback(directory):
    errors=[]
    for table in reversed(TABLES):
        try:run(['iptables-restore','--wait','5'],input=(directory/(table+'.rules')).read_text())
        except (RuntimeError,OSError,subprocess.TimeoutExpired) as exc:errors.append(str(exc))
    for path in (CONFIG,APPLIED):
        try:
            saved=directory/path.name
            if saved.exists():atomic(path,saved.read_bytes())
            else:path.unlink(missing_ok=True)
        except OSError as exc:errors.append(str(exc))
    try:FORWARD.write_bytes((directory/'ip_forward').read_bytes())
    except OSError as exc:errors.append(str(exc))
    if errors:raise ForwardError('La recuperación no se completó. Revisá el servidor: '+'; '.join(errors))

def kernel_fingerprint(tables):
    selected=[]
    for table in TABLES:
        selected.append(table)
        for line in tables[table].splitlines():
            if line.startswith(':'+PREFIX):selected.append(re.sub(r'\[\d+:\d+\]','[0:0]',line))
            elif line.startswith('-A '):
                tokens=shlex.split(line)
                if tokens[1].startswith(PREFIX) or tokens[1] in ('PREROUTING','POSTROUTING','FORWARD'):
                    selected.append(shlex.join(tokens))
    return digest('\n'.join(selected))

def install(s,config):
    entries=config['entries'];active=any(r['enabled'] for r in entries)
    if not active and not any(chain_names(s['tables'][table]) for table in TABLES):
        atomic(CONFIG,(canonical(config)+'\n').encode());return None
    script=scripts(s,entries)
    desired=digest('\n'.join(line for line in script.splitlines() if line.startswith(('-A ','-I '))))
    try:applied=json.loads(APPLIED.read_text())
    except (OSError,ValueError):applied={}
    if applied.get('desired')==desired and applied.get('kernel')==kernel_fingerprint(s['tables']) and (not active or s['forward_enabled']):
        if load()!=config:atomic(CONFIG,(canonical(config)+'\n').encode())
        return None
    run(['iptables-restore','--wait','5','--test','--noflush'],input=script)
    directory=backup(s)
    try:
        # No NAT is enabled before its source guard and exact FORWARD rules exist.
        run(['iptables-restore','--wait','5','--noflush'],input=script)
        if active and s['ports']['active'] and not routing_error(s):
            # The boot service runs after the firewall. No early-boot sysctl file enables routing.
            FORWARD.write_text('1\n')
        # Do not disable forwarding another VPN may now need when the last rule is paused.
        atomic(CONFIG,(canonical(config)+'\n').encode())
        current={table:run(['iptables-save','-t',table]) for table in TABLES}
        for entry in entries:
            if entry['enabled'] and (entry['port'],entry['protocol']) not in s['ports']['protected'] and ('spf:'+entry['id']) not in current['nat']:raise ForwardError('No se pudo verificar la regla NAT instalada.')
        atomic(APPLIED,canonical({'desired':desired,'kernel':kernel_fingerprint(current)}).encode())
    except (RuntimeError,OSError,subprocess.TimeoutExpired) as exc:
        try:rollback(directory)
        except (RuntimeError,OSError) as recovery:raise ForwardError(f'Falló el cambio: {exc}. {recovery}') from exc
        raise ForwardError(f'No se aplicó el cambio; se restauró la configuración anterior. {exc}') from exc
    return str(directory)

def change(payload):
    if payload.get('confirm') is not True:raise ForwardError('Falta confirmar la redirección.')
    config=load();s=snapshot();proposal=plan(s,config,payload)
    if payload.get('revision')!=proposal['revision']:raise ForwardError('La configuración cambió. Revisá nuevamente la vista previa.')
    if proposal['action'] in ('create','update') and payload.get('target_ip')!=proposal['candidate']['target_ip']:
        raise ForwardError('La dirección del dominio cambió. Revisá nuevamente la vista previa.')
    candidate=proposal['candidate'];action=proposal['action'];entries=[dict(r) for r in config['entries']]
    if action=='create':candidate={**candidate,'id':secrets.token_hex(8),'created_at':now()}
    else:entries=[r for r in entries if r['id']!=candidate['id']]
    if action!='delete':entries.append({**candidate,'updated_at':now()})
    entries.sort(key=lambda r:(r['port'],r['protocol']))
    directory=install(s,{'version':1,'entries':entries})
    return {'ok':True,'action':action,'id':candidate['id'],'backup':directory}

def sync():
    config=load()
    # An empty installation never touches the firewall or enables routing.
    if not config['entries']:return {'ok':True,'synced':True,'empty':True}
    return {'ok':True,'synced':True,'backup':install(snapshot(),config)}

def status(extra_port=None):
    config=load();s=snapshot();listed=ports.inventory(s['ports'],extra_port)['ports']
    candidates=[]
    for item in listed:
        if item['families'].get('4') in ('open','restricted'):
            item['forwarding_disabled']=eligible(s,item['port'],item['protocol']);candidates.append(item)
    entries=[]
    for item in config['entries']:
        applied=bool(item['enabled'] and s['forward_enabled'] and 'spf:'+item['id'] in s['tables']['nat'])
        blocked=eligible(s,item['port'],item['protocol']) if item['enabled'] else ''
        entries.append({**item,'applied':applied,'warning':blocked})
    return {'ok':True,'version':1,'timestamp':int(dt.datetime.now(dt.timezone.utc).timestamp()),'revision':revision(s,config),
      'source_ip':s['source_ip'],'interface':s['interface'],'firewall_active':s['ports']['active'],'forward_enabled':s['forward_enabled'],'ports':candidates,'entries':entries,
      'notice':'TCP/UDP sobre IPv4 pública. Los puertos restringidos conservan sus IP permitidas. No se abren puertos automáticamente. El destino ve la IP del servidor; TLS se transmite sin modificar. Dominio de destino fijado a su IPv4 al confirmar.'}
