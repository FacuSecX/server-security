"""Transactional Cloudflare origin protection. Fixed paths, official sources, no shell.

Policy and rollback copies belong to this VPS. PEM keys never enter API results,
audit messages, command arguments, or the policy JSON.
"""
import contextlib,datetime,hashlib,ipaddress,json,os,re,secrets,shlex,socket,stat,subprocess,tempfile,time,urllib.request
from pathlib import Path
import storypulse_uninstall as removal

BASE=Path('/etc/server-monitor-cloudflare')
POLICY=BASE/'policy.json'
CERT=BASE/'origin.pem'
KEY=BASE/'origin.key'
ROOTS=BASE/'origin-ca.pem'
HTTP=BASE/'http.conf'
TAG='ServerMonitor Cloudflare'
SSL_TAG='ServerMonitor HTTPS'
PRIORITY_TAG='ServerMonitor Cloudflare priority'
PRIORITY_CHAIN='ssm-cf-web'
BEFORE_FILES={4:Path('/etc/ufw/before.rules'),6:Path('/etc/ufw/before6.rules')}
repair_monitors=lambda family:None
STACK=Path('/var/lib/storypulse-security/webapps/stack.json')
MANAGED_MAIN='/etc/nginx/server-monitor.conf'
WEB_VHOST='/etc/nginx/conf.d/00-server-monitor-webapps.conf'
ROOT_URLS=('https://developers.cloudflare.com/ssl/static/origin_ca_rsa_root.pem','https://developers.cloudflare.com/ssl/static/origin_ca_ecc_root.pem')
class CloudflareError(RuntimeError):pass

def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def sha(value):return hashlib.sha256(value).hexdigest()
def run(args,input=None,check=True,timeout=30):
    result=subprocess.run(args,input=input,capture_output=True,text=True,timeout=timeout,env={**os.environ,'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},stdin=subprocess.DEVNULL if input is None else None)
    if check and result.returncode:raise CloudflareError('No se pudo completar la comprobación de '+Path(args[0]).name+'. Se conservó la configuración anterior.')
    return result
def safe(path):
    path=Path(path);removal.safe_path(path)
    if path.exists():
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>2*1024**2:raise CloudflareError('Hay un archivo de configuración inseguro. No se modificó.')
    return path
def read_policy():
    if not POLICY.exists():return {}
    safe(POLICY)
    if POLICY.stat().st_mode&0o077:raise CloudflareError('La política Cloudflare debe ser privada.')
    value=json.loads(POLICY.read_text())
    if value.get('version')!=1:raise CloudflareError('La política Cloudflare no es compatible.')
    return value
def write(path,data,mode=0o600):
    path=safe(path);removal.safe_path(path.parent);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,name=tempfile.mkstemp(prefix='.'+path.name+'-',dir=str(path.parent))
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'wb') as handle:handle.write(data.encode() if isinstance(data,str) else data);handle.flush();os.fsync(handle.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)
def store(policy):write(POLICY,json.dumps(policy,ensure_ascii=False))
def enabled():
    p=read_policy();return bool(p.get('block_direct') or p.get('ssl'))
def blocked():return read_policy().get('block_direct') is True

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise CloudflareError('La fuente oficial redirigió inesperadamente.')
def official(url,limit=65536):
    try:
        with urllib.request.build_opener(NoRedirect()).open(urllib.request.Request(url,headers={'User-Agent':'Server-Monitor/2.0'}),timeout=20) as response:
            data=response.read(limit+1)
            if response.status!=200 or len(data)>limit:raise ValueError()
            return data.decode('ascii')
    except Exception:raise CloudflareError('No se pudo descargar la información oficial de Cloudflare. Se conserva la última configuración válida.') from None
def networks(v4,v6):
    result=[]
    for family,text in ((4,v4),(6,v6)):
        lines=text.splitlines()
        if not 2<=len(lines)<=100:raise CloudflareError('La lista oficial de rangos está incompleta.')
        for line in lines:
            try:network=ipaddress.ip_network(line.strip(),strict=True)
            except ValueError:raise CloudflareError('Cloudflare devolvió un rango no válido.') from None
            if network.version!=family or not network.is_global or network.prefixlen<(8 if family==4 else 19):raise CloudflareError('Cloudflare devolvió un rango demasiado amplio o no público.')
            if network in result:raise CloudflareError('Cloudflare devolvió rangos repetidos.')
            result.append(network)
    return [str(n) for n in result]
def refresh_ranges():return networks(official('https://www.cloudflare.com/ips-v4'),official('https://www.cloudflare.com/ips-v6'))
def domain(value):
    if not isinstance(value,str):raise CloudflareError('Ingresá el dominio del sitio.')
    try:value=value.strip().rstrip('.').encode('idna').decode('ascii').lower()
    except UnicodeError:raise CloudflareError('El dominio no es válido.') from None
    if len(value)>253 or '.' not in value or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in value.split('.')):raise CloudflareError('Ingresá solo el dominio, sin https://, puerto ni ruta.')
    try:ipaddress.ip_address(value)
    except ValueError:return value
    raise CloudflareError('Usá un dominio de Cloudflare, no una IP.')
def payload(body,apply=False):
    fields={'block_direct','ssl','domain','certificate','private_key','refresh'}|({'revision','confirm'} if apply else set())
    if not isinstance(body,dict) or set(body)-fields or type(body.get('block_direct')) is not bool or type(body.get('ssl')) is not bool:raise CloudflareError('Opciones Cloudflare no válidas.')
    if type(body.get('refresh',False)) is not bool:raise CloudflareError('Actualización no válida.')
    for name in ('certificate','private_key'):
        if not isinstance(body.get(name,''),str) or len(body.get(name,''))>65536 or '\x00' in body.get(name,''):raise CloudflareError('El certificado o la clave superan el formato permitido.')
    result={k:v for k,v in body.items() if k not in ('revision','confirm')};result['domain']=domain(body.get('domain')) if body['ssl'] or body['block_direct'] else ''
    if bool(body.get('certificate','').strip())!=bool(body.get('private_key','').strip()):raise CloudflareError('Pegá tanto el certificado como su clave privada.')
    if not body['ssl'] and (body.get('certificate') or body.get('private_key')):raise CloudflareError('Activá SSL para añadir un certificado.')
    return result

# A small Nginx lexer: comments and braces inside quotes are never directives.
TOKEN=re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|\#[^\n]*|[{};]|(?:\$\{[^}]*\}|[^\s{};#])+')
def parse(text):
    tokens=[m for m in TOKEN.finditer(text) if not m[0].startswith('#')];at=0
    def group(nested=False):
        nonlocal at
        nodes=[]
        while at<len(tokens):
            if tokens[at][0]=='}':
                if not nested:raise CloudflareError('La estructura de Nginx no es válida.')
                closing=tokens[at];at+=1;return nodes,closing
            start=tokens[at].start();words=[]
            while at<len(tokens) and tokens[at][0] not in ('{','}',';'):words.append(tokens[at][0]);at+=1
            if not words or at>=len(tokens) or tokens[at][0]=='}':raise CloudflareError('No se pudo interpretar la configuración Nginx.')
            end=tokens[at];at+=1
            node={'name':words[0],'args':words[1:],'start':start,'end':end.end(),'children':[]}
            if end[0]=='{':node['open']=end.end();node['children'],closing=group(True);node['end']=closing.end();node['close']=closing.start()
            nodes.append(node)
        if nested:raise CloudflareError('La configuración Nginx tiene llaves incompletas.')
        return nodes,None
    return group()[0]
def walk(nodes):
    for node in nodes:yield node;yield from walk(node['children'])
def listen_port(node):
    if node['name']!='listen' or not node['args']:return None
    value=node['args'][0]
    return int(value) if value.isdigit() else int(value.rsplit(':',1)[1]) if ':' in value and value.rsplit(':',1)[1].isdigit() else None
def servers(text):return [n for n in walk(parse(text)) if n['name']=='server' and any(listen_port(x) in (80,443) for x in n['children'])]
def edit(text,changes):
    for start,end,value in sorted(changes,reverse=True):text=text[:start]+value+text[end:]
    return text
def render(path,text,policy=None):
    p=read_policy() if policy is None else policy
    if not (p.get('ssl') or p.get('block_direct')):return text
    changes=[];nodes=parse(text)
    for node in walk(nodes):
        if node['name']=='http' and p.get('block_direct'):
            changes.append((node['open'],node['open'],'\ninclude '+str(HTTP)+';\n'))
    for index,node in enumerate(servers(text)):
        extra='\n'
        if p.get('block_direct'):extra+='if ($ssm_cf_peer_allowed = 0) { return 403; }\n'
        selected=str(path)==p.get('target') and index==p.get('target_index',0)
        if selected:
            extra+='location = /'+p['challenge']+' { add_header Cache-Control "no-store" always; return 200 "'+p['nonce']+'"; }\n'
        if p.get('ssl') and selected:
            listeners=[x for x in node['children'] if x['name']=='listen']
            if any(listen_port(x)!=80 for x in listeners) or any(x['name'].startswith('ssl_') for x in node['children']):raise CloudflareError('Este sitio ya tiene una configuración SSL propia. Se conserva sin sobrescribirla.')
            redirect=[]
            for item in listeners:
                args=item['args'];address=args[0];tls='443' if address=='80' else address.rsplit(':',1)[0]+':443'
                if any(x not in ('default_server','bind','reuseport','ipv6only=on','ipv6only=off') for x in args[1:]):raise CloudflareError('La escucha Nginx tiene opciones que requieren una revisión manual.')
                changes.append((item['start'],item['end'],'listen '+' '.join([tls,'ssl',*args[1:]])+';'))
                redirect.append('listen '+' '.join(args)+';')
            if not any('[' in x['args'][0] for x in listeners) and any(x['args'][0] in ('80','0.0.0.0:80') for x in listeners) and Path('/proc/net/if_inet6').exists() and Path('/proc/net/if_inet6').read_text().strip():
                extra+='listen [::]:443 ssl;\n';redirect.append('listen [::]:80;')
            names=[x for x in node['children'] if x['name']=='server_name']
            for item in names:changes.append((item['start'],item['end'],'server_name '+p['domain']+';'))
            if not names:extra+='server_name '+p['domain']+';\n'
            extra+='ssl_certificate '+str(CERT)+';\nssl_certificate_key '+str(KEY)+';\nssl_protocols TLSv1.2 TLSv1.3;\n'
            guard='if ($ssm_cf_peer_allowed = 0) { return 403; }\n' if p.get('block_direct') else ''
            changes.append((node['end'],node['end'],'\nserver {\n'+'\n'.join(redirect)+'\nserver_name '+p['domain']+';\n'+guard+'return 308 https://'+p['domain']+'$request_uri;\n}\n'))
        changes.append((node['open'],node['open'],extra))
    return edit(text,changes)
def remember(path,base,rendered):
    p=read_policy()
    if not enabled() or base==rendered:return
    key=str(path);previous=p.get('files',{}).get(key,{})
    p.setdefault('files',{})[key]={'base':base,'hash':sha(rendered.encode()),'mode':previous.get('mode',0o644)};store(p)
def source(path):
    path=safe(path);text=path.read_text();record=read_policy().get('files',{}).get(str(path))
    if record:
        if sha(text.encode())!=record['hash']:raise CloudflareError('Nginx cambió fuera del panel. No se sobrescribe esa configuración; revisala antes de continuar.')
        return record['base']
    return text
def discover():
    # Select the actual front end, including the dedicated WordPress instance.
    stack=json.loads(STACK.read_text()) if STACK.exists() else {}
    if stack.get('mode')=='apache':raise CloudflareError('Estas opciones corresponden a Nginx. El sitio actual usa Apache.')
    if stack.get('mode')=='dedicated':
        import storypulse_service_flow as flow
        flow.runtime_directory('server-monitor-webnginx')
        main=Path('/etc/server-monitor-webapps/nginx.conf');unit='server-monitor-webnginx.service'
    else:
        unit='nginx.service';main=Path(stack.get('nginx_main') or ('/etc/nginx/server-monitor.conf' if Path('/etc/nginx/server-monitor.conf').exists() else '/etc/nginx/nginx.conf'))
    safe(main)
    if not main.exists():raise CloudflareError('Instalá Nginx antes de configurar Cloudflare.')
    result=run(['nginx','-T','-c',str(main)])
    paths={main.resolve()}
    for raw in re.findall(r'^# configuration file ([^\n]+):$',result.stdout,re.M):
        path=Path(raw).resolve()
        if not any(path.is_relative_to(root) for root in (Path('/etc/nginx'),Path('/etc/server-monitor-webapps'),BASE)) and path not in (HTTP,):raise CloudflareError('Nginx incluye archivos externos que requieren revisión manual.')
        if path!=HTTP and path.exists() and (servers(source(path)) or any(n['name']=='http' for n in parse(source(path)))):paths.add(path)
    if len(paths)>64:raise CloudflareError('Demasiados sitios Nginx para una única operación.')
    return {'main':str(main.resolve()),'unit':unit,'files':sorted(str(x) for x in paths),'preferred':str(Path(stack['vhost']).resolve()) if stack.get('vhost') else ''}
def target(front,name):
    choices=[]
    for raw in front['files']:
        for index,node in enumerate(servers(source(raw))):
            if not any(listen_port(x)==80 for x in node['children']):continue
            names=[arg.strip('"\'') for x in node['children'] if x['name']=='server_name' for arg in x['args']]
            score=3 if name in names else 2 if raw==front['preferred'] else 1
            choices.append((score,raw,index))
    if not choices:raise CloudflareError('No hay un sitio HTTP en Nginx para aplicar la configuración.')
    best=max(x[0] for x in choices);choices=[x for x in choices if x[0]==best]
    if len(choices)!=1:raise CloudflareError('Hay varios sitios Nginx. El dominio debe coincidir con el server_name del sitio que querés proteger.')
    return choices[0][1:]
def certificate(cert,key,name,folder,roots):
    if not cert.strip().startswith('-----BEGIN CERTIFICATE-----') or not key.strip().startswith(('-----BEGIN PRIVATE KEY-----','-----BEGIN RSA PRIVATE KEY-----','-----BEGIN EC PRIVATE KEY-----')):raise CloudflareError('Pegá el certificado Origin CA y su clave privada completos en formato PEM, sin contraseña.')
    cp=folder/'certificate.pem';kp=folder/'private.key';rp=folder/'ca.pem'
    write(cp,cert.strip()+'\n');write(kp,key.strip()+'\n');write(rp,roots)
    try:
        run(['openssl','pkey','-in',str(kp),'-passin','pass:','-check','-noout'])
        pub=run(['openssl','pkey','-in',str(kp),'-passin','pass:','-pubout']).stdout
        if pub!=run(['openssl','x509','-in',str(cp),'-pubkey','-noout']).stdout:raise ValueError()
    except Exception:raise CloudflareError('La clave privada no es válida o no corresponde al certificado.') from None
    if run(['openssl','verify','-CAfile',str(rp),'-purpose','sslserver','-verify_hostname',name,str(cp)],check=False).returncode:raise CloudflareError('El certificado no es un Origin CA válido para ese dominio, todavía no es válido o está vencido.')
    details=run(['openssl','x509','-in',str(cp),'-noout','-enddate','-fingerprint','-sha256']).stdout.splitlines()
    return {'expires':details[0].removeprefix('notAfter='),'fingerprint':details[1].split('=',1)[-1]}
def cert_info(body):
    p=read_policy()
    if not body['ssl']:return None
    cert=body.get('certificate','').strip();key=body.get('private_key','').strip()
    if not cert:
        if not p.get('ssl') or not CERT.exists() or not KEY.exists():raise CloudflareError('Pegá el certificado Origin CA y su clave privada para activar SSL.')
        safe(CERT);safe(KEY)
        if KEY.stat().st_mode&0o077:raise CloudflareError('La clave privada debe tener permisos 0600 para root.')
        cert=CERT.read_text();key=KEY.read_text()
    roots=ROOTS.read_text() if ROOTS.exists() else ''.join(official(url) for url in ROOT_URLS)
    removal.safe_path(BASE);BASE.mkdir(mode=0o700,parents=True,exist_ok=True)
    if BASE.stat().st_uid!=0 or BASE.stat().st_mode&0o077:raise CloudflareError('El directorio de certificados debe ser privado y pertenecer a root.')
    with tempfile.TemporaryDirectory(prefix='.certificate-',dir=str(BASE)) as directory:
        return certificate(cert,key,body['domain'],Path(directory),roots)
def firewall_rules():
    output=run(['ufw','status','numbered']).stdout
    return [(int(m[1]),m[2]) for m in re.finditer(r'^\[\s*(\d+)\]\s*(.*)$',output,re.M) if any('# '+tag in m[2] for tag in (TAG,SSL_TAG))]

def priority_text(text,family,enable,ranges):
    begin='# BEGIN SERVER_MONITOR_CLOUDFLARE\n';end='# END SERVER_MONITOR_CLOUDFLARE\n'
    if text.count(begin)!=text.count(end) or text.count(begin)>1:raise CloudflareError('Las reglas persistentes Cloudflare requieren revisión. No se sobrescribieron.')
    if begin in text:text=text.split(begin,1)[0]+text.split(end,1)[1]
    if PRIORITY_CHAIN in text:raise CloudflareError('Existe una cadena de firewall ajena con el mismo nombre. Se conservó sin cambios.')
    if not enable:return text
    sections=list(re.finditer(r'^\*filter\s*$',text,re.M))
    if len(sections)!=1:raise CloudflareError('No se pudo localizar la sección de filtrado de UFW.')
    start=sections[0].end();commit=re.search(r'^COMMIT\s*$',text[start:],re.M)
    if not commit:raise CloudflareError('La configuración de UFW no está completa.')
    part=text[start:start+commit.start()];first=re.search(r'^-A ',part,re.M)
    if not first:raise CloudflareError('No se pudo localizar la cadena de entrada de UFW.')
    chain='ufw-before-input' if family==4 else 'ufw6-before-input'
    if not re.search(r'^:'+chain+r'\s',part,re.M):raise CloudflareError('La cadena de entrada de UFW no coincide.')
    comment=' -m comment --comment '+json.dumps(PRIORITY_TAG)
    lines=[':'+PRIORITY_CHAIN+' - [0:0]','-A '+chain+' -p tcp -m multiport --dports 80,443'+comment+' -j '+PRIORITY_CHAIN,'-A '+PRIORITY_CHAIN+' -i lo'+comment+' -j RETURN']
    lines+=['-A '+PRIORITY_CHAIN+' -s '+network+comment+' -j RETURN' for network in ranges if ipaddress.ip_network(network).version==family]
    lines+=['-A '+PRIORITY_CHAIN+' -p tcp'+comment+' -j REJECT --reject-with tcp-reset']
    at=start+first.start();return text[:at]+begin+'\n'.join(lines)+'\n'+end+text[at:]

def priority_cleanup():
    for binary in ('iptables','ip6tables'):
        result=run([binary,'-S',PRIORITY_CHAIN],check=False)
        if result.returncode:continue
        rows=[shlex.split(line) for line in result.stdout.splitlines() if line.startswith('-A ')]
        if any(PRIORITY_TAG not in row for row in rows):raise CloudflareError('La cadena Cloudflare contiene reglas ajenas. No se eliminó.')
        # The UFW reload has removed the jump. Never delete other chains.
        run([binary,'-F',PRIORITY_CHAIN]);run([binary,'-X',PRIORITY_CHAIN])

def assert_priority(policy):
    for family,binary in ((4,'iptables'),(6,'ip6tables')):
        chain='ufw-before-input' if family==4 else 'ufw6-before-input'
        rules=[shlex.split(line) for line in run([binary,'-S',chain]).stdout.splitlines() if line.startswith('-A ')]
        positions=[i for i,row in enumerate(rules) if '-j' in row and row[row.index('-j')+1]==PRIORITY_CHAIN and PRIORITY_TAG in row and '--dports' in row and row[row.index('--dports')+1]=='80,443']
        if len(positions)!=1 or any('-j' in row and row[row.index('-j')+1]=='ACCEPT' and not ('-i' in row and row[row.index('-i')+1]=='lo') for row in rules[:positions[0]]):raise CloudflareError('El bloqueo Cloudflare no está antes de las conexiones aceptadas por UFW.')
        actual=[shlex.split(line) for line in run([binary,'-S',PRIORITY_CHAIN]).stdout.splitlines() if line.startswith('-A ')]
        expected=[['-A',PRIORITY_CHAIN,'-i','lo','-m','comment','--comment',PRIORITY_TAG,'-j','RETURN']]
        expected += [['-A',PRIORITY_CHAIN,'-s',network,'-m','comment','--comment',PRIORITY_TAG,'-j','RETURN'] for network in policy['ranges'] if ipaddress.ip_network(network).version==family]
        expected += [['-A',PRIORITY_CHAIN,'-p','tcp','-m','comment','--comment',PRIORITY_TAG,'-j','REJECT','--reject-with','tcp-reset']]
        if actual!=expected:raise CloudflareError('El filtro Cloudflare IPv'+str(family)+' no coincide con los rangos oficiales o no rechaza la conexión.')
        saved=safe(BEFORE_FILES[family]).read_text()
        if saved!=priority_text(saved,family,True,policy['ranges']):raise CloudflareError('El filtro Cloudflare no quedó guardado para las próximas recargas de UFW.')
def firewall(enabled,ranges,ssl=False):
    # UFW preserves unrelated rules, including SSH; owned rules go before broad allows.
    # Runs BEFORE ESTABLISHED and all broad ALLOW rules, including old sockets.
    for family,path in BEFORE_FILES.items():
        text=safe(path).read_text();rendered=priority_text(text,family,enabled,ranges)
        if text!=rendered:write(path,rendered,stat.S_IMODE(path.stat().st_mode))
    run(['ufw','reload'])
    if not enabled:priority_cleanup()
    for number,_ in sorted(firewall_rules(),reverse=True):run(['ufw','--force','delete',str(number)])
    if not enabled:
        if ssl:run(['ufw','prepend','allow','in','proto','tcp','from','any','to','any','port','80,443','comment',SSL_TAG])
        for family in (4,6):repair_monitors(family)
        return
    for network in reversed(ranges):
        run(['ufw','prepend','allow','in','proto','tcp','from',network,'to','any','port','80,443','comment',TAG])
    for family in (4,6):repair_monitors(family)
def firewall_ready():
    import storypulse_ports as ports
    snapshot=ports.read_snapshot()
    if not snapshot['active'] or not snapshot['ipv6']:raise CloudflareError('La protección requiere UFW activo con IPv4 e IPv6 habilitados. No se dejó una familia sin proteger.')
    return snapshot
def assert_firewall(policy=None):
    snapshot=firewall_ready();p=read_policy() if policy is None else policy
    if not p.get('block_direct'):
        if p.get('ssl'):
            allowed={r['family'] for r in snapshot['rules'] if r['comment']==SSL_TAG and r['action']=='ALLOW' and r['any_source'] and r['protocol']=='tcp' and r['spans']==[(80,80),(443,443)]}
            if allowed!={4,6}:raise CloudflareError('Los puertos HTTPS fueron modificados. Usá Revisar cambios en la protección de Nginx para repararlos.')
        return
    owned=[r for r in snapshot['rules'] if r['comment']==TAG]
    expected={str(ipaddress.ip_network(n)) for n in p['ranges']}
    allowed={str(ipaddress.ip_network(r['source'])) for r in owned if r['action']=='ALLOW' and r['direction']=='IN' and r['protocol']=='tcp' and r['spans']==[(80,80),(443,443)]}
    if allowed!=expected:raise CloudflareError('Las reglas Cloudflare fueron modificadas. Usá Revisar cambios en la protección de Nginx para repararlas antes de instalar servicios web.')
    assert_priority(p)
def adopt_webapp(path):
    """A later WordPress installation becomes the managed domain's HTTPS root."""
    p=read_policy();path=str(path)
    if not p.get('ssl') or p.get('target')==path:return
    if path!=WEB_VHOST or p.get('target')!=MANAGED_MAIN:raise CloudflareError('SSL ya protege otro sitio. Conservá ese sitio y revisá el dominio antes de publicar otra aplicación.')
    old=Path(p['target']);base=source(old);p['target']=path;p['target_index']=0
    text=render(str(old),base,p);write(old,text,stat.S_IMODE(old.stat().st_mode))
    p['files'][str(old)]={'base':base,'hash':sha(text.encode()),'mode':stat.S_IMODE(old.stat().st_mode)};store(p)
def health_args(path):
    p=read_policy()
    if p.get('ssl'):return ['--cacert',str(ROOTS),'--resolve',p['domain']+':443:127.0.0.1','https://'+p['domain']+path]
    return ['http://127.0.0.1'+path]
def http_config(ranges):
    return '# Server Monitor: generated from official Cloudflare ranges\ngeo $realip_remote_addr $ssm_cf_peer_allowed {\ndefault 0;\n127.0.0.0/8 1;\n::1/128 1;\n'+''.join(n+' 1;\n' for n in ranges)+'}\n'+''.join('set_real_ip_from '+n+';\n' for n in ranges)+'real_ip_header CF-Connecting-IP;\nreal_ip_recursive on;\n'
def label_files(paths):
    import shutil
    if not shutil.which('getenforce',path='/usr/sbin:/usr/bin:/sbin:/bin'):return
    if run(['getenforce'],check=False).stdout.strip().lower()=='disabled':return
    for pattern,label in ((str(BASE)+'(/.*)?','httpd_config_t'),(str(BASE)+'/origin\\.(pem|key)','cert_t')):
        if run(['semanage','fcontext','-a','-t',label,pattern],check=False).returncode:run(['semanage','fcontext','-m','-t',label,pattern])
    run(['restorecon','-RF',str(BASE),*paths])
def edge_probe(p):
    try:addresses=sorted({row[4][0] for row in socket.getaddrinfo(p['domain'],443,type=socket.SOCK_STREAM)})
    except OSError:raise CloudflareError('El dominio no resuelve. Activá su registro DNS con proxy de Cloudflare antes de continuar.') from None
    nets=[ipaddress.ip_network(n) for n in p['ranges']]
    if not addresses or any(not any(ipaddress.ip_address(a) in n for n in nets) for a in addresses):raise CloudflareError('El dominio no está detrás del proxy de Cloudflare (nube naranja). Se restauró la configuración anterior.')
    address=next((a for a in addresses if ':' not in a),addresses[0]);address='['+address+']' if ':' in address else address
    # Follow at most three SAME-HOST redirects, always pinned to a Cloudflare IP.
    url=('https' if p['ssl'] else 'http')+'://'+p['domain']+'/'+p['challenge']
    for attempt in range(4):
        result=run(['curl','--noproxy','*','--silent','--show-error','--connect-timeout','5','--max-time','12','--max-filesize','8192','--resolve',p['domain']+':80:'+address,'--resolve',p['domain']+':443:'+address,'-i',url],check=False,timeout=15)
        parts=re.split(r'\r?\n\r?\n',result.stdout,maxsplit=1)
        if result.returncode or len(parts)!=2:break
        header,body=parts;match=re.match(r'HTTP/\S+ (\d+)',header);code=int(match[1]) if match else 0
        if code==200 and body==p['nonce']:return
        location=re.search(r'^location:\s*(\S+)',header,re.I|re.M)
        if code not in (301,302,307,308) or not location:break
        value=location[1]
        if value.startswith('/'):value='https://'+p['domain']+value
        if value!='https://'+p['domain']+'/'+p['challenge']:break
        url=value
    raise CloudflareError('Cloudflare no pudo llegar correctamente a este Nginx. Revisá el DNS, los puertos del proveedor y SSL/TLS Full (strict); Flexible puede provocar un bucle. Se restauró la configuración anterior.')
def status(body):
    if body!={}:raise CloudflareError('Consulta no válida.')
    p=read_policy()
    try:front=discover();installed=True;active=run(['systemctl','is-active',front['unit']],check=False).stdout.strip()=='active';error=''
    except (RuntimeError,OSError):installed=False;active=False;front={};error='No se pudo comprobar Nginx.'
    protection=False;ssl_active=False
    if p.get('block_direct'):
        try:assert_firewall(p);protection=True
        except (RuntimeError,OSError):error+=' El bloqueo de acceso directo no es efectivo. Revisá y aplicá nuevamente la protección.'
    if p.get('ssl') and active:
        try:
            probe=run(['curl','--noproxy','*','--silent','--show-error','--fail','--connect-timeout','1','--max-time','3',*health_args('/'+p['challenge'])],check=False,timeout=5)
            ssl_active=probe.returncode==0 and probe.stdout==p['nonce']
        except (RuntimeError,OSError,subprocess.TimeoutExpired):pass
        if not ssl_active:error+=' El SSL configurado no respondió correctamente a la comprobación HTTPS.'
    return dict(ok=True,installed=installed,active=active,unit=front.get('unit',''),block_direct=bool(p.get('block_direct')),protection_active=protection,ssl=bool(p.get('ssl')),ssl_active=ssl_active,domain=p.get('domain',''),certificate=p.get('certificate'),updated_at=p.get('updated_at'),range_count=len(p.get('ranges',[])),error=error.strip())
def plan(body):
    body=payload(body);front=discover();p=read_policy();on=body['block_direct'] or body['ssl']
    if on or p.get('block_direct'):firewall_ready()
    if body['block_direct'] and '--with-http_realip_module' not in run(['nginx','-V']).stderr:raise CloudflareError('Esta instalación Nginx no incluye el módulo para verificar la IP original de Cloudflare.')
    selected=target(front,body['domain']) if on else ('',0)
    info=cert_info(body)
    hashes={raw:sha(Path(raw).read_bytes()) for raw in front['files']}
    material={'options':{k:v for k,v in body.items() if k not in ('certificate','private_key')},'certificate':info,'front':front,'hashes':hashes,'policy':p,'firewall':run(['ufw','status','numbered']).stdout,'new_certificate':sha(body.get('certificate','').strip().encode()),'new_key':sha(body.get('private_key','').strip().encode())}
    return dict(ok=True,revision=digest(material),domain=body['domain'],block_direct=body['block_direct'],ssl=body['ssl'],certificate=info,unit=front['unit'],site=selected[0],message='Se respaldará Nginx, se habilitarán TCP 80/443 según las opciones elegidas y se comprobará el acceso por Cloudflare. Si falla, se restaurará el estado anterior. SSH no se modifica.')
def reload(front):
    if 'server-monitor-webnginx' in front['unit']:
        import storypulse_service_flow as flow
        flow.runtime_directory('server-monitor-webnginx')
    run(['nginx','-t','-c',front['main']])
    if run(['systemctl','is-active',front['unit']],check=False).stdout.strip()=='active':run(['systemctl','reload',front['unit']],timeout=45)
    else:run(['systemctl','enable','--now',front['unit']],timeout=60)
    if run(['systemctl','is-active',front['unit']],check=False).stdout.strip()!='active':raise CloudflareError('Nginx no quedó activo.')
def update_stack_hash():
    if STACK.exists():
        p=json.loads(STACK.read_text());path=Path(p['vhost'])
        if path.exists():p['vhost_sha256']=sha(path.read_bytes());write(STACK,json.dumps(p))
def timer(enabled):
    service=Path('/etc/systemd/system/server-monitor-cloudflare.service');timerpath=service.with_suffix('.timer')
    if enabled:
        write(service,'[Unit]\nDescription=Server Monitor Cloudflare official ranges\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -B /usr/local/sbin/storypulse_cloudflare.py --refresh\nUMask=0077\n',0o644)
        write(timerpath,'[Unit]\nDescription=Update Cloudflare origin ranges daily\n[Timer]\nOnCalendar=daily\nRandomizedDelaySec=3600\nPersistent=true\n[Install]\nWantedBy=timers.target\n',0o644)
        run(['systemctl','daemon-reload']);run(['systemctl','enable','--now',timerpath.name])
    else:
        run(['systemctl','disable','--now',timerpath.name],check=False)
        for path in (service,timerpath):safe(path);path.unlink(missing_ok=True)
        run(['systemctl','daemon-reload'])
def trim_backups():
    root=BASE/'backups'
    if not root.exists():return
    folders=sorted((p for p in root.iterdir() if p.name.isdigit()),key=lambda p:p.name)
    for folder in folders[:-3]:
        removal.safe_path(folder)
        if not folder.is_dir() or folder.stat().st_uid!=0:continue
        files=list(folder.iterdir())
        if any(not (p.name.isdigit() or p.name=='index.json') or not p.is_file() or p.is_symlink() for p in files):continue
        for path in files:safe(path);path.unlink()
        folder.rmdir()
def apply(body):
    import fcntl
    request=payload(body,True)
    if body.get('confirm') is not True or not re.fullmatch('[a-f0-9]{64}',str(body.get('revision',''))):raise CloudflareError('Revisá y confirmá la operación.')
    with removal.package_lock(),removal.FIREWALL_LOCK.open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise CloudflareError('Hay otro cambio de firewall en curso.') from None
        reviewed=plan(request)
        if reviewed['revision']!=body['revision']:raise CloudflareError('La configuración cambió. Revisá nuevamente antes de confirmar.')
        old=read_policy();front=discover();on=request['block_direct'] or request['ssl'];new={**old,**{k:v for k,v in request.items() if k not in ('certificate','private_key','refresh')},'version':1,'main':front['main'],'unit':front['unit'],'files':{},'certificate':reviewed['certificate']}
        if on:
            new['target'],new['target_index']=target(front,request['domain']);new['challenge']='ssm-origin-'+secrets.token_hex(16);new['nonce']=secrets.token_hex(24)
            new['ranges']=refresh_ranges() if request.get('refresh') or not old.get('ranges') or not (old.get('block_direct') or old.get('ssl')) else old['ranges']
        bases={raw:source(raw) for raw in front['files']}
        paths={Path(x) for x in bases}|set(BEFORE_FILES.values())|{POLICY,HTTP,CERT,KEY,ROOTS,STACK,Path('/etc/ufw/user.rules'),Path('/etc/ufw/user6.rules'),Path('/etc/systemd/system/server-monitor-cloudflare.service'),Path('/etc/systemd/system/server-monitor-cloudflare.timer')}
        backup={path:(safe(path).read_bytes(),stat.S_IMODE(path.stat().st_mode)) if path.exists() else None for path in paths}
        # Durable private rollback copy; never expose it through status or the web root.
        destination=BASE/'backups'/str(time.time_ns())
        for index,(path,value) in enumerate(backup.items()):
            if value:write(destination/str(index),value[0])
        write(destination/'index.json',json.dumps([{'path':str(p),'mode':v[1] if v else None} for p,v in backup.items()]))
        was_active=run(['systemctl','is-active',front['unit']],check=False).stdout.strip()=='active'
        was_enabled=run(['systemctl','is-enabled',front['unit']],check=False).stdout.strip()=='enabled'
        try:
            if request['ssl']:
                if request.get('certificate'):write(CERT,request['certificate'].strip()+'\n');write(KEY,request['private_key'].strip()+'\n')
                if not ROOTS.exists():write(ROOTS,''.join(official(url) for url in ROOT_URLS))
            write(HTTP,http_config(new.get('ranges',[])),0o644)
            for raw,base in bases.items():
                rendered=render(raw,base,new);mode=stat.S_IMODE(Path(raw).stat().st_mode)
                write(Path(raw),rendered,mode)
                if on and rendered!=base:new['files'][raw]={'base':base,'hash':sha(rendered.encode()),'mode':mode}
            # Test BEFORE narrowing the firewall. Never reload invalid configuration.
            label_files(list(bases));run(['nginx','-t','-c',front['main']]);firewall(request['block_direct'],new.get('ranges',[]),request['ssl']);assert_firewall(new);reload(front)
            if on:edge_probe(new)
            new['updated_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();store(new);update_stack_hash();timer(on)
            if request['ssl']:
                # Open the local origin with the trusted Origin CA, never curl -k.
                response=run(['curl','--noproxy','*','--silent','--show-error','--fail','--max-time','8',*health_args('/'+new['challenge'])])
                if response.stdout!=new['nonce']:raise CloudflareError('Falló la comprobación HTTPS local.')
            trim_backups()
            return dict(ok=True,message='Configuración Cloudflare aplicada y comprobada.' if on else 'Protección Cloudflare desactivada. Se restauró la configuración web anterior.',state=status({}))
        except Exception as error:
            for path,value in backup.items():
                if value:write(path,value[0],value[1])
                else:safe(path);path.unlink(missing_ok=True)
            try:
                label_files(list(bases));run(['ufw','reload'])
                if not old.get('block_direct'):priority_cleanup()
                for family in (4,6):repair_monitors(family)
                reload(front) if was_active else run(['systemctl','stop',front['unit']])
                if not was_enabled:run(['systemctl','disable',front['unit']])
                timer(bool(old.get('block_direct') or old.get('ssl')))
            except Exception:raise CloudflareError('La operación falló y no se pudo confirmar toda la restauración. Conservá el respaldo privado y revisá Nginx por SSH.') from None
            if isinstance(error,CloudflareError):raise
            raise CloudflareError('No se pudo aplicar Cloudflare. Se restauró la configuración anterior.') from None

def scheduled_refresh():
    p=read_policy()
    if not enabled():return
    body={k:p[k] for k in ('domain','block_direct','ssl')};body['refresh']=True
    reviewed=plan(body);apply({**body,'revision':reviewed['revision'],'confirm':True})
    run(['/usr/local/sbin/storypulse-securityctl','sync'])
if __name__=='__main__':
    import sys
    if os.geteuid()!=0 or sys.argv[1:]!=['--refresh']:raise SystemExit('Acción no permitida.')
    try:scheduled_refresh()
    except Exception as error:raise SystemExit(str(error) if isinstance(error,CloudflareError) else 'Cloudflare: se conservó la última configuración válida.')
