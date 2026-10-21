export const MENU_PERMISSIONS=Object.freeze([
 ['overview','Resumen','General'],['activity','Tráfico entrante','Tráfico de red'],['outgoing','Tráfico saliente','Tráfico de red'],['providers','Proveedores','General'],
 ['ssh','Accesos SSH','SSH'],['reports','Generar Reporte','SSH'],
 ['ports','GestiÃ³n de puertos','Puertos'],['forwarding','Port Forwarding','Puertos'],['port-traffic','TrÃ¡fico en puertos','Puertos'],
 ['services-install','Instalar servicios','Servicios'],['services-manage','Gestionar servicios','Servicios'],['services-remove','Eliminar servicios','Servicios'],
 ['games-install','Instalar juegos','Juegos'],['games-manage','Gestionar juegos','Juegos'],['games-remove','Eliminar juegos','Juegos'],
 ['databases','Bases de datos','General'],['investigate','Investigar IP','General'],['blocks','Bloqueos de IP','Bloqueos'],
 ['authorized-ips','IP autorizadas','Bloqueos'],['system','Estado del sistema','Sistema'],['alerts','Alertas','Sistema'],
 ['appearance','Personalizar panel','General'],['cleanup','Borrado de datos','General']
].map(([id,label,group])=>Object.freeze({id,label,group})));
export const ALL_PERMISSIONS=Object.freeze(MENU_PERMISSIONS.map(p=>p.id));
const known=new Set(ALL_PERMISSIONS);
export function validatePermissions(value){
 if(!Array.isArray(value)||value.length>ALL_PERMISSIONS.length||value.some(v=>typeof v!=='string'||!known.has(v))||new Set(value).size!==value.length)
  throw Object.assign(new Error('Los permisos contienen menÃºs no vÃ¡lidos o repetidos.'),{status:400});
 return ALL_PERMISSIONS.filter(id=>value.includes(id));
}
export function permissionsFor(user){
 if(user?.primary||user?.administrator)return [...ALL_PERMISSIONS,'terminal','panel-users'];
 return user?.permissions===undefined?[...ALL_PERMISSIONS]:validatePermissions(user.permissions);
}
const routes=new Map([
 ['/api/cloudflare',['services-manage']],['/api/cloudflare/plan',['services-manage']],['/api/cloudflare/apply',['services-manage']],
 ['/api/network/outgoing',['outgoing']],
 ['/api/games',['games-install','games-manage','games-remove']],['/api/games/console',['games-manage']],['/api/games/ftp/reveal',['games-manage']],['/api/games/plan',['games-install','games-manage','games-remove']],['/api/games/apply',['games-install','games-manage','games-remove']],
 ['/api/catalog-services',['services-install','services-manage','services-remove']],['/api/catalog-services/versions',['services-install']],['/api/catalog-services/plan',['services-install','services-manage','services-remove']],['/api/catalog-services/apply',['services-install','services-manage','services-remove']],
 ['/api/service-versions',['services-install']],['/api/ports',['ports']],['/api/ports/plan',['ports']],['/api/ports/apply',['ports']],
 ['/api/forwarding',['forwarding']],['/api/forwarding/plan',['forwarding']],['/api/forwarding/apply',['forwarding']],
 ['/api/services',['services-install','services-manage','services-remove']],['/api/services/plan',['services-install','services-manage','services-remove']],['/api/services/apply',['services-install','services-manage','services-remove']],
 ['/api/mysql',['services-install','services-manage','services-remove','databases']],['/api/mysql/plan',['services-install','services-manage','services-remove']],['/api/mysql/apply',['services-install','services-manage','services-remove']],['/api/mysql/structure',['services-manage']],
 ['/api/mysql/login',['databases']],['/api/mysql/data',['databases']],['/api/mysql/logout',['databases']],
 ['/api/cleanup',['cleanup']],['/api/cleanup/plan',['cleanup']],['/api/cleanup/apply',['cleanup']],
 ['/api/server/reboot/plan',['system']],['/api/server/reboot',['system']],
 ['/api/alerts',['alerts']],['/api/alerts/configure',['alerts']],
 ['/api/authorized-ips',['authorized-ips']],['/api/authorized-ips/plan',['authorized-ips']],['/api/authorized-ips/apply',['authorized-ips']],
 ['/api/reports/ssh',['reports']],['/api/ssh-live',['ssh']],['/api/port',['port-traffic']],
 ['/api/blocks',['blocks']],['/api/blocks/ip',['blocks']],['/api/blocks/provider',['blocks']],
 ['/api/providers/evaluate',['blocks']],['/api/ip',['investigate']],
 ['/api/refresh',['overview','activity','outgoing','providers','ssh','port-traffic','system']]
]);
const common=new Set(['/api/profile/avatar','/api/health','/api/dashboard','/api/server','/api/commands/status','/api/notifications','/api/notifications/read','/api/notifications/delete']);
export function routeAllowed(user,path){
 if(user?.primary||user?.administrator)return true;
 if(path==='/api/terminal'||path.startsWith('/api/terminal/'))return false;
 if(common.has(path))return true;
 const required=routes.get(path);return !!required&&required.some(id=>permissionsFor(user).includes(id));
}
export function requireServicePermission(user,action){
 const required=(action==='install'||action==='upgrade')?'services-install':action==='uninstall'?'services-remove':'services-manage';
 if(!permissionsFor(user).includes(required))throw Object.assign(new Error('Tu cuenta no tiene permiso para esta operaciÃ³n del servicio.'),{status:403});
}
export function permittedDashboard(user,data){
 if(user?.primary||user?.administrator)return data;
 const rights=new Set(permissionsFor(user)),has=(...ids)=>ids.some(id=>rights.has(id));
 const overview=has('overview'),activity=has('activity');
 return {...data,
  summary:overview?data.summary:{...(has('providers')?{providers:data.summary.providers,drop_packets:data.summary.drop_packets}:{}),...(has('ssh')?{ssh_failures:data.summary.ssh_failures,ssh_success:data.summary.ssh_success}: {})},
  system:has('system')?data.system:{},
  countries:overview?data.countries:[],countries_all:overview?data.countries_all:[],
  timeline:overview?data.timeline:[],providers:has('overview','providers')?data.providers:[],
  ports:has('port-traffic')?data.ports:[],ssh_users:has('overview','ssh')?data.ssh_users:[],
  ssh_events:has('ssh')?data.ssh_events:[],events:has('overview','activity')?data.events:[],
  activity_events:activity?data.activity_events:{}
 };
}
export const ACCESS_TARGETS=Object.freeze({...Object.fromEntries(MENU_PERMISSIONS.map(p=>[p.id,p.label])),terminal:'Terminal','panel-users':'Usuarios panel','restricted-api':'FunciÃ³n restringida'});
export function routeTarget(path){
 if(path==='/api/terminal'||path.startsWith('/api/terminal/'))return 'terminal';
 if(path==='/api/auth/users'||path.startsWith('/api/auth/users/'))return 'panel-users';
 return routes.get(path)?.[0]||'restricted-api';
}
export const serviceTarget=action=>(action==='install'||action==='upgrade')?'services-install':action==='uninstall'?'services-remove':'services-manage';

export const gameTarget=action=>action==='install'?'games-install':action==='uninstall'?'games-remove':'games-manage';
export function requireGamePermission(user,action){if(!permissionsFor(user).includes(gameTarget(action)))throw Object.assign(new Error('Tu cuenta no tiene permiso para esta operación del juego.'),{status:403});}
