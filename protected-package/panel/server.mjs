import {serverScope,createServerSwitch} from './server-scope.mjs';
import {createAsnDatabase} from './geo-asn.mjs';
import {createOutgoingTraffic} from './outgoing-traffic.mjs';
import {createCountryDatabase} from './geo-country.mjs';
import {createGeoCache} from './geo-cache.mjs';
import {countryName} from './geo-ip.mjs';
import {createProfileApi} from './profile-api.mjs';
import {createZoneApi} from './zone-api.mjs';
import {createZoneControllerFlow} from './zone-controller-flow.mjs';
import {createGamesApi} from './games-api.mjs';
import {createGameFtpVault} from './game-ftp-vault.mjs';
import {createCloudflareApi} from './cloudflare-api.mjs';
import {createCatalogServicesApi} from './catalog-services-api.mjs';
import {createWebappControllerFlow} from './webapp-controller-flow.mjs';
import {createServiceVersionsApi} from './service-versions-api.mjs';
import {createPanelAuth} from './panel-auth.mjs';
import {requireServicePermission,permittedDashboard,serviceTarget,requireGamePermission,gameTarget} from './panel-permissions.mjs';
import {createTerminalApi} from './terminal-api.mjs';
import {createTerminalRunner} from './terminal-runner.mjs';
import {createWindowsHello} from './windows-hello.mjs';
import {protectedRuntime,protectedPaths,protectedCall} from './protected-runtime.mjs';
import {createInstallationHealth} from './installation-health.mjs';
import {normalizeSshConfig,sshConfigurationId,connectionArgs,createSshAuthentication} from './ssh-auth.mjs';
import {createCommandGuard} from './command-guard.mjs';
import {createTrustedPolicy,createTrustedApi} from './trusted-api.mjs';
import {createAlertsApi} from './alerts-api.mjs';
import {createNotifications} from './notifications.mjs';
import {readJsonBody,readResponseJson} from './http-input.mjs';
import {downloadReport} from './report-download.mjs';
import {createSystemApi} from './system-api.mjs';
import {createCleanupApi} from './cleanup-api.mjs';
import {createHistoryStore} from './cleanup-store.mjs';
import {createMysqlApi} from './mysql-api.mjs';
import http from "node:http";
import { dashboardData, DashboardCache } from "./dashboard-data.mjs";
import { isGeoCandidate, localRequestAllowed, validateListen, setSecurityHeaders } from "./local-security.mjs";
import { gunzipSync } from "node:zlib";
import { spawn } from "node:child_process";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { DatabaseSync } from "node:sqlite";
import { existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, join } from "node:path";
import { fileURLToPath,domainToASCII } from "node:url";

const ROOT = dirname(fileURLToPath(import.meta.url));
const windowsHello=createWindowsHello(ROOT);
const STATIC_ROOT = join(ROOT, "dist");
const STATE_BASE = protectedRuntime?protectedPaths().data:ROOT;
const CONFIG_PATH = join(ROOT, "config.json");

const SECURITY_CTL = "/usr/local/sbin/storypulse-securityctl";
const ACTION_TOKEN = randomBytes(32).toString("hex");
const PANEL_SESSION_ID = randomBytes(8).toString("hex");
const dashboardCache = new DashboardCache();

const config = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
const scope=serverScope({base:STATE_BASE,root:ROOT,config,metadata:protectedRuntime?process.env.SSM_SERVER_META:null});
const DATA_ROOT=scope.data,PROVIDER_APPROVALS_PATH=scope.approvals;
mkdirSync(DATA_ROOT,{recursive:true});
const panelAuth = await createPanelAuth({root:ROOT,serverIdentity:scope.id,serverLabel:scope.label,hello:windowsHello,onDenied:(user,target,source)=>notifications.accessDenied(user,target,source)});
const serverSwitch=createServerSwitch({token:protectedRuntime?process.env.SSM_SWITCH_TOKEN:'',safe:()=>restartSafe()});
delete process.env.SSM_SWITCH_TOKEN;
const installationHealth=createInstallationHealth({enabled:protectedRuntime&&process.env.SSM_MIGRATION_CHECK==='1',check:()=>protectedCall('installation-check')});
config.ssh=normalizeSshConfig(config.ssh,ROOT);
const sshAuthentication=createSshAuthentication(config.ssh);
let sshPasswordRejected=false;
process.once('exit',()=>sshAuthentication.dispose());
const listenPort = Number(process.env.STORYPULSE_PORT || config.listenPort || 8766);
const listenHost = config.listenHost || "127.0.0.1";
validateListen(listenHost, listenPort);
const reportConfig = config.reports || {};
const REPORT_LOCAL_OUTPUT = scope.reports;
const REPORT_MAX_DAYS = Math.max(1, Math.min(7, Math.trunc(Number(reportConfig.maxDays || 7))));
// Collection runs only the root-owned, installed collector through its fixed controller action.
const db = new DatabaseSync(join(DATA_ROOT, "storypulse.db"));
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = NORMAL;
  CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    kind TEXT NOT NULL,
    ip TEXT NOT NULL,
    provider_slug TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL DEFAULT '',
    port TEXT NOT NULL DEFAULT '',
    service TEXT NOT NULL DEFAULT '',
    decision TEXT NOT NULL DEFAULT '',
    ssh_user TEXT NOT NULL DEFAULT '',
    auth_method TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS events_timestamp_idx ON events(timestamp);
  CREATE INDEX IF NOT EXISTS events_ip_idx ON events(ip);
  CREATE INDEX IF NOT EXISTS events_kind_timestamp_idx ON events(kind,timestamp);
  CREATE INDEX IF NOT EXISTS events_ip_timestamp_idx ON events(ip,timestamp);
  CREATE TABLE IF NOT EXISTS geo_cache (
    ip TEXT PRIMARY KEY,
    country_code TEXT NOT NULL DEFAULT '',
    country TEXT NOT NULL DEFAULT '',
    isp TEXT NOT NULL DEFAULT '',
    asn TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL,
    ok INTEGER NOT NULL DEFAULT 1
  );
  CREATE TABLE IF NOT EXISTS state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS block_audit (
    id INTEGER PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    ok INTEGER NOT NULL,
    details TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS block_audit_timestamp_idx ON block_audit(timestamp);
  PRAGMA optimize;
`);


const outgoingTraffic=createOutgoingTraffic(db);
const insertEvent = db.prepare(`
  INSERT OR IGNORE INTO events
  (id,timestamp,kind,ip,provider_slug,provider,protocol,port,service,decision,ssh_user,auth_method,details)
  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
`);
const setState = db.prepare("INSERT INTO state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");
const getState = db.prepare("SELECT value FROM state WHERE key=?");
const insertBlockAudit = db.prepare(`
  INSERT INTO block_audit(timestamp,action,target,reason,ok,details)
  VALUES(?,?,?,?,?,?)
`);

let connection = {
  connected: false,
  collecting: false,
  transport: "SSH persistente",
  transportConnected: false,
  lastSuccess: 0,
  lastAttempt: 0,
  sourceIp: "",
  error: "Esperando la primera conexión",
};
let refreshTimer;
let catchupTimer;
let sshMasterProcess = null;
let sshMasterStarting = null;
let sshMasterReady = false;
let sshMasterOwned = false;
let sshMasterStderr = "";
let panelSessionMarkerSent = false;
let sshReportJob = {
  status: "idle",
  days: null,
  started_at: 0,
  finished_at: 0,
  files: [],
  message: "Todavía no se generó ningún reporte desde el panel.",
  error: "",
};
const GEO_BACKEND_VERSION = 5;

function stateValue(key, fallback) {
  const row = getState.get(key);
  if (!row) return fallback;
  try { return JSON.parse(row.value); } catch { return fallback; }
}

function saveState(key, value) {
  setState.run(key, JSON.stringify(value));
}

const trustedPolicy=createTrustedPolicy(stateValue('trusted_policy',null));
const notifications=createNotifications(db,{isAuthorized:ip=>trustedPolicy.has(ip)});
db.function('is_authorized_ip',ip=>trustedPolicy.has(ip)?1:0);
function acceptTrustedPolicy(value){
  if(value?.ready===false){saveState('trusted_policy_invalid',true);return;}
  if(!trustedPolicy.update(value))return;
  saveState('trusted_policy_invalid',false);
  saveState('trusted_policy',trustedPolicy.current());
  notifications.reconcileAuthorization();dashboardCache.entries.clear();
}


if (Number(stateValue("geo_backend_version", 0)) < GEO_BACKEND_VERSION) {
  // Reintenta los países pendientes con la base local, conservando los datos confirmados.
  db.prepare("UPDATE geo_cache SET updated_at=0 WHERE ok=0 OR country_code='' ").run();
  saveState("geo_backend_version", GEO_BACKEND_VERSION);
}

function isTailscaleAddress(address) {
  const value = String(address || "").trim().toLowerCase();
  const parts = value.split(".").map(Number);
  if (parts.length === 4 && parts.every(part => Number.isInteger(part) && part >= 0 && part <= 255)) {
    return parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127;
  }
  return value.startsWith("fd7a:115c:a1e0:");
}

db.function("is_geo_candidate", { deterministic:true }, value => isGeoCandidate(String(value || "")) ? 1 : 0);

db.function("is_tailscale_ip", { deterministic:true }, value => isTailscaleAddress(value) ? 1 : 0);

function sshTarget() {
  return `${config.ssh.user}@${config.ssh.host}`;
}

function plinkConnectionArgs(options={}) {return connectionArgs(config.ssh,options);}

function sharedConnectionExists(timeoutMs=protectedRuntime?20000:5000) {
  return new Promise(resolve => {
    const child = spawn(config.ssh.plinkPath, [
      ...plinkConnectionArgs(), "-shareexists", sshTarget(),
    ], {
      windowsHide: true,
      stdio: "ignore",
    });
    let settled = false;
    const finish = value => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve(value);
    };
    const timeout = setTimeout(() => {
      child.kill();
      finish(false);
    }, timeoutMs);
    child.on("error", () => finish(false));
    child.on("close", code => finish(code === 0));
  });
}

function wait(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

async function markPanelSessionStarted() {
  if (panelSessionMarkerSent) return;
  await runSharedRemote(
    `/usr/bin/logger -t storypulse-panel -- 'SESSION_STARTED ${PANEL_SESSION_ID}'`,
    "",
    10000,
  );
  panelSessionMarkerSent = true;
}

function stopOwnedSshMaster() {
  const child = sshMasterProcess;
  sshMasterReady = false;
  connection.transportConnected = false;
  if (child && sshMasterOwned && child.exitCode === null && !child.killed) child.kill();
  sshMasterProcess = null;
  sshMasterOwned = false;
}

async function ensureSshMaster() {
  if (sshMasterStarting) return sshMasterStarting;
  if(sshPasswordRejected)throw new Error("El servidor rechazó la contraseña SSH. Corregila y volvé a iniciar el panel; no se repetirán intentos automáticamente.");
  sshMasterStarting = (async () => {
    if (sshMasterReady && await sharedConnectionExists()) {
      connection.transportConnected = true;
      await markPanelSessionStarted();
      return;
    }

    sshMasterReady = false;
    connection.transportConnected = false;
    if (await sharedConnectionExists()) {
      // Puede ser una sesión de PuTTY ya abierta por el usuario. Se reutiliza,
      // pero no se cierra al terminar el panel porque no nos pertenece.
      sshMasterReady = true;
      sshMasterOwned = false;
      connection.transportConnected = true;
      await markPanelSessionStarted();
      return;
    }

    stopOwnedSshMaster();
    sshMasterStderr = "";
    const credential=sshAuthentication.prepare();
    try {
    const args = [
      ...plinkConnectionArgs({ authenticate: true,passwordFile:credential.path }),
      "-share", "-N", sshTarget(),
    ];
    const child = spawn(config.ssh.plinkPath, args, {
      windowsHide: true,
      stdio: ["ignore", "ignore", "pipe"],
    });
    sshMasterProcess = child;
    sshMasterOwned = true;
    let spawnError = null;
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", chunk => {
      sshMasterStderr = sshAuthentication.redact(`${sshMasterStderr}${chunk}`).slice(-4000);
    });
    child.on("error", error => { spawnError = error; });
    child.on("close", () => {
      if (sshMasterProcess !== child) return;
      sshMasterProcess = null;
      sshMasterReady = false;
      sshMasterOwned = false;
      connection.transportConnected = false;
    });

    const deadline=Date.now()+15000;
    while (Date.now()<deadline) {
      if (spawnError) throw spawnError;
      if (child.exitCode !== null) {
        if(config.ssh.authMode==='password'&&/Access denied|Authentication failed|No supported authentication|Unable to authenticate|password was not accepted/i.test(sshMasterStderr))sshPasswordRejected=true;
        throw new Error((sshMasterStderr || `La conexión SSH persistente terminó con código ${child.exitCode}`).trim());
      }
      if (await sharedConnectionExists(Math.max(100,Math.min(2000,deadline-Date.now())))) {
        sshMasterReady = true;
        connection.transportConnected = true;
        await markPanelSessionStarted();
        return;
      }
      await wait(250);
    }

    stopOwnedSshMaster();
    throw new Error("No se pudo establecer la conexión SSH persistente en 15 segundos");
    }finally{credential.cleanup();}
  })().finally(() => {
    sshMasterStarting = null;
  });
  return sshMasterStarting;
}

function runSharedRemote(remote, input = "", timeoutMs = 30000) {
  serverSwitch.assert();
  return new Promise((resolve, reject) => {
    const ssh = config.ssh;
    const args = [
      ...plinkConnectionArgs(), "-share", "-no-trivial-auth",
    ];
    args.push(sshTarget(), remote);
    const child = spawn(ssh.plinkPath, args, {
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let outputBytes = 0;
    let overflow = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", chunk => {
      if (overflow) return;
      outputBytes += Buffer.byteLength(chunk);
      if (outputBytes > 32*1024*1024) { overflow=true; stdout=""; child.kill(); return; }
      stdout += chunk;
    });
    child.stderr.on("data", chunk => { stderr = sshAuthentication.redact(stderr + chunk).slice(-65536); });
    child.on("error", error => {
      clearTimeout(timeout);
      reject(error);
    });
    child.on("close", code => {
      clearTimeout(timeout);
      if (overflow) { reject(new Error("La respuesta remota supera el límite de 32 MB. Reducí el período de consulta.")); return; }
      if (timedOut) {
        reject(new Error("La operación remota superó el tiempo máximo"));
        return;
      }
      if (code !== 0) {
        reject(new Error((stderr || stdout || `Plink terminó con código ${code}`).trim()));
        return;
      }
      resolve(stdout);
    });
    child.stdin.on("error", error => {
      if (error.code !== "EPIPE" && error.code !== "ERR_STREAM_DESTROYED") reject(error);
    });
    child.stdin.end(input);
  });
}

async function runRemote(remote, input = "", timeoutMs = 30000) {
  await ensureSshMaster();
  commandGuard.assertCurrent();
  try {
    return await runSharedRemote(remote, input, timeoutMs);
  } catch (error) {
    if (!await sharedConnectionExists()) {
      sshMasterReady = false;
      connection.transportConnected = false;
    }
    throw error;
  }
}

async function runPlink(sinceEpoch, untilEpoch) {
  const remote = `sudo -n ${SECURITY_CTL} collect --json-input`;
  const stdout = await runRemote(remote, JSON.stringify({since:Math.max(0,Math.floor(sinceEpoch)),until:Math.max(0,Math.floor(untilEpoch))}), 90000);
  try {
    const wire = stdout.trim();
    const decoded = wire.startsWith("SPGZIP1:")
      ? gunzipSync(Buffer.from(wire.slice(8), "base64"), {maxOutputLength:128*1024*1024}).toString("utf8")
      : wire;
    const payload = JSON.parse(decoded);
    if (!payload.ok) throw new Error(payload.error || "El recolector no respondió correctamente");
    return payload;
  } catch (error) {
    throw new Error(`Respuesta inválida del servidor: ${error.message}`);
  }
}

function persistEvents(events) {
  // Upgrade old journal IDs in the same transaction, without duplicating the
  // overlap at the saved collection boundary. Later entries remain distinct.
  const migrateId = db.prepare(`UPDATE events SET id=? WHERE id=?
    AND NOT EXISTS (SELECT 1 FROM events WHERE id=?)`);
  db.exec("BEGIN");
  try {
    for (const event of events || []) {
      if(event.kind==='network_outgoing'){outgoingTraffic.persist(event);continue;}
      if (event.legacy_id && event.legacy_id !== event.id) {
        migrateId.run(event.id, event.legacy_id, event.id);
      }
      notifications.ingest(event);
      insertEvent.run(
        event.id, Number(event.timestamp), event.kind || "", event.ip || "",
        event.provider_slug || "", event.provider || "", event.protocol || "",
        String(event.port ?? ""), event.service || "", event.decision || "",
        event.ssh_user || "", event.auth_method || "", event.details || "",
      );
    }
    if(config.geoLookup)geoCache.fill((events||[]).map(event=>event.ip));
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

// Countries and network operators are resolved locally for every incoming IP.
// There is no per-IP HTTP request, daily quota, or external lookup queue.
async function geolocateBatch(addresses){
 if(!config.geoLookup)return false;
 return fetchGeoBatch(addresses);
}
async function fetchGeoBatch(addresses){
 const ips=[...new Set((addresses||[]).map(value=>String(value||'').trim()))].filter(ip=>isIP(ip)).slice(0,100);
 geoCache.fill(ips);return ips.length>0;
}
async function ensureGeo(ip){
 if(config.geoLookup&&isIP(ip))geoCache.fill([ip]);
}

async function collectNow() {
  if(serverSwitch.paused()||!panelAuth.ready()||process.env.SSM_MIGRATION_CHECK==='1')return;
  if (connection.collecting) return;
  connection.collecting = true;
  connection.lastAttempt = Math.floor(Date.now() / 1000);
  let moreHistory = false;
  try {
    const generation = historyStore.generation();
    const policyGeneration=trustedPolicy.generation();
    const now = Math.floor(Date.now() / 1000);
    const previous = stateValue("last_remote_timestamp", 0);
    const firstSince = now - Number(config.initialHistoryHours || 168) * 3600;
    const since = previous ? Math.max(0, previous - 3) : firstSince;
    const batchHours = Math.min(24, Math.max(1, Number(config.historyBatchHours) || 12));
    const batchSeconds = Number(stateValue("collection_batch_seconds", batchHours*3600)) || batchHours*3600;
    const until = Math.min(now, since + Math.min(batchHours*3600, Math.max(60,batchSeconds)));
    const payload = await runPlink(since, until);
    const collectedUntil = Number(payload.collected_until);
    if (!Number.isInteger(collectedUntil) || collectedUntil !== until) {
      throw new Error("El servidor no confirmó el límite del historial consultado");
    }
    if (generation !== historyStore.generation()) return;
    historyStore.applyReset(payload.cleanup_reset);
    const floor = Number(stateValue("cleanup_reset", null)?.cutoff || 0);
    if(policyGeneration===trustedPolicy.generation())acceptTrustedPolicy(payload.system?.security_monitor);
    persistEvents((payload.events || []).filter(row => row.timestamp >= floor));
    saveState("providers", payload.providers || []);
    saveState("system", payload.system || {});
    saveState("last_remote_timestamp", Math.max(collectedUntil, floor));
    moreHistory = Math.max(collectedUntil, floor) < now;
    connection.historyPending = moreHistory;
    connection.sourceIp = payload.collector_ip || connection.sourceIp;
    connection.connected = true;
    connection.lastSuccess = payload.generated_at;
    connection.error = "";
  } catch (error) {
    connection.connected = false;
    if (/COLLECTION_TOO_LARGE|límite de 32 MB|maxOutputLength|larger than/i.test(String(error.message || error))) {
      const current=Number(stateValue("collection_batch_seconds", 43200)) || 43200;
      if(current>60){saveState("collection_batch_seconds",Math.max(60,Math.floor(current/2)));moreHistory=true;}
    }
    connection.error = String(error.message || error).split("\n").slice(-3).join(" ").slice(0, 600);
  } finally {
    connection.collecting = false;
    if (moreHistory) {
      clearTimeout(catchupTimer);
      catchupTimer = setTimeout(collectNow, 250);
    }
  }
}

function countryFlag(code) {
  if (!countryName(code)) return "🌐";
  return [...code].map(char => String.fromCodePoint(127397 + char.charCodeAt())).join("");
}

function serviceFor(protocol, port) {
  if (String(port).startsWith("tipo-")) return "ICMP";
  const names = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",
    443:"HTTPS",445:"SMB",1433:"SQL Server",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",
    5900:"VNC",6379:"Redis",8000:"HTTP alternativo",8080:"HTTP alternativo",
    8443:"HTTPS alternativo",9200:"Elasticsearch",27017:"MongoDB",
  };
  return names[Number(port)] || (protocol === "ICMP" ? "ICMP" : "Servicio desconocido");
}

function isFirewallBlocked(row) {
  return row.kind === "firewall" || row.kind === "firewall_block";
}

function isFirewallAllowed(row) {
  return row.kind === "firewall_allow";
}

function flowStatus(row) {
  if (isFirewallBlocked(row)) return "blocked";
  if (isFirewallAllowed(row)) return "accepted";
  return "other";
}

function dashboard(hours = 24) {
  const safeHours = [24, 168, 720].includes(Number(hours)) ? Number(hours) : 24;
  const providerSnapshot = stateValue("providers", []);
  const system = stateValue("system", {});
  const trusted = new Set(trustedPolicy.current()?.authorized_ips || []);
  function decorate(row) {
    if (!row.provider) row.provider = row.isp || "Sin identificar";
    row.admin_source = trustedPolicy.has(row.ip);
    row.authorized = row.kind === "ssh_success" && row.admin_source;
    row.severity = row.kind === "ssh_success" ? (row.authorized ? "low" : "critical")
      : row.kind === "ssh_failure" ? "medium" : "info";
    row.country_flag = countryFlag(row.country_code);
    row.flow_status = flowStatus(row);
    row.display_ip = row.authorized || (isFirewallAllowed(row) && row.admin_source) ? "IP autorizada" : row.ip;
    return row;
  }
  const data = dashboardCache.get(JSON.stringify([safeHours,[...trusted].sort()]),
    db.prepare("SELECT total_changes() revision").get().revision,
    () => dashboardData(db, {hours:safeHours, now:Math.floor(Date.now()/1000), trusted, decorate, serviceFor,authorizedSql:'is_authorized_ip(e.ip)'}));
  const providerLogAgg = new Map(data.providers.map(row => [row.key,row]));
  const providers = providerSnapshot.map(row => ({...row,
    logged_events:providerLogAgg.get(row.slug)?.count || 0,
    unique_ips:providerLogAgg.get(row.slug)?.unique_ips || 0,
  })).sort((a,b) => b.packets-a.packets);
  return {
    mode:data.summary.total_events ? "live" : "empty", hours:safeHours, statistics_as_of:data.as_of,
    connection:{...connection,host:config.ssh.host,refresh_seconds:Number(config.refreshSeconds || 20)},
    summary:{...data.summary,drop_packets:providerSnapshot.reduce((sum,row)=>sum+Number(row.packets||0),0),
      providers:providerSnapshot.length,active_services:(system.services||[]).filter(row=>row.state==="active").length},
    countries:data.countries.slice(0,8),countries_all:data.countries,providers:providers.slice(0,60),
    ports:data.ports,ssh_users:data.users,timeline:data.timeline,events:data.events,
    activity_events:data.activity_events,ssh_events:data.ssh_events,system,
  };
}

function sshLiveReport(hours = 24, resultValue = "", queryValue = "", userValue = "") {
  const safeHours = [24, 168, 720].includes(Number(hours)) ? Number(hours) : 24;
  const since = Math.floor(Date.now() / 1000) - safeHours * 3600;
  const result = ["success", "failed", "blocked"].includes(String(resultValue)) ? String(resultValue) : "";
  const query = String(queryValue || "").trim().slice(0, 100);
  const user = String(userValue || "").trim().slice(0, 100);
  const sshCondition = `(e.kind LIKE 'ssh_%' OR (
    e.kind IN ('firewall','firewall_block') AND UPPER(e.protocol)='TCP' AND e.port='22'
  ))`;
  const conditions = ["e.timestamp>=?", "NOT(is_tailscale_ip(e.ip)=1 AND is_authorized_ip(e.ip)=1)", sshCondition];
  const params = [since];

  if (result === "success") conditions.push("e.kind='ssh_success'");
  else if (result === "failed") conditions.push("e.kind IN ('ssh_failure','ssh_invalid_user')");
  else if (result === "blocked") conditions.push("e.kind IN ('firewall','firewall_block') AND UPPER(e.protocol)='TCP' AND e.port='22'");
  if (user) {
    conditions.push("e.ssh_user=?");
    params.push(user);
  }
  if (query) {
    const pattern = `%${query}%`;
    conditions.push(`(
      e.ip LIKE ? OR e.provider LIKE ? OR e.ssh_user LIKE ? OR
      g.country LIKE ? OR g.isp LIKE ? OR g.asn LIKE ?
    )`);
    params.push(pattern, pattern, pattern, pattern, pattern, pattern);
  }

  const baseSummary = db.prepare(`
    SELECT
      SUM(CASE WHEN e.kind='ssh_success' THEN 1 ELSE 0 END) success,
      SUM(CASE WHEN e.kind IN ('ssh_failure','ssh_invalid_user') THEN 1 ELSE 0 END) failed,
      SUM(CASE WHEN e.kind IN ('firewall','firewall_block') AND UPPER(e.protocol)='TCP' AND e.port='22' THEN 1 ELSE 0 END) blocked,
      COUNT(DISTINCT e.ip) unique_ips
    FROM events e
    WHERE e.timestamp>=? AND NOT(is_tailscale_ip(e.ip)=1 AND is_authorized_ip(e.ip)=1) AND ${sshCondition}
  `).get(since);
  const matched = db.prepare(`
    SELECT COUNT(*) total, COUNT(DISTINCT e.ip) unique_ips
    FROM events e LEFT JOIN geo_cache g ON g.ip=e.ip
    WHERE ${conditions.join(" AND ")}
  `).get(...params);
  const rows = db.prepare(`
    SELECT e.*, COALESCE(g.country_code,'') country_code,
      COALESCE(NULLIF(g.country,''),'Desconocido') country,
      COALESCE(g.isp,'') isp, COALESCE(g.asn,'') asn
    FROM events e LEFT JOIN geo_cache g ON g.ip=e.ip
    WHERE ${conditions.join(" AND ")}
    ORDER BY e.timestamp DESC LIMIT 5000
  `).all(...params);
  const users = db.prepare(`
    SELECT e.ssh_user key, e.ssh_user label, COUNT(*) count
    FROM events e
    WHERE e.timestamp>=? AND NOT(is_tailscale_ip(e.ip)=1 AND is_authorized_ip(e.ip)=1)
      AND e.kind IN ('ssh_failure','ssh_invalid_user') AND e.ssh_user<>''
    GROUP BY e.ssh_user ORDER BY count DESC, e.ssh_user ASC LIMIT 500
  `).all(since);
  const trusted = new Set(trustedPolicy.current()?.authorized_ips || []);

  for (const row of rows) {
    const blocked = row.kind === "firewall" || row.kind === "firewall_block";
    row.ssh_result = blocked ? "blocked" : row.kind === "ssh_success" ? "success" : "failed";
    row.result_label = blocked ? "Bloqueado por firewall" : row.kind === "ssh_success" ? "Exitoso" : "Fallido";
    row.authorized = row.kind === "ssh_success" && trustedPolicy.has(row.ip);
    row.display_ip = row.authorized ? "IP autorizada" : row.ip;
    row.provider = row.provider || row.isp || "Sin identificar";
    row.country_flag = countryFlag(row.country_code);
    if (blocked) row.auth_method = "UFW/ipset";
  }

  return {
    hours: safeHours,
    refresh_seconds: Math.max(10, Number(config.refreshSeconds || 20)),
    result,
    query,
    user,
    summary: {
      success: Number(baseSummary?.success || 0),
      failed: Number(baseSummary?.failed || 0),
      blocked: Number(baseSummary?.blocked || 0),
      unique_ips: Number(baseSummary?.unique_ips || 0),
      matched: Number(matched?.total || 0),
      matched_unique_ips: Number(matched?.unique_ips || 0),
    },
    users,
    events: rows,
    truncated: Number(matched?.total || 0) > rows.length,
  };
}

function portReport(protocol, port, hours = 24) {
  const safeHours = [24, 168, 720].includes(Number(hours)) ? Number(hours) : 24;
  const safeProtocol = String(protocol || "").toUpperCase();
  const safePort = String(port || "");
  if (!/^[A-Z0-9]{2,8}$/.test(safeProtocol) || !/^[A-Za-z0-9-]{1,16}$/.test(safePort)) {
    throw new Error("Puerto o protocolo no válido");
  }
  const since = Math.floor(Date.now() / 1000) - safeHours * 3600;
  const total = db.prepare(`
    SELECT COUNT(*) count, COUNT(DISTINCT ip) unique_ips
    FROM events
    WHERE timestamp>=? AND kind IN ('firewall','firewall_block') AND UPPER(protocol)=? AND port=?
  `).get(since, safeProtocol, safePort);
  const rows = db.prepare(`
    SELECT e.*, COALESCE(g.country_code,'') country_code,
      COALESCE(NULLIF(g.country,''),'Desconocido') country,
      COALESCE(g.isp,'') isp, COALESCE(g.asn,'') asn
    FROM events e LEFT JOIN geo_cache g ON g.ip=e.ip
    WHERE e.timestamp>=? AND e.kind IN ('firewall','firewall_block') AND UPPER(e.protocol)=? AND e.port=?
    ORDER BY e.timestamp DESC LIMIT 2000
  `).all(since, safeProtocol, safePort);
  for (const row of rows) {
    if (!row.provider) row.provider = row.isp || "Sin identificar";
    row.country_flag = countryFlag(row.country_code);
  }
  return {
    protocol: safeProtocol,
    port: safePort,
    hours: safeHours,
    service: rows[0]?.service || serviceFor(safeProtocol, safePort),
    total: Number(total?.count || 0),
    unique_ips: Number(total?.unique_ips || 0),
    truncated: Number(total?.count || 0) > rows.length,
    events: rows,
  };
}

function ipReport(address) {
  const rows = db.prepare(`
    SELECT e.*, COALESCE(g.country_code,'') country_code, COALESCE(g.country,'Desconocido') country,
      COALESCE(g.isp,'') isp, COALESCE(g.asn,'') asn
    FROM events e LEFT JOIN geo_cache g ON g.ip=e.ip WHERE e.ip=? ORDER BY e.timestamp DESC LIMIT 1000
  `).all(address);
  const total = Number(db.prepare("SELECT COUNT(*) count FROM events WHERE ip=?").get(address)?.count || 0);
  const sshUsers = db.prepare(`
    SELECT COALESCE(NULLIF(ssh_user,''),'desconocido') user, COUNT(*) attempts,
      MIN(timestamp) first_seen, MAX(timestamp) last_seen
    FROM events
    WHERE ip=? AND kind IN ('ssh_failure','ssh_invalid_user')
    GROUP BY COALESCE(NULLIF(ssh_user,''),'desconocido')
    ORDER BY attempts DESC, last_seen DESC
  `).all(address);
  const sshEvents = db.prepare(`
    SELECT timestamp, kind, COALESCE(NULLIF(ssh_user,''),'desconocido') ssh_user,
      auth_method, decision, details
    FROM events
    WHERE ip=? AND kind LIKE 'ssh_%'
    ORDER BY timestamp DESC LIMIT 1000
  `).all(address);
  const sshTotal = Number(db.prepare("SELECT COUNT(*) count FROM events WHERE ip=? AND kind LIKE 'ssh_%'").get(address)?.count || 0);
  return {
    ip: address,
    count: total,
    events: rows,
    geo: rows[0] ? {country_code:rows[0].country_code,country:rows[0].country,isp:rows[0].isp,asn:rows[0].asn} : null,
    ssh: {
      total: sshTotal,
      users: sshUsers,
      events: sshEvents,
      truncated: sshTotal > sshEvents.length,
    },
  };
}

function parseRemoteJson(raw, fallbackMessage) {
  try {
    const payload = JSON.parse(String(raw || "").trim());
    if (!payload.ok) throw new Error(payload.error || fallbackMessage);
    return payload;
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error(fallbackMessage);
    throw error;
  }
}

const commandGuard=createCommandGuard({authorize:requireActionToken,revalidate:req=>!serverSwitch.paused()&&panelAuth.canAct(req),sendJson});
function securityCtl(command,payload=null){serverSwitch.assert();return commandGuard.run(command,payload,executeSecurityCtl);}
function checkGameAccess(request,action){
  try{requireGamePermission(request.panelUser,action);}
  catch(error){if(error.status===403)notifications.accessDenied(request.panelUser,gameTarget(action),'api');throw error;}
}
function checkServiceAccess(request,action){
  try{requireServicePermission(request.panelUser,action);}
  catch(error){if(error.status===403)notifications.accessDenied(request.panelUser,serviceTarget(action),'api');throw error;}
}
let panelAlertDeliveryBusy=false;
async function deliverPanelAlerts(){
  if(serverSwitch.paused()||!panelAuth.ready()||process.env.SSM_MIGRATION_CHECK==='1')return;
  if(panelAlertDeliveryBusy||!connection.connected||commandGuard.state().busy||commandGuard.state().cooldown_ms>0)return;
  const events=notifications.pendingTelegram();if(!events.length)return;
  panelAlertDeliveryBusy=true;
  try{
    const result=await securityCtl('alerts-panel-events',{events});
    notifications.finishTelegram(events,result?.ok===true&&result?.retry!==true);
  }catch{notifications.finishTelegram(events,false);}
  finally{panelAlertDeliveryBusy=false;}
}
const panelAlertDeliveryTimer=setInterval(()=>void deliverPanelAlerts().catch(()=>{}),10000);
panelAlertDeliveryTimer.unref();

const zoneControllerFlow=createZoneControllerFlow({root:ROOT,runRemote});
const webappControllerFlow=createWebappControllerFlow({root:ROOT,runRemote});
async function executeSecurityCtl(command, payload = null) {
  await webappControllerFlow.ensure(command,payload);
  if(['zone-status','zone-plan','zone-apply','zone-repair','zone-forum-credentials'].includes(command))return zoneControllerFlow.execute(command,payload||{});
  if (!new Set(["status", "list", "block", "unblock", "provider-block", "provider-unblock", "sync", "report-ssh", "report-download", "ports-status", "ports-plan", "ports-apply", "forwarding-status", "forwarding-plan", "forwarding-apply", "services-status", "services-plan", "services-apply", "mysql-status", "mysql-plan", "mysql-apply", "mysql-data", "mysql-structure", "cleanup-status", "cleanup-plan", "cleanup-apply", "system-metrics", "system-plan", "system-reboot", "trusted-status", "trusted-plan", "trusted-apply", "alerts-status", "alerts-configure", "alerts-panel-events", "services-versions", "catalog-status", "catalog-versions", "catalog-plan", "catalog-apply", "games-status", "games-console", "games-plan", "games-apply", "cloudflare-status", "cloudflare-plan", "cloudflare-apply"]).has(command)) {
    throw new Error("Operación remota no permitida");
  }
  if(['games-plan','games-apply'].includes(command))await zoneControllerFlow.execute('zone-runtime-check',{});
  const usesInput = ["block", "unblock", "provider-block", "provider-unblock", "report-ssh", "report-download", "ports-status", "ports-plan", "ports-apply", "forwarding-status", "forwarding-plan", "forwarding-apply", "services-status", "services-plan", "services-apply", "mysql-status", "mysql-plan", "mysql-apply", "mysql-data", "mysql-structure", "cleanup-status", "cleanup-plan", "cleanup-apply", "system-metrics", "system-plan", "system-reboot", "trusted-status", "trusted-plan", "trusted-apply", "alerts-status", "alerts-configure", "alerts-panel-events", "services-versions", "catalog-status", "catalog-versions", "catalog-plan", "catalog-apply", "games-status", "games-console", "games-plan", "games-apply", "cloudflare-status", "cloudflare-plan", "cloudflare-apply"].includes(command);
  const remote = `sudo -n ${SECURITY_CTL} ${command}${usesInput ? " --json-input" : ""}`;
  try {
    const timeout = command.startsWith("cloudflare-") ? 300000 : command === "games-apply" ? 18*60*1000 : command === "games-plan" ? 90000 : command.startsWith("catalog-") ? (command === "catalog-status" ? 90000 : 30*60*1000) : ["mysql-apply","services-apply"].includes(command)&&payload?.action==="upgrade" ? 45*60*1000 : command === "services-versions" ? 10*60*1000 : command === "alerts-configure" ? 60000 : command === "trusted-apply" ? 90000 : command === "cleanup-apply" ? 300000 : command === "mysql-apply" ? 18*60*1000 : command === "services-apply" ? 18*60*1000 : command === "report-ssh" ? 31 * 60 * 1000 : (command.startsWith("provider-") || ["ports-apply","forwarding-apply"].includes(command)) ? 120000 : 35000;
    const raw = await runRemote(remote, usesInput ? JSON.stringify(payload || {}) : "", timeout);
    return parseRemoteJson(raw, "El controlador del servidor devolvió una respuesta no válida");
  } catch (error) {
    const message = String(error.message || error).trim();
    try {
      const parsed = JSON.parse(message);
      throw new Error(parsed.error || message);
    } catch (parsedError) {
      if (!(parsedError instanceof SyntaxError)) throw parsedError;
      throw new Error(message);
    }
  }
}

function reportPublicState() {
  return {
    ...sshReportJob,
    files: Array.isArray(sshReportJob.files) ? sshReportJob.files : [],
  };
}

async function runLocalReportDownloader() {
  const file=await downloadReport({securityCtl,directory:REPORT_LOCAL_OUTPUT,openFile:!protectedRuntime});
  if(protectedRuntime)await protectedCall('open-report',{path:file});
  return file;
}

function startSshReportDownload() {
  const generation=historyStore.generation();
  if (["generating", "downloading"].includes(sshReportJob.status)) {
    throw new Error("Ya hay un reporte SSH en proceso");
  }
  sshReportJob = {
    ...sshReportJob,
    status: "downloading",
    started_at: sshReportJob.started_at || Math.floor(Date.now() / 1000),
    finished_at: 0,
    message: "Descargando y abriendo el TXT más reciente disponible…",
    error: "",
  };
  void commandGuard.track(async () => {
    try {
      await runLocalReportDownloader();
      if(generation!==historyStore.generation()){historyStore.pruneFiles();throw new Error("Se limpiaron los registros durante la descarga del reporte.");}
      sshReportJob = {
        ...sshReportJob,
        status: "complete",
        finished_at: Math.floor(Date.now() / 1000),
        message: "El TXT más reciente fue descargado y abierto correctamente.",
      };
    } catch (error) {
      sshReportJob = {
        ...sshReportJob,
        status: "error",
        finished_at: Math.floor(Date.now() / 1000),
        message: "No se pudo descargar el reporte SSH.",
        error: String(error.message || error).slice(0, 1200),
      };
    }
  }).catch(error=>{sshReportJob={...sshReportJob,status:"error",error:error.message,message:"No se pudo completar el reporte SSH."};});
  return reportPublicState();
}

function startSshReport(days) {
  if(cleanupApi.busy())throw new Error("Hay una limpieza en curso. Esperá su resultado.");
  const generation=historyStore.generation();
  if (!Number.isInteger(days) || days < 1 || days > REPORT_MAX_DAYS) {
    throw new Error(`El período debe ser un número entero entre 1 y ${REPORT_MAX_DAYS} días`);
  }
  if (["generating", "downloading"].includes(sshReportJob.status)) {
    throw new Error("Ya hay un reporte SSH en proceso");
  }
  sshReportJob = {
    status: "generating",
    days,
    started_at: Math.floor(Date.now() / 1000),
    finished_at: 0,
    files: [],
    message: `Analizando los últimos ${days} ${days === 1 ? "día" : "días"} en el servidor…`,
    error: "",
  };

  void commandGuard.track(async () => {
    try {
      const remote = await securityCtl("report-ssh", { minutes: days * 24 * 60 });
      if(generation!==historyStore.generation())throw new Error("Se limpiaron los registros durante la generación del reporte.");
      sshReportJob = { ...sshReportJob, files: remote.files || [] };
      if (remote.no_findings) {
        sshReportJob = {
          ...sshReportJob,
          status: "complete",
          finished_at: Math.floor(Date.now() / 1000),
          message: `No se encontraron fallos SSH en los últimos ${days} ${days === 1 ? "día" : "días"}.`,
        };
        return;
      }
      if (!Array.isArray(remote.files) || remote.files.length === 0) {
        throw new Error(remote.warning || "El servidor no generó un archivo nuevo");
      }
      sshReportJob = {
        ...sshReportJob,
        status: "downloading",
        message: "Reporte generado. Descargando y abriendo el TXT más reciente…",
      };
      await runLocalReportDownloader();
      if(generation!==historyStore.generation()){historyStore.pruneFiles();throw new Error("Se limpiaron los registros durante la descarga del reporte.");}
      sshReportJob = {
        ...sshReportJob,
        status: "complete",
        finished_at: Math.floor(Date.now() / 1000),
        message: "Reporte generado, descargado y abierto correctamente.",
      };
    } catch (error) {
      sshReportJob = {
        ...sshReportJob,
        status: "error",
        finished_at: Math.floor(Date.now() / 1000),
        message: "No se pudo completar el reporte SSH.",
        error: String(error.message || error).slice(0, 1200),
      };
    }
  }).catch(error=>{sshReportJob={...sshReportJob,status:"error",error:error.message,message:"No se pudo completar el reporte SSH."};});
  return reportPublicState();
}

function blockAudit(action, target, reason, ok, details = "") {
  insertBlockAudit.run(
    Math.floor(Date.now() / 1000), action, target, reason || "", ok ? 1 : 0,
    String(details || "").slice(0, 1200),
  );
}

async function blockOverview() {
  let controller;
  try {
    controller = await securityCtl("status");
  } catch (error) {
    controller = {
      ok: false,
      installed: false,
      count: 0,
      ipv4: 0,
      ipv6: 0,
      entries: [],
      rules: { ipv4:false, ipv6:false },
      error: String(error.message || error),
    };
  }
  return {
    ok: true,
    action_token: ACTION_TOKEN,
    controller,
    providers: stateValue("providers", []),
    audit: db.prepare(`
      SELECT timestamp,action,target,reason,ok,details
      FROM block_audit ORDER BY timestamp DESC LIMIT 50
    `).all(),
  };
}

function requireActionToken(request) {
  if(serverSwitch.paused()||!panelAuth.canAct(request))return false;
  const token = String(request.headers["x-storypulse-token"] || "");
  if (!token || token.length !== ACTION_TOKEN.length) return false;
  const actual = Buffer.from(token);
  const expected = Buffer.from(ACTION_TOKEN);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function cleanReason(value) {
  const text = String(value || "").replace(/[\x00-\x1f\x7f]/g, " ").replace(/\s+/g, " ").trim();
  if (text.length > 160) throw new Error("El motivo no puede superar 160 caracteres");
  return text || "Bloqueo manual desde el panel local";
}

function providerPrefixDigest(asn, prefixes) {
  const normalizedAsn = normalizeAsn(asn);
  const canonical = [...new Set((prefixes || []).map(value => String(value).trim()).filter(validCidr))].sort();
  return createHash("sha256").update(JSON.stringify({ asn:normalizedAsn, prefixes:canonical })).digest("hex");
}

function providerApprovals() {
  if (!existsSync(PROVIDER_APPROVALS_PATH)) return [];
  try {
    const rows = JSON.parse(readFileSync(PROVIDER_APPROVALS_PATH, "utf8"));
    if (!Array.isArray(rows)) return [];
    return rows.map(row => ({
      asn: normalizeAsn(row?.asn),
      name: String(row?.name || "").trim(),
      prefix_digest: String(row?.prefix_digest || "").trim().toLowerCase(),
      approved_at: String(row?.approved_at || "").trim(),
      note: String(row?.note || "").trim(),
    })).filter(row => row.asn && /^[0-9a-f]{64}$/.test(row.prefix_digest));
  } catch {
    return [];
  }
}

function normalizeAsn(value) {
  const match = String(value || "").trim().toUpperCase().match(/^(?:AS)?(\d{1,10})$/);
  if (!match) return "";
  const number = Number(match[1]);
  return Number.isSafeInteger(number) && number > 0 && number <= 4294967295 ? `AS${number}` : "";
}

function validCidr(value) {
  const parts = String(value || "").split("/");
  if (parts.length !== 2) return false;
  const family = isIP(parts[0]);
  const prefix = Number(parts[1]);
  return family > 0 && Number.isInteger(prefix) && prefix >= 0 && prefix <= (family === 4 ? 32 : 128);
}

async function ripeStat(endpoint, resource) {
  commandGuard.touch();
  const url = new URL(`https://stat.ripe.net/data/${endpoint}/data.json`);
  url.searchParams.set("resource", resource);
  const response = await fetch(url, {
    signal: AbortSignal.timeout(15000),
    headers: { "User-Agent":"StoryPulse-Security-Dashboard/5.0" },
  });
  if (!response.ok) throw new Error(`RIPEstat respondió HTTP ${response.status}`);
  const payload = await readResponseJson(response,16*1024*1024);
  if (payload.status !== "ok" || !payload.data) throw new Error("RIPEstat no devolvió datos utilizables");
  return payload.data;
}

function officialFeedFor(holder) {
  const value = String(holder || "").toLowerCase();
  if (/cloudflare/.test(value)) return {name:"Cloudflare IP ranges",url:"https://www.cloudflare.com/ips/"};
  if (/amazon|amazon\.com|aws/.test(value)) return {name:"AWS ip-ranges.json",url:"https://ip-ranges.amazonaws.com/ip-ranges.json"};
  if (/google/.test(value)) return {name:"Google Cloud IP ranges",url:"https://www.gstatic.com/ipranges/cloud.json"};
  if (/oracle/.test(value)) return {name:"Oracle Cloud public IP ranges",url:"https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"};
  return null;
}

async function evaluateProvider(value, expectedName = "") {
  const query = String(value || "").trim();
  const addressFamily = isIP(query);
  let asn = addressFamily ? "" : normalizeAsn(query);
  let observedPrefix = "";
  let geo = null;
  let observedProvider = "";
  let observedSlug = "";

  if (!addressFamily && !asn) throw new Error("Ingresa una IP pública o un ASN, por ejemplo AS14061");
  if (addressFamily) {
    await ensureGeo(query);
    geo = db.prepare("SELECT country_code,country,isp,asn FROM geo_cache WHERE ip=?").get(query) || null;
    const latest = db.prepare(`
      SELECT provider,provider_slug FROM events WHERE ip=?
      ORDER BY timestamp DESC LIMIT 1
    `).get(query);
    observedProvider = latest?.provider || geo?.isp || "";
    observedSlug = latest?.provider_slug || "";
    const network = await ripeStat("network-info", query);
    observedPrefix = String(network.prefix || "");
    const firstAsn = Array.isArray(network.asns) ? network.asns[0] : network.asns;
    asn = normalizeAsn(firstAsn);
    if (!asn) throw new Error("No se encontró un ASN anunciante para esa IP");
  }

  const [overview, announcements] = await Promise.all([
    ripeStat("as-overview", asn),
    ripeStat("announced-prefixes", asn),
  ]);
  const holder = String(overview.holder || expectedName || observedProvider || asn).trim();
  const prefixes = (announcements.prefixes || [])
    .map(item => String(item.prefix || item).trim())
    .filter(validCidr);
  const ipv4 = prefixes.filter(prefix => isIP(prefix.split("/")[0]) === 4);
  const ipv6 = prefixes.filter(prefix => isIP(prefix.split("/")[0]) === 6);
  const digest = providerPrefixDigest(asn, prefixes);
  const approval = providerApprovals().find(row => row.asn === asn && row.prefix_digest === digest) || null;
  if (!observedSlug) {
    const known = db.prepare(`
      SELECT e.provider,e.provider_slug
      FROM events e JOIN geo_cache g ON g.ip=e.ip
      WHERE UPPER(g.asn)=? AND e.provider_slug<>''
      ORDER BY e.timestamp DESC LIMIT 1
    `).get(asn);
    observedProvider = observedProvider || known?.provider || "";
    observedSlug = known?.provider_slug || "";
  }
  const snapshots = stateValue("providers", []);
  const normalizedHolder = holder.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
  const already = snapshots.find(row =>
    (observedSlug && row.slug === observedSlug) ||
    (normalizedHolder.length >= 5 && (
      String(row.name || "").toLowerCase().includes(normalizedHolder) ||
      normalizedHolder.includes(String(row.name || "").toLowerCase())
    ))
  );
  const officialFeed = officialFeedFor(`${holder} ${observedProvider} ${expectedName}`);
  const residentialTerms = /\b(telecom|broadband|mobile|wireless|residential|cable|university|school|municipal|government|fiber)\b/i;
  const hostingTerms = /\b(cloud|hosting|host|server|datacenter|data center|colo|vps|compute)\b/i;
  const identity = `${holder} ${observedProvider} ${expectedName}`;
  let assessment = "manual-review";
  let label = "Revisión manual obligatoria";
  const reasons = [];

  if (already) {
    assessment = "already-blocked";
    label = "Ya está bloqueado";
    reasons.push(`Coincide con la regla existente ${already.name}.`);
  } else if (overview.announced === false || !prefixes.length) {
    assessment = "insufficient";
    label = "Datos insuficientes";
    reasons.push("El ASN no anuncia prefijos utilizables en la vista actual de BGP.");
  } else if (/\bovh\b/i.test(identity) || asn === "AS16276") {
    assessment = "not-recommended";
    label = "Proveedor protegido";
    reasons.push("OVH aloja este servidor y está excluido de los bloqueos masivos.");
  } else if (residentialTerms.test(identity)) {
    assessment = "not-recommended";
    label = "No recomendado";
    reasons.push("La identidad contiene señales de red residencial, móvil, educativa o de telecomunicaciones mixta.");
  } else if (hostingTerms.test(identity)) {
    reasons.push("La identidad observada es compatible con hosting, nube o centro de datos.");
  } else {
    reasons.push("La identidad no permite confirmar por sí sola que todo el ASN sea exclusivamente alojamiento de servidores.");
  }
  if (officialFeed) reasons.push("Existe una fuente oficial de rangos que debe compararse antes de aprobar un bloqueo masivo.");
  else if (!already) reasons.push("RIPEstat confirma anuncios BGP, pero eso no demuestra que todos pertenezcan sólo a clientes de servidores.");

  return {
    ok: true,
    query,
    sample_ip: addressFamily ? query : "",
    observed_prefix: observedPrefix,
    observed_provider: observedProvider,
    geo,
    asn,
    holder,
    announced: overview.announced !== false,
    prefixes: { total:prefixes.length, ipv4:ipv4.length, ipv6:ipv6.length, preview:prefixes.slice(0, 24) },
    all_prefixes: prefixes,
    assessment,
    assessment_label: label,
    reasons,
    already_blocked: already ? {slug:already.slug,name:already.name} : null,
    official_feed: officialFeed,
    prefix_digest: digest,
    review_code: digest.slice(0, 12).toUpperCase(),
    approved_for_blocking: Boolean(approval),
    approval: approval ? {name:approval.name,approved_at:approval.approved_at,note:approval.note} : null,
    can_apply: Boolean(approval) && !already && assessment !== "insufficient" && assessment !== "not-recommended",
    sources: [
      {name:"RIPEstat · AS Overview",url:`https://stat.ripe.net/${asn}`},
      {name:"RIPEstat · Announced Prefixes",url:`https://stat.ripe.net/data/announced-prefixes/data.json?resource=${asn}`},
      ...(officialFeed ? [officialFeed] : []),
    ],
  };
}

function sendJson(response, status, payload) {
  const denied=commandGuard.failure();
  if(status>=400&&denied){status=429;payload={...payload,error:denied.message,retry_after:denied.retry_after};response.setHeader('Retry-After',String(denied.retry_after));}

  const body = JSON.stringify(payload);
  response.writeHead(status, { "Content-Type":"application/json; charset=utf-8", "Cache-Control":"no-store", "Content-Length":Buffer.byteLength(body) });
  response.end(body);
}

function publicProviderEvaluation(evaluation, controller = null) {
  const current = (controller?.provider_blocks || []).find(row => normalizeAsn(row.asn) === evaluation.asn) || null;
  const result = { ...evaluation };
  delete result.all_prefixes;
  if (current) {
    result.assessment = "already-blocked";
    result.assessment_label = "Ya está bloqueado desde el panel";
    result.can_apply = false;
    result.panel_block = {
      asn: current.asn,
      name: current.name,
      prefixes: Array.isArray(current.prefixes) ? current.prefixes.length : 0,
      created_at: current.created_at,
    };
    result.reasons = [`El bloqueo aprobado ${current.asn} ya está activo.`, ...(result.reasons || [])];
  }
  return result;
}

function staticFile(request, response) {
  const url = new URL(request.url, "http://localhost");
  const relative = url.pathname === "/" ? "index.html" : url.pathname === "/login" ? "login.html" : decodeURIComponent(url.pathname.slice(1));
  if (!["zone.js","cloudflare.js","cloudflare.css","network-traffic.js","network-traffic.css","avatars.js","avatars.css","avatars.svg","games.js","games.css","game-logo-samp.png","service-logo-phpmyadmin.svg","service-logo-wordpress.svg","service-logo-nginx.svg","service-logo-apache.svg","service-logo-php.svg","service-logo-certbot.svg","service-logo-docker.svg","service-logo-postgresql.svg","service-logo-redis.svg","service-logo-fail2ban.svg","service-logo-wireguard.svg","service-logo-postfix.svg","service-logo-mysql.svg","service-logo-ftp.svg","catalog-services.js","catalog-services.css","service-versions.js","panel-users.js","terminal.js","terminal.css","login.html","auth.js","auth.css","index.html","alerts.js","alert-sounds.js","app.js","mysql.js","cleanup.js","personalization.js","command-guard.js","personalization.css","notifications.js","notifications.css","authorized-ips.js","server-info.js","server-info.css","server-eye.svg","styles.css","enhancements.css"].includes(relative)) { response.writeHead(403); response.end(); return; }
  const path = join(STATIC_ROOT, relative);
  if (!existsSync(path) || !statSync(path).isFile()) { response.writeHead(404); response.end("No encontrado"); return; }
  const types = { ".html":"text/html; charset=utf-8", ".css":"text/css; charset=utf-8", ".js":"text/javascript; charset=utf-8", ".svg":"image/svg+xml", ".png":"image/png" };
  response.writeHead(200, { "Content-Type":types[extname(path)] || "application/octet-stream", "Cache-Control":"no-store" });
  response.end(request.method === "HEAD" ? undefined : readFileSync(path));
}

let portsRequest = null;
let portsCache = null;
let portsBusy = false;
let forwardingRequest = null;
let forwardingCache = null;
let forwardingBusy = false;
let servicesCache=null,servicesRequest=null,servicesPlanning=false;
let servicesJob={status:"idle"};
function servicePayload(body,{apply=false}={}) {
  const allowed=["install","upgrade","uninstall","create-user","update-user","enable-user","disable-user","delete-user","start","stop","restart"];
  if(!allowed.includes(body.action))throw new Error("Acción de servicio no válida.");
  const fields=["action","confirm","revision","selection","erase_data","open_firewall","username","root","permissions","password"];
  if(Object.keys(body).some(k=>!fields.includes(k)))throw new Error("Parámetros de servicio no permitidos.");
  const result={action:body.action};
  if(body.action==="uninstall") {
    const allowed=new Set(["action","erase_data",...(apply?["confirm","revision"]:[])]);
    if(body.erase_data!==true||Object.keys(body).some(k=>!allowed.has(k)))throw new Error("Confirmá el borrado permanente de los datos del servicio.");
    result.erase_data=true;
  }
  if(["install","upgrade"].includes(body.action)){
    const allowed=new Set(["action","selection",...(body.action==="install"?["open_firewall"]:[]),...(apply?["confirm","revision"]:[])]);
    if(typeof body.selection!=="string"||!/^[a-f0-9]{64}$/.test(body.selection)||Object.keys(body).some(k=>!allowed.has(k)))throw new Error("Elegí una versión del catálogo actualizado.");
    result.selection=body.selection;
  }
  if(body.action==="install") {
    if(typeof body.open_firewall!=="boolean")throw new Error("Indicá si querés habilitar los puertos FTP.");
    result.open_firewall=body.open_firewall;
  }
  if(body.action.endsWith("-user")) {
    if(typeof body.username!=="string"||!/^[a-z][a-z0-9_-]{2,31}$/.test(body.username))throw new Error("Nombre de usuario FTP no válido.");
    result.username=body.username;
    if(body.action==="create-user") {
      if(typeof body.root!=="string"||!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(body.root))throw new Error("Nombre de carpeta no válido.");
      result.root=body.root;
    }
    if(["create-user","update-user"].includes(body.action)) {
      const keys=["list","download","upload","mkdir","rename","delete"];
      if(!body.permissions||Array.isArray(body.permissions)||Object.keys(body.permissions).length!==keys.length||keys.some(k=>typeof body.permissions[k]!=="boolean"))throw new Error("Permisos FTP no válidos.");
      result.permissions=Object.fromEntries(keys.map(k=>[k,body.permissions[k]]));
      if(apply) {
        if(body.action==="create-user"||body.password) {
          if(typeof body.password!=="string"||body.password.length<12||body.password.length>128||/[\x00-\x1f\x7f]/.test(body.password))throw new Error("La contraseña debe tener entre 12 y 128 caracteres, sin caracteres de control.");
          result.password=body.password;
        }
      }
    }
  }
  return result;
}
async function liveServices() {
  if(servicesJob.status==="running"||mysqlApi.busy()||cleanupApi.busy())return servicesCache?.data||{ok:true,installed:false,users:[]};
  if(servicesCache&&Date.now()-servicesCache.time<3000)return servicesCache.data;
  if(!servicesRequest)servicesRequest=securityCtl("services-status",{}).then(data=>{servicesCache={time:Date.now(),data};return data;}).finally(()=>{servicesRequest=null;});
  return servicesRequest;
}
function startServiceChange(payload) {
  if(servicesJob.status==="running"||servicesPlanning||portsBusy||forwardingBusy||mysqlApi.busy()||cleanupApi.busy())throw new Error("Hay un cambio en curso. Esperá su resultado.");
  servicesJob={id:randomBytes(8).toString("hex"),status:"running",action:payload.action,started_at:Math.floor(Date.now()/1000),message:payload.action==="uninstall"?"Eliminando FTP y sus datos. Puede demorar varios minutos…":payload.action==="upgrade"?"Respaldando y actualizando FTP. Puede demorar varios minutos…":payload.action==="install"?"Instalando FTP seguro. Puede demorar varios minutos…":"Aplicando el cambio de FTP…"};
  securityCtl("services-apply",payload).then(result=>{
    servicesJob={...servicesJob,status:"success",finished_at:Math.floor(Date.now()/1000),message:"Cambio FTP aplicado correctamente."};
    servicesCache=null;portsCache=null;forwardingCache=null;
    blockAudit(`ftp-${result.action}`,result.username||"ftp","Cambio confirmado de FTP",true,"");
  }).catch(error=>{
    servicesJob={...servicesJob,status:"error",finished_at:Math.floor(Date.now()/1000),message:"No se completó el cambio FTP. "+String(error.message||error)};
    servicesCache=null;
    blockAudit(`ftp-${payload.action}`,payload.username||"ftp","Cambio FTP",false,"Operación de servicio no completada");
  });
  return servicesJob;
}
function forwardingHost(value){
  if(typeof value!=='string'||!value||value.length>253||value!==value.trim()||/[\s\\/:@?#%]/.test(value))throw new Error('Ingresá sólo una IPv4 pública o un dominio, sin URL, rutas ni comandos.');
  if(isIP(value)){if(isIP(value)!==4||!isGeoCandidate(value))throw new Error('El destino debe ser una IPv4 pública.');return value;}
  if(/^[\d.]+$/.test(value))throw new Error('Dirección IPv4 no válida.');
  const ascii=domainToASCII(value.replace(/\.$/,'')).toLowerCase();
  if(!ascii||ascii.length>253||!ascii.includes('.')||!ascii.split('.').every(label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)))
    throw new Error('Dominio no válido: no se permiten comandos, rutas ni puertos.');
  return ascii;
}
function forwardingPayload(body) {
  if(Object.keys(body).some(k=>!["action","id","port","protocol","target_port","host","target_ip","confirm","revision"].includes(k)))throw new Error("Parámetros de redirección no permitidos.");
  if(body.target_ip!==undefined&&(typeof body.target_ip!=="string"||isIP(body.target_ip)!==4||!isGeoCandidate(body.target_ip)))throw new Error("Dirección de destino no válida.");
  const action=body.action;
  if (!["create","update","enable","disable","delete"].includes(action)) throw new Error("Acción de redirección no válida.");
  const payload={action};
  if(action!=="create") {
    if(!/^[a-f0-9]{16}$/.test(body.id||""))throw new Error("Identificador de redirección no válido.");
    payload.id=body.id;
  }
  if(["create","update"].includes(action)) {
    if(!Number.isInteger(body.port)||body.port<1||body.port>65535||!Number.isInteger(body.target_port)||body.target_port<1||body.target_port>65535||
       !["tcp","udp"].includes(body.protocol)||typeof body.host!=="string"||!body.host||body.host.length>253)
      throw new Error("Revisá los puertos, el protocolo y el destino.");
    Object.assign(payload,{port:body.port,protocol:body.protocol,target_port:body.target_port,host:forwardingHost(body.host)});
  }
  return payload;
}
async function liveForwarding(port) {
  const key=port||0;
  if(forwardingCache?.key===key&&Date.now()-forwardingCache.time<3000)return forwardingCache.data;
  if(forwardingRequest){await forwardingRequest;return liveForwarding(port);}
  forwardingRequest=securityCtl("forwarding-status",port?{port}:{}).then(data=>{forwardingCache={key,time:Date.now(),data};return data;});
  try{return await forwardingRequest;}finally{forwardingRequest=null;}
}
function portPayload(body) {
  if(Object.keys(body).some(k=>!["port","protocol","action","confirm","revision"].includes(k)))throw new Error("Parámetros de puerto no permitidos.");
  if (!Number.isInteger(body.port) || body.port < 1 || body.port > 65535 ||
      !["tcp", "udp"].includes(body.protocol) || !["open", "close"].includes(body.action))
    throw new Error("Seleccioná un puerto entre 1 y 65535, TCP o UDP y una acción válida.");
  return {port:body.port, protocol:body.protocol, action:body.action};
}
async function livePorts(port) {
  // Coalesce polling without holding a stale inventory after a firewall change.
  const key = port || 0;
  if (portsCache?.key === key && Date.now() - portsCache.time < 3000) return portsCache.data;
  if (portsRequest) { await portsRequest; return livePorts(port); }
  portsRequest = securityCtl("ports-status", port ? {port} : {}).then(data => {
    portsCache = {key, time:Date.now(), data}; return data;
  });
  try { return await portsRequest; } finally { portsRequest = null; }
}
const alertsApi=createAlertsApi({securityCtl,requireActionToken,readJsonBody,sendJson,actionToken:ACTION_TOKEN});
const systemApi=createSystemApi({securityCtl,requireActionToken,readJsonBody,sendJson,actionToken:ACTION_TOKEN,
  otherBusy:()=>portsBusy||forwardingBusy||servicesPlanning||servicesJob.status==='running'||cleanupApi.busy()||mysqlApi.busy()||['generating','downloading'].includes(sshReportJob.status)});
const historyStore=createHistoryStore({db,dataDir:DATA_ROOT,reportDir:REPORT_LOCAL_OUTPUT,stateValue,saveState,
  onReset:()=>{dashboardCache.entries.clear();clearTimeout(catchupTimer);
    sshReportJob={status:'idle',files:[],message:'Historial de reportes reiniciado.'};}});
const countryDatabase=createCountryDatabase(DATA_ROOT);
const asnDatabase=createAsnDatabase(DATA_ROOT);
const secondaryAsnDatabase=createAsnDatabase(DATA_ROOT,{source:'iptoasn'});
const networkOperators={lookup:ip=>asnDatabase.lookup(ip)||secondaryAsnDatabase.lookup(ip)};
const geoCache=createGeoCache({db,countries:countryDatabase,operators:networkOperators,generation:()=>historyStore.generation()});
const preferencesDb = new DatabaseSync(scope.preferences);
preferencesDb.exec('CREATE TABLE IF NOT EXISTS panel_profiles(user_id TEXT PRIMARY KEY,avatar TEXT NOT NULL)');
if(db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='panel_profiles'").get()){
  const save=preferencesDb.prepare('INSERT OR IGNORE INTO panel_profiles VALUES(?,?)');
  for(const row of db.prepare('SELECT user_id,avatar FROM panel_profiles').all())save.run(row.user_id,row.avatar);
}
const profileApi=createProfileApi({db:preferencesDb,readJsonBody,sendJson,canAct:req=>panelAuth.canAct(req)});
const cleanupApi=createCleanupApi({securityCtl,requireActionToken,readJsonBody,sendJson,actionToken:ACTION_TOKEN,historyStore,
  otherBusy:()=>portsBusy||forwardingBusy||servicesPlanning||servicesJob.status==='running'||mysqlApi.busy()||['generating','downloading'].includes(sshReportJob.status)});
const mysqlApi=createMysqlApi({panelSession:req=>panelAuth.session(req),sessionActive:session=>panelAuth.sessionActive(session),securityCtl,requireActionToken,readJsonBody,sendJson,actionToken:ACTION_TOKEN,
  authorizeService:checkServiceAccess,
  networkBusy:()=>cleanupApi.busy()||portsBusy||forwardingBusy||servicesPlanning||servicesJob.status==='running',
  invalidate:()=>{portsCache=null;forwardingCache=null;},audit:blockAudit});
const trustedApi=createTrustedApi({securityCtl,requireActionToken,readJsonBody,sendJson,actionToken:ACTION_TOKEN,
  onPolicy:acceptTrustedPolicy,otherBusy:()=>connection.collecting||portsBusy||forwardingBusy||servicesPlanning||servicesJob.status==='running'||mysqlApi.busy()||cleanupApi.busy()});
const terminalRunner=createTerminalRunner({root:ROOT,ssh:config.ssh,ensureConnection:ensureSshMaster,
  redact:value=>sshAuthentication.redact(value)});
const terminalApi=createTerminalApi({auth:panelAuth,hello:windowsHello,sendJson,
  execute:(command,verify)=>commandGuard.run('terminal-execute',null,()=>terminalRunner(command,()=>{commandGuard.assertCurrent();verify();}))});
const cloudflareApi=createCloudflareApi({securityCtl,requireActionToken,readJsonBody,sendJson,authorizeService:checkServiceAccess,otherBusy:()=>catalogServicesApi.busy()||gamesApi.busy()||servicesPlanning||servicesJob.status==='running'||mysqlApi.busy()||cleanupApi.busy()||systemApi.busy()||serviceVersionsApi.busy(),invalidate:()=>{portsCache=null;forwardingCache=null;},audit:blockAudit});
const catalogServicesApi=createCatalogServicesApi({securityCtl,requireActionToken,readJsonBody,sendJson,actionToken:ACTION_TOKEN,authorizeService:checkServiceAccess,otherBusy:()=>servicesPlanning||servicesJob.status==='running'||mysqlApi.busy()||cleanupApi.busy()||systemApi.busy()||serviceVersionsApi.busy(),invalidate:()=>{portsCache=null;forwardingCache=null;},audit:blockAudit});
const serviceVersionsApi=createServiceVersionsApi({securityCtl,requireActionToken,readJsonBody,sendJson,actionToken:ACTION_TOKEN,otherBusy:()=>servicesPlanning||servicesJob.status==="running"||mysqlApi.busy()||cleanupApi.busy()||systemApi.busy()});
const gamesApi=createGamesApi({securityCtl,requireActionToken,readJsonBody,sendJson,actionToken:ACTION_TOKEN,authorizeGame:checkGameAccess,auth:panelAuth,hello:windowsHello,ftpVault:createGameFtpVault(config.ssh,{serverId:scope.legacy?'':scope.id}),otherBusy:()=>catalogServicesApi.busy()||servicesPlanning||servicesJob.status==='running'||mysqlApi.busy()||cleanupApi.busy()||systemApi.busy()||serviceVersionsApi.busy(),invalidate:()=>{portsCache=null;forwardingCache=null;},audit:blockAudit});
const zoneApi=createZoneApi({auth:panelAuth,hello:windowsHello,runAction:work=>commandGuard.track(work),securityCtl,requireActionToken,readJsonBody,sendJson,actionToken:ACTION_TOKEN,authorizeGame:checkGameAccess,ftpVault:createGameFtpVault(config.ssh,{serverId:scope.legacy?'':scope.id}),otherBusy:()=>gamesApi.busy()||cloudflareApi.busy()||catalogServicesApi.busy()||servicesPlanning||servicesJob.status==='running'||mysqlApi.busy()||cleanupApi.busy()||systemApi.busy()||serviceVersionsApi.busy(),invalidate:()=>{portsCache=null;forwardingCache=null;},audit:blockAudit});
function restartSafe(){return !zoneApi.busy()&&!cloudflareApi.busy()&&!gamesApi.busy()&&!catalogServicesApi.busy()&&!serviceVersionsApi.busy()&&!panelAuth.busy()&&!terminalApi.busy()&&!commandGuard.state().busy&&!servicesPlanning&&servicesJob.status!=='running'&&!mysqlApi.busy()&&!cleanupApi.busy()&&!systemApi.busy()&&!['generating','downloading'].includes(sshReportJob.status)&&!portsBusy&&!forwardingBusy;}
const server = http.createServer(async (request, response) => {
  setSecurityHeaders(response);
  if (!localRequestAllowed(request, listenPort)) {
    sendJson(response, 403, {error:"Acceso permitido únicamente desde el panel local."});
    return;
  }
  let accessUrl;
  try {
    if(!['GET','HEAD','POST'].includes(request.method)){sendJson(response,405,{error:'Método no permitido.'});return;}
    if(request.url.length>4096){sendJson(response,414,{error:'Dirección demasiado larga.'});return;}
    accessUrl=new URL(request.url,`http://${request.headers.host}`);decodeURIComponent(accessUrl.pathname);
    if(new Set(accessUrl.searchParams.keys()).size!==[...accessUrl.searchParams.keys()].length){sendJson(response,400,{error:"No se permiten parámetros repetidos."});return;}
  } catch {sendJson(response,400,{error:'Dirección no válida.'});return;}
  if(accessUrl.pathname==='/api/connection/suspend'){
    if(request.method!=='POST'){sendJson(response,405,{error:'Método no permitido.'});return;}
    const code=serverSwitch.suspend(request.headers['x-ssm-switch']);sendJson(response,code,{ok:code===200});return;
  }
  if(serverSwitch.paused()){sendJson(response,409,{error:'El panel está cambiando de servidor. Volvé a ingresar.'});return;}
  if(scope.id&&accessUrl.pathname.startsWith('/api/')&&!accessUrl.pathname.startsWith('/api/auth/')&&accessUrl.pathname!=='/api/health'&&request.headers['x-panel-server']!==scope.id){sendJson(response,409,{error:'Esta ventana pertenece a otra conexión. Ingresá nuevamente al servidor seleccionado.',server_changed:true});return;}
  serverSwitch.track(request,response);
  terminalApi.observe(request,response,accessUrl);
  if(await panelAuth.handle(request,response,accessUrl))return;
  return commandGuard.request(request,response,async()=>{
  try {
    if (!['GET','POST','HEAD'].includes(request.method)) { sendJson(response,405,{error:"Método no permitido."}); return; }
    if (request.url.length > 4096) { sendJson(response,414,{error:"La dirección solicitada es demasiado larga."}); return; }
    let url;
    try { url = new URL(request.url, `http://${request.headers.host || "localhost"}`); decodeURIComponent(url.pathname); }
    catch { sendJson(response,400,{error:"La dirección solicitada no es válida."}); return; }
    if (request.method === 'POST' && !String(request.headers['content-type']||'').toLowerCase().startsWith('application/json')) {
      sendJson(response,415,{error:"Se requiere Content-Type application/json."}); return;
    }
    if(await profileApi.handle(request,response,url))return;
    if(url.pathname==='/api/commands/status'&&request.method==='GET'){sendJson(response,200,{ok:true,...commandGuard.state(),action_token:ACTION_TOKEN});return;}
    if(url.pathname==='/api/notifications' && request.method==='GET') {
      const cursor=url.searchParams.get('before');
      if(cursor!==null && !/^[1-9]\d{0,15}$/.test(cursor)){sendJson(response,400,{error:'Cursor no válido.'});return;}
      try{sendJson(response,200,{...notifications.snapshot(cursor===null?null:Number(cursor),request.panelUser),
        monitor:{...(stateValue('system',{}).security_monitor||{ready:false,error:'Esperando la configuración del servidor.'}),...(trustedPolicy.current()||{}),ready:!stateValue('trusted_policy_invalid',false)&&Boolean(trustedPolicy.current())},
        connected:connection.connected,last_success:connection.lastSuccess,action_token:ACTION_TOKEN});}
      catch(error){sendJson(response,400,{error:error.message});}return;
    }
    if(['/api/notifications/read','/api/notifications/delete'].includes(url.pathname) && request.method==='POST') {
      if(!requireActionToken(request)){sendJson(response,403,{error:'Autorización local inválida. Recargá el panel.'});return;}
      const body=await readJsonBody(request);
      try{if(url.pathname.endsWith('/delete'))notifications.deleteRead(body,request.panelUser);else notifications.markRead(body,request.panelUser);sendJson(response,200,{ok:true});}
      catch(error){sendJson(response,400,{error:error.message});}return;
    }
    if(await terminalApi.handle(request,response,url))return;
    if(await alertsApi.handle(request,response,url))return;
    if(await trustedApi.handle(request,response,url))return;
    if(await systemApi.handle(request,response,url))return;
    if(request.method==="POST"&&systemApi.busy()){sendJson(response,409,{error:"El servidor está reiniciándose. Esperá a que se reconecte."});return;}
    if(await cleanupApi.handle(request,response,url))return;
    if(await zoneApi.handle(request,response,url))return;
    if(await gamesApi.handle(request,response,url))return;
    if(await cloudflareApi.handle(request,response,url))return;
    if(await catalogServicesApi.handle(request,response,url))return;
    if(await serviceVersionsApi.handle(request,response,url))return;
    if(await mysqlApi.handle(request,response,url))return;
    if (url.pathname === "/api/dashboard") {
      const data = dashboard(url.searchParams.get("hours"));
      // Nunca sustituir una conexión pendiente por cifras ficticias. El panel
      // debe mostrar exclusivamente datos recopilados del servidor.
      sendJson(response, 200, permittedDashboard(request.panelUser,data));
      return;
    }
    if (url.pathname === "/api/health") {
      sendJson(response, 200, {
        ok:true,
        app:"storypulse-security",
        version:53,protected_runtime:protectedRuntime,auth_ready:panelAuth.ready(),ssh_config_id:sshConfigurationId(config.ssh),
        restart_safe:!serverSwitch.paused()&&restartSafe(),server_id:scope.id,server_label:scope.label,server_scope_ready:true,
        release_version:"2.0",
        ssh_transport:"persistent",
        ssh_transport_connected:connection.transportConnected,
        ...await installationHealth(),
      });
      return;
    }
    if(url.pathname==="/api/services"&&request.method==="GET") {
      try{sendJson(response,200,{...await liveServices(),action_token:ACTION_TOKEN,job:servicesJob});}
      catch(error){sendJson(response,502,{error:"No se pudieron consultar los servicios. "+error.message,job:servicesJob});}
      return;
    }
    if(["/api/services/plan","/api/services/apply"].includes(url.pathname)&&request.method==="POST") {
      if(!requireActionToken(request)){sendJson(response,403,{error:"Autorización local inválida. Recargá el panel."});return;}
      const body=await readJsonBody(request),apply=url.pathname.endsWith("/apply");let payload;
      checkServiceAccess(request,body.action);
      try{payload=servicePayload(body,{apply});}catch(error){sendJson(response,400,{error:error.message});return;}
      if(servicesJob.status==="running"||servicesPlanning||portsBusy||forwardingBusy||mysqlApi.busy()||cleanupApi.busy()){sendJson(response,409,{error:"Hay un cambio en curso. Esperá su resultado."});return;}
      if(apply) {
        if(body.confirm!==true||!/^[a-f0-9]{64}$/.test(body.revision||"")){sendJson(response,400,{error:"Revisá y confirmá el cambio."});return;}
        try{sendJson(response,202,{ok:true,job:startServiceChange({...payload,confirm:true,revision:body.revision})});}
        catch(error){sendJson(response,409,{error:error.message});}
      } else {
        servicesPlanning=true;
        try{sendJson(response,200,await securityCtl("services-plan",payload));}
        catch(error){sendJson(response,409,{error:error.message});}
        finally{servicesPlanning=false;}
      }
      return;
    }
    if(url.pathname==="/api/forwarding"&&request.method==="GET") {
      const raw=url.searchParams.get("port");
      if(raw!==null&&(!/^\d{1,5}$/.test(raw)||Number(raw)<1||Number(raw)>65535)){sendJson(response,400,{error:"Puerto no válido."});return;}
      try{sendJson(response,200,{...await liveForwarding(Number(raw)||null),action_token:ACTION_TOKEN});}
      catch(error){sendJson(response,502,{error:`No se pudo consultar Port Forwarding. ${error.message}`});}
      return;
    }
    if(["/api/forwarding/plan","/api/forwarding/apply"].includes(url.pathname)&&request.method==="POST") {
      if(!requireActionToken(request)){sendJson(response,403,{error:"Autorización local inválida. Recargá el panel."});return;}
      const body=await readJsonBody(request);let payload;
      try{payload=forwardingPayload(body);}catch(error){sendJson(response,400,{error:error.message});return;}
      const apply=url.pathname.endsWith("/apply");
      if(apply&&(body.confirm!==true||!/^[a-f0-9]{64}$/.test(body.revision||""))){sendJson(response,400,{error:"Revisá y confirmá la vista previa."});return;}
      if(forwardingBusy||portsBusy||servicesJob.status==="running"||mysqlApi.busy()||cleanupApi.busy()){sendJson(response,409,{error:"Hay un cambio en curso. Esperá su resultado."});return;}
      forwardingBusy=true;
      try {
        const result=await securityCtl(apply?"forwarding-apply":"forwarding-plan",{...payload,revision:body.revision,target_ip:body.target_ip,confirm:body.confirm});
        if(apply){forwardingCache=null;portsCache=null;blockAudit(`forwarding-${payload.action}`,payload.id||`${payload.protocol}/${payload.port}`,"Cambio de redirección confirmado",true,"");}
        sendJson(response,200,result);
      } catch(error){
        if(apply)blockAudit(`forwarding-${payload.action}`,payload.id||`${payload.protocol}/${payload.port}`,"Cambio de redirección",false,error.message);
        sendJson(response,409,{error:error.message});
      } finally{forwardingBusy=false;if(apply){forwardingCache=null;portsCache=null;}}
      return;
    }
    if (url.pathname === "/api/ports" && request.method === "GET") {
      const raw = url.searchParams.get("port");
      if (raw !== null && (!/^\d{1,5}$/.test(raw) || Number(raw) < 1 || Number(raw) > 65535)) {
        sendJson(response, 400, {error:"Puerto no válido: usá un número entre 1 y 65535."}); return;
      }
      try { sendJson(response, 200, {...await livePorts(Number(raw) || null), action_token:ACTION_TOKEN}); }
      catch (error) { sendJson(response, 502, {error:`No se pudo consultar la gestión de puertos del servidor. ${error.message}`}); }
      return;
    }
    if (["/api/ports/plan", "/api/ports/apply"].includes(url.pathname) && request.method === "POST") {
      if (!requireActionToken(request)) {
        sendJson(response, 403, {error:"Autorización local inválida. Recargá el panel."}); return;
      }
      const body = await readJsonBody(request);
      let payload;
      try { payload = portPayload(body); }
      catch (error) { sendJson(response, 400, {error:error.message}); return; }
      const apply = url.pathname.endsWith("/apply");
      if (apply && (body.confirm !== true || !/^[a-f0-9]{64}$/.test(body.revision || ""))) {
        sendJson(response, 400, {error:"Revisá la vista previa y confirmá el cambio."}); return;
      }
      if (portsBusy || forwardingBusy || servicesJob.status==="running"||mysqlApi.busy()||cleanupApi.busy()) { sendJson(response, 409, {error:"Hay un cambio en curso. Esperá su resultado."}); return; }
      portsBusy = true;
      try {
        const result = await securityCtl(apply ? "ports-apply" : "ports-plan", {...payload, revision:body.revision, confirm:body.confirm});
        if (apply) { portsCache = null; blockAudit(`port-${payload.action}`, `${payload.protocol}/${payload.port}`, "Cambio confirmado de puerto", true, ""); }
        sendJson(response, 200, result);
      } catch (error) {
        if (apply) blockAudit(`port-${payload.action}`, `${payload.protocol}/${payload.port}`, "Cambio de puerto", false, error.message);
        sendJson(response, 409, {error:error.message});
      } finally { portsBusy=false; if (apply) { portsCache = null; forwardingCache=null; } }
      return;
    }
    if (url.pathname === "/api/reports/ssh" && request.method === "GET") {
      sendJson(response, 200, {
        ok: true,
        action_token: ACTION_TOKEN,
        job: reportPublicState(),
        config: {
          max_days: REPORT_MAX_DAYS,
          local_output_dir: REPORT_LOCAL_OUTPUT,
          remote_output_dir: "/var/lib/storypulse-security/Informes/SSH/archivos",
          downloader_ready: true,
        },
      });
      return;
    }
    if (url.pathname === "/api/reports/ssh" && request.method === "POST") {
      if (!requireActionToken(request)) {
        sendJson(response, 403, { error:"Autorización local inválida. Recarga el panel." });
        return;
      }
      const body = await readJsonBody(request);
      if (body.confirm !== true) {
        sendJson(response, 400, { error:"La generación requiere confirmación explícita" });
        return;
      }
      if (!new Set(["generate", "download"]).has(body.action)) {
        sendJson(response, 400, { error:"La operación de reporte no es válida" });
        return;
      }
      try {
        const job = body.action === "download"
          ? startSshReportDownload()
          : startSshReport(body.days);
        sendJson(response, 202, { ok:true, job });
      } catch (error) {
        sendJson(response, 409, { error:String(error.message || error) });
      }
      return;
    }
    if (url.pathname === "/api/network/outgoing" && request.method === "GET") {
      try{
        const data=outgoingTraffic.query(url.searchParams);
        data.monitor=stateValue('system',{}).outgoing_monitor||{enabled:false};
        sendJson(response,200,data);
      }catch(error){sendJson(response,error.status||500,{error:error.status?error.message:'No se pudo consultar el tráfico saliente.'});}
      return;
    }
    if (url.pathname === "/api/ssh-live") {
      try {
        sendJson(response, 200, sshLiveReport(
          url.searchParams.get("hours"),
          url.searchParams.get("result"),
          url.searchParams.get("query"),
          url.searchParams.get("user"),
        ));
      } catch (error) {
        sendJson(response, 400, { error:String(error.message || error) });
      }
      return;
    }
    if (url.pathname === "/api/refresh" && request.method === "POST") {
      void commandGuard.track(()=>collectNow()).catch(()=>{});
      sendJson(response, 202, { ok:true, collecting:true });
      return;
    }
    if (url.pathname === "/api/blocks" && request.method === "GET") {
      sendJson(response, 200, await blockOverview());
      return;
    }
    if (url.pathname === "/api/blocks/ip" && request.method === "POST") {
      if (!requireActionToken(request)) {
        sendJson(response, 403, { error:"Autorización local inválida. Recarga el panel." });
        return;
      }
      const body = await readJsonBody(request);
      const action = body.action === "block" ? "block" : body.action === "unblock" ? "unblock" : "";
      const address = String(body.ip || "").trim();
      if (!action || !isIP(address)) {
        sendJson(response, 400, { error:"Operación o dirección IP no válida" });
        return;
      }
      if (body.confirm !== true) {
        sendJson(response, 400, { error:"La operación requiere confirmación explícita" });
        return;
      }
      const reason = action === "block" ? cleanReason(body.reason) : "";
      try {
        const result = await securityCtl(action, { ip:address, reason });
        blockAudit(action, address, reason, true, JSON.stringify({changed:result.changed}));
        sendJson(response, 200, result);
      } catch (error) {
        blockAudit(action, address, reason, false, String(error.message || error));
        sendJson(response, 502, { error:String(error.message || error) });
      }
      return;
    }
    if (url.pathname === "/api/blocks/provider" && request.method === "POST") {
      if (!requireActionToken(request)) {
        sendJson(response, 403, { error:"Autorización local inválida. Recarga el panel." });
        return;
      }
      const body = await readJsonBody(request);
      const action = body.action === "block" ? "block" : body.action === "unblock" ? "unblock" : "";
      const asn = normalizeAsn(body.asn);
      if (!action || !asn || body.confirm !== true || normalizeAsn(body.confirm_asn) !== asn) {
        sendJson(response, 400, { error:"La operación requiere confirmar el ASN exacto" });
        return;
      }
      const reason = cleanReason(body.reason || `Proveedor ${asn} confirmado tras revisión manual`);
      try {
        if (action === "unblock") {
          const result = await securityCtl("provider-unblock", { asn });
          blockAudit("provider-unblock", asn, reason, true, JSON.stringify({changed:result.changed}));
          sendJson(response, 200, result);
          return;
        }
        const evaluation = await evaluateProvider(asn, body.expected_name);
        if (!evaluation.approved_for_blocking || !evaluation.can_apply) {
          throw new Error("Este ASN no tiene una aprobación vigente para sus prefijos actuales");
        }
        if (String(body.prefix_digest || "").toLowerCase() !== evaluation.prefix_digest) {
          throw new Error("Los prefijos cambiaron desde la evaluación; vuelve a revisarlos");
        }
        const result = await securityCtl("provider-block", {
          asn: evaluation.asn,
          name: evaluation.holder,
          prefixes: evaluation.all_prefixes,
          approval_digest: evaluation.prefix_digest,
          reason,
        });
        blockAudit("provider-block", asn, reason, true, JSON.stringify({changed:result.changed,prefixes:evaluation.all_prefixes.length,digest:evaluation.prefix_digest}));
        sendJson(response, 200, result);
      } catch (error) {
        blockAudit(`provider-${action}`, asn, reason, false, String(error.message || error));
        sendJson(response, 502, { error:String(error.message || error) });
      }
      return;
    }
    if (url.pathname === "/api/providers/evaluate" && request.method === "POST") {
      const body = await readJsonBody(request);
      try {
        const evaluation = await evaluateProvider(body.query, body.expected_name);
        let controller = null;
        try { controller = await securityCtl("status"); } catch {}
        sendJson(response, 200, publicProviderEvaluation(evaluation, controller));
      } catch (error) {
        sendJson(response, 400, { error:String(error.message || error) });
      }
      return;
    }
    if (url.pathname === "/api/ip") {
      const address = (url.searchParams.get("address") || "").trim();
      if (!isIP(address) || address.includes("%")) { sendJson(response,400,{error:"IP no válida"}); return; }
      commandGuard.touch();
      await ensureGeo(address);
      sendJson(response, 200, ipReport(address));
      return;
    }
    if (url.pathname === "/api/port") {
      try {
        const data = portReport(
          url.searchParams.get("protocol"),
          url.searchParams.get("port"),
          url.searchParams.get("hours"),
        );
        sendJson(response, 200, data);
      } catch (error) {
        sendJson(response, 400, { error:String(error.message || error) });
      }
      return;
    }
    staticFile(request, response);
  } catch (error) {
    if (!response.destroyed && !response.writableEnded) sendJson(response, error.status || 400, { error:String(error.message || error) });
  }
  });
});

server.on("error", error => {
  if (error.code === "EADDRINUSE") {
    console.error(`El puerto local ${listenPort} ya está ocupado. Verificá qué instancia está usándolo.`);
    process.exitCode = 1;
    return;
  }
  console.error(`No se pudo iniciar Server Monitor: ${error.message}`);
  process.exitCode = 1;
});

server.requestTimeout = 20000;
server.headersTimeout = 10000;
server.keepAliveTimeout = 5000;
server.maxRequestsPerSocket = 100;
server.maxConnections = 64;
let countryRefreshTimer;
async function refreshCountryDatabase(){
 if(!config.geoLookup)return;
 try{await geoCache.repair();const results=await Promise.allSettled([countryDatabase.update(),asnDatabase.update(),secondaryAsnDatabase.update()]);if(results.some(result=>result.status==='fulfilled'&&result.value))await geoCache.repair({refresh:true});for(const result of results)if(result.status==='rejected')console.warn('Datos de red: se conserva la última base válida. '+String(result.reason?.message||'Actualización no disponible').slice(0,200));}
 catch(error){console.warn('Países: se conserva la base disponible. '+String(error.message).slice(0,200));}
}
server.listen(listenPort, listenHost, () => {
  console.log(`Server Monitor disponible en http://${config.listenHost}:${listenPort}`);
  void refreshCountryDatabase();
  countryRefreshTimer=setInterval(()=>void refreshCountryDatabase(),86400000);countryRefreshTimer.unref();
  collectNow();
  refreshTimer = setInterval(collectNow, Math.max(10, Number(config.refreshSeconds || 20)) * 1000);
});

function shutdown() {
  clearInterval(countryRefreshTimer);
  clearInterval(panelAlertDeliveryTimer);
  clearInterval(refreshTimer);
  clearTimeout(catchupTimer);
  stopOwnedSshMaster();
  server.close(() => process.exit(0));
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
