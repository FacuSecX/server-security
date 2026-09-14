import http from "node:http";
import { spawn } from "node:child_process";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { DatabaseSync } from "node:sqlite";
import { existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(fileURLToPath(import.meta.url));
const STATIC_ROOT = join(ROOT, "dist");
const DATA_ROOT = join(ROOT, "data");
const ENV_PATH = join(ROOT, ".env");
const PROVIDER_APPROVALS_PATH = join(ROOT, "provider-approvals.json");
const SECURITY_CTL = "/usr/local/sbin/server-securityctl";
const REMOTE_COLLECTOR = "/usr/local/lib/server-security/collector.py";
const ACTION_TOKEN = randomBytes(32).toString("hex");
const PANEL_SESSION_ID = randomBytes(8).toString("hex");

function loadEnvironmentFile(path) {
  if (!existsSync(path)) return;
  for (const rawLine of readFileSync(path, "utf8").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const separator = line.indexOf("=");
    if (separator < 1) continue;
    const key = line.slice(0, separator).trim();
    if (!/^[A-Z_][A-Z0-9_]*$/.test(key) || Object.hasOwn(process.env, key)) continue;
    let value = line.slice(separator + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    process.env[key] = value;
  }
}

function envText(name, fallback = "") {
  const value = process.env[name];
  return value === undefined ? fallback : String(value).trim();
}

function envNumber(name, fallback, minimum, maximum) {
  const value = Number(envText(name, String(fallback)));
  if (!Number.isFinite(value)) return fallback;
  return Math.max(minimum, Math.min(maximum, value));
}

function envBoolean(name, fallback) {
  const value = envText(name, fallback ? "true" : "false").toLowerCase();
  if (["1", "true", "yes", "on"].includes(value)) return true;
  if (["0", "false", "no", "off"].includes(value)) return false;
  return fallback;
}

function envList(name) {
  return envText(name).split(",").map(value => value.trim()).filter(Boolean);
}

loadEnvironmentFile(ENV_PATH);

const config = {
  listenHost: envText("SERVER_SECURITY_LISTEN_HOST", "127.0.0.1"),
  listenPort: envNumber("SERVER_SECURITY_LISTEN_PORT", 8765, 1, 65535),
  refreshSeconds: envNumber("SERVER_SECURITY_REFRESH_SECONDS", 20, 10, 3600),
  initialHistoryHours: envNumber("SERVER_SECURITY_INITIAL_HISTORY_HOURS", 168, 1, 720),
  geoLookup: envBoolean("SERVER_SECURITY_GEO_LOOKUP", true),
  maxGeoLookupsPerCycle: envNumber("SERVER_SECURITY_MAX_GEO_LOOKUPS", 100, 1, 100),
  trustedSshIps: envList("SERVER_SECURITY_TRUSTED_SSH_IPS"),
  reports: {
    downloadBat: envText("SERVER_SECURITY_REPORT_DOWNLOAD_BAT"),
    localOutputDir: envText("SERVER_SECURITY_REPORT_LOCAL_DIR"),
    remoteOutputDir: envText("SERVER_SECURITY_REPORT_REMOTE_DIR", "/var/lib/server-security/reports"),
    maxDays: envNumber("SERVER_SECURITY_REPORT_MAX_DAYS", 7, 1, 7),
  },
  ssh: {
    host: envText("SERVER_SECURITY_SSH_HOST"),
    port: envNumber("SERVER_SECURITY_SSH_PORT", 22, 1, 65535),
    user: envText("SERVER_SECURITY_SSH_USER"),
    plinkPath: envText("SERVER_SECURITY_PLINK_PATH", "C:\\Program Files\\PuTTY\\plink.exe"),
    keyPath: envText("SERVER_SECURITY_SSH_KEY_PATH"),
    hostKeyFingerprint: envText("SERVER_SECURITY_SSH_HOST_KEY"),
  },
};

const missingConfiguration = [
  ["SERVER_SECURITY_SSH_HOST", config.ssh.host],
  ["SERVER_SECURITY_SSH_USER", config.ssh.user],
  ["SERVER_SECURITY_SSH_HOST_KEY", config.ssh.hostKeyFingerprint],
].filter(([, value]) => !value).map(([name]) => name);
if (missingConfiguration.length) {
  throw new Error(`Falta configurar ${missingConfiguration.join(", ")} en el archivo .env`);
}
if (!["127.0.0.1", "::1", "localhost"].includes(config.listenHost.toLowerCase())) {
  throw new Error("SERVER_SECURITY_LISTEN_HOST debe ser una dirección local: 127.0.0.1, ::1 o localhost");
}

mkdirSync(DATA_ROOT, { recursive: true });
const reportConfig = config.reports || {};
const REPORT_DOWNLOAD_BAT = String(reportConfig.downloadBat || "");
const REPORT_LOCAL_OUTPUT = String(reportConfig.localOutputDir || "");
const REPORT_REMOTE_OUTPUT = String(reportConfig.remoteOutputDir || "/var/lib/server-security/reports");
const REPORT_MAX_DAYS = Math.max(1, Math.min(7, Math.trunc(Number(reportConfig.maxDays || 7))));
const db = new DatabaseSync(join(DATA_ROOT, "server-security.db"));
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
let sshMasterProcess = null;
let sshMasterStarting = null;
let sshMasterReady = false;
let sshMasterOwned = false;
let sshMasterStderr = "";
let panelSessionMarkerSent = false;
let geoBlockedUntil = 0;
let sshReportJob = {
  status: "idle",
  days: null,
  started_at: 0,
  finished_at: 0,
  files: [],
  message: "Todavía no se generó ningún reporte desde el panel.",
  error: "",
};
const GEO_BACKEND_VERSION = 3;

function stateValue(key, fallback) {
  const row = getState.get(key);
  if (!row) return fallback;
  try { return JSON.parse(row.value); } catch { return fallback; }
}

function saveState(key, value) {
  setState.run(key, JSON.stringify(value));
}

if (Number(stateValue("geo_backend_version", 0)) < GEO_BACKEND_VERSION) {
  // La versión anterior agotaba rápidamente el límite diario de consultas
  // individuales. Reintenta de inmediato los resultados fallidos con el
  // proveedor por lotes, sin descartar las ubicaciones ya confirmadas.
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

db.function("is_tailscale_ip", { deterministic:true }, value => isTailscaleAddress(value) ? 1 : 0);

function sshTarget() {
  return `${config.ssh.user}@${config.ssh.host}`;
}

function plinkConnectionArgs({ authenticate = false } = {}) {
  const ssh = config.ssh;
  const args = [
    "-batch", authenticate ? "-agent" : "-noagent", "-ssh",
    "-P", String(ssh.port || 22), "-hostkey", ssh.hostKeyFingerprint,
  ];
  if (authenticate && ssh.keyPath && existsSync(ssh.keyPath)) args.push("-i", ssh.keyPath);
  return args;
}

function sharedConnectionExists() {
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
    }, 5000);
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
    `/usr/bin/logger -t server-security-panel -- 'SESSION_STARTED ${PANEL_SESSION_ID}'`,
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
    const args = [
      ...plinkConnectionArgs({ authenticate: true }),
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
      sshMasterStderr = `${sshMasterStderr}${chunk}`.slice(-4000);
    });
    child.on("error", error => { spawnError = error; });
    child.on("close", () => {
      if (sshMasterProcess !== child) return;
      sshMasterProcess = null;
      sshMasterReady = false;
      sshMasterOwned = false;
      connection.transportConnected = false;
    });

    for (let attempt = 0; attempt < 60; attempt += 1) {
      if (spawnError) throw spawnError;
      if (child.exitCode !== null) {
        throw new Error((sshMasterStderr || `La conexión SSH persistente terminó con código ${child.exitCode}`).trim());
      }
      if (await sharedConnectionExists()) {
        sshMasterReady = true;
        connection.transportConnected = true;
        await markPanelSessionStarted();
        return;
      }
      await wait(250);
    }

    stopOwnedSshMaster();
    throw new Error("No se pudo establecer la conexión SSH persistente en 15 segundos");
  })().finally(() => {
    sshMasterStarting = null;
  });
  return sshMasterStarting;
}

function runSharedRemote(remote, input = "", timeoutMs = 30000) {
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
    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.on("error", error => {
      clearTimeout(timeout);
      reject(error);
    });
    child.on("close", code => {
      clearTimeout(timeout);
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
    child.stdin.end(input);
  });
}

async function runRemote(remote, input = "", timeoutMs = 30000) {
  await ensureSshMaster();
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

async function runPlink(sinceEpoch) {
  const remote = `sudo -n /usr/bin/python3 ${REMOTE_COLLECTOR} ${Math.max(0, Math.floor(sinceEpoch))} "\${SSH_CONNECTION%% *}"`;
  const stdout = await runRemote(remote, "", 90000);
  try {
    const payload = JSON.parse(stdout.trim());
    if (!payload.ok) throw new Error(payload.error || "El recolector no respondió correctamente");
    return payload;
  } catch (error) {
    throw new Error(`Respuesta inválida del VPS: ${error.message}`);
  }
}

function persistEvents(events) {
  db.exec("BEGIN");
  try {
    for (const event of events || []) {
      insertEvent.run(
        event.id, Number(event.timestamp), event.kind || "", event.ip || "",
        event.provider_slug || "", event.provider || "", event.protocol || "",
        String(event.port ?? ""), event.service || "", event.decision || "",
        event.ssh_user || "", event.auth_method || "", event.details || "",
      );
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

const upsertGeo = db.prepare(`
  INSERT INTO geo_cache(ip,country_code,country,isp,asn,updated_at,ok)
  VALUES(?,?,?,?,?,?,?)
  ON CONFLICT(ip) DO UPDATE SET country_code=excluded.country_code,country=excluded.country,
    isp=excluded.isp,asn=excluded.asn,updated_at=excluded.updated_at,ok=excluded.ok
`);

async function geolocateBatch(addresses) {
  const ips = [...new Set((addresses || []).map(value => String(value || "").trim()))]
    .filter(value => value && !isTailscaleAddress(value))
    .slice(0, 100);
  const now = Math.floor(Date.now() / 1000);
  if (!ips.length || now < geoBlockedUntil) return false;

  try {
    const fields = "status,message,query,country,countryCode,isp,org,as";
    const response = await fetch(`http://ip-api.com/batch?fields=${encodeURIComponent(fields)}`, {
      method: "POST",
      signal: AbortSignal.timeout(12000),
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "Server-Security-Dashboard/2.0",
      },
      body: JSON.stringify(ips),
    });
    const retrySeconds = Math.max(1, Number(response.headers.get("x-ttl") || 60));
    if (response.status === 429) {
      geoBlockedUntil = now + retrySeconds;
      return false;
    }
    if (!response.ok) throw new Error(`Geolocalización HTTP ${response.status}`);
    const rows = await response.json();
    if (!Array.isArray(rows)) throw new Error("Respuesta geográfica no válida");

    for (const [index, row] of rows.entries()) {
      // La API conserva el orden del lote. Usamos la dirección original para
      // que una representación IPv6 comprimida no cree otra clave en caché.
      const ip = ips[index] || String(row.query || "");
      if (!ip) continue;
      if (row.status === "success" && /^[A-Za-z]{2}$/.test(row.countryCode || "")) {
        const asText = String(row.as || "");
        upsertGeo.run(
          ip,
          String(row.countryCode).toUpperCase(),
          row.country || "Desconocido",
          row.isp || row.org || "",
          asText.match(/^AS\d+/i)?.[0]?.toUpperCase() || "",
          now,
          1,
        );
      } else {
        upsertGeo.run(ip, "", "Desconocido", "", "", now, 0);
      }
    }

    const remainingHeader = response.headers.get("x-rl");
    if (remainingHeader !== null && Number(remainingHeader) === 0) geoBlockedUntil = now + retrySeconds;
    return true;
  } catch {
    // Evita insistir en cada ciclo si el servicio externo no está disponible.
    geoBlockedUntil = Math.max(geoBlockedUntil, now + 60);
    return false;
  }
}

async function ensureGeo(ip) {
  const now = Math.floor(Date.now() / 1000);
  const cached = db.prepare("SELECT * FROM geo_cache WHERE ip=?").get(ip);
  const ttl = cached?.ok && cached?.country_code ? 30 * 86400 : 1800;
  if (!cached || now - cached.updated_at >= ttl || !cached.country_code) {
    await geolocateBatch([ip]);
  }
}

async function enrichPendingIps() {
  if (!config.geoLookup) return;
  const limit = Math.min(100, Math.max(1, Number(config.maxGeoLookupsPerCycle || 100)));
  const rows = db.prepare(`
    SELECT DISTINCT e.ip FROM events e
    LEFT JOIN geo_cache g ON g.ip=e.ip
    WHERE g.ip IS NULL OR (? - g.updated_at) > CASE WHEN g.ok=1 THEN 2592000 ELSE 1800 END
    ORDER BY e.timestamp DESC LIMIT ?
  `).all(Math.floor(Date.now() / 1000), limit);
  await geolocateBatch(rows.map(row => row.ip));
}

async function collectNow() {
  if (connection.collecting) return;
  connection.collecting = true;
  connection.lastAttempt = Math.floor(Date.now() / 1000);
  try {
    const previous = stateValue("last_remote_timestamp", 0);
    const firstSince = Math.floor(Date.now() / 1000) - Number(config.initialHistoryHours || 168) * 3600;
    const since = previous ? Math.max(0, previous - 3) : firstSince;
    const payload = await runPlink(since);
    persistEvents(payload.events);
    saveState("providers", payload.providers || []);
    saveState("system", payload.system || {});
    saveState("last_remote_timestamp", payload.generated_at);
    connection.sourceIp = payload.collector_ip || connection.sourceIp;
    connection.connected = true;
    connection.lastSuccess = payload.generated_at;
    connection.error = "";
    await enrichPendingIps();
  } catch (error) {
    connection.connected = false;
    connection.error = String(error.message || error).split("\n").slice(-3).join(" ").slice(0, 600);
  } finally {
    connection.collecting = false;
  }
}

function countryFlag(code) {
  if (!/^[A-Z]{2}$/.test(code || "")) return "🌐";
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

function aggregate(rows, keyFn, labelFn, limit = 8) {
  const map = new Map();
  for (const row of rows) {
    const key = keyFn(row);
    if (!key) continue;
    const item = map.get(key) || { key, label: labelFn(row), count: 0, ips: new Set() };
    item.count += 1;
    if (row.ip) item.ips.add(row.ip);
    map.set(key, item);
  }
  return [...map.values()]
    .sort((a, b) => b.count - a.count)
    .slice(0, limit)
    .map(item => ({ key: item.key, label: item.label, count: item.count, unique_ips: item.ips.size }));
}

function firewallCountriesSince(since) {
  return db.prepare(`
    SELECT
      COALESCE(NULLIF(g.country_code,''),'XX') key,
      COALESCE(NULLIF(g.country,''),'Desconocido') label,
      SUM(CASE WHEN e.kind IN ('firewall','firewall_block') THEN 1 ELSE 0 END) blocked,
      SUM(CASE WHEN e.kind='firewall_allow' THEN 1 ELSE 0 END) accepted,
      COUNT(*) total,
      COUNT(DISTINCT e.ip) unique_ips
    FROM events e
    LEFT JOIN geo_cache g ON g.ip=e.ip
    WHERE e.timestamp>=?
      AND e.kind IN ('firewall','firewall_block','firewall_allow')
    GROUP BY COALESCE(NULLIF(g.country_code,''),'XX'), COALESCE(NULLIF(g.country,''),'Desconocido')
    ORDER BY total DESC, label ASC
  `).all(since).map(row => ({
    ...row,
    count: Number(row.total || 0),
    blocked: Number(row.blocked || 0),
    accepted: Number(row.accepted || 0),
    total: Number(row.total || 0),
    unique_ips: Number(row.unique_ips || 0),
  }));
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

function timeline(rows, hours) {
  const buckets = hours <= 24 ? 24 : hours <= 168 ? 28 : 30;
  const width = hours * 3600 / buckets;
  const now = Math.floor(Date.now() / 1000);
  const start = now - hours * 3600;
  const result = Array.from({ length: buckets }, (_, index) => ({
    timestamp: Math.floor(start + index * width), blocked: 0, accepted: 0, ssh: 0, unique: new Set(),
  }));
  for (const row of rows) {
    const index = Math.max(0, Math.min(buckets - 1, Math.floor((row.timestamp - start) / width)));
    const bucket = result[index];
    if (isFirewallBlocked(row)) bucket.blocked += 1;
    if (isFirewallAllowed(row)) bucket.accepted += 1;
    if (row.kind.startsWith("ssh_")) bucket.ssh += 1;
    bucket.unique.add(row.ip);
  }
  return result.map(row => ({ timestamp: row.timestamp, blocked: row.blocked, accepted: row.accepted, ssh: row.ssh, unique: row.unique.size }));
}

function dashboard(hours = 24) {
  const safeHours = [24, 168, 720].includes(Number(hours)) ? Number(hours) : 24;
  const since = Math.floor(Date.now() / 1000) - safeHours * 3600;
  const rows = db.prepare(`
    SELECT e.*, COALESCE(g.country_code,'') country_code,
      COALESCE(NULLIF(g.country,''),'Desconocido') country,
      COALESCE(g.isp,'') isp, COALESCE(g.asn,'') asn
    FROM events e LEFT JOIN geo_cache g ON g.ip=e.ip
    WHERE e.timestamp>=? ORDER BY e.timestamp DESC LIMIT 50000
  `).all(since);
  const providerSnapshot = stateValue("providers", []);
  const system = stateValue("system", {});
  const trusted = new Set(config.trustedSshIps || []);
  if (connection.sourceIp) trusted.add(connection.sourceIp);
  for (const row of rows) {
    if (!row.provider) row.provider = row.isp || "Sin identificar";
    row.admin_source = trusted.has(row.ip);
    row.authorized = row.kind === "ssh_success" && trusted.has(row.ip);
    row.severity = row.kind === "ssh_success" ? (row.authorized ? "low" : "critical")
      : row.kind === "ssh_failure" ? "medium" : "info";
    row.country_flag = countryFlag(row.country_code);
    row.flow_status = flowStatus(row);
    if (row.authorized || (isFirewallAllowed(row) && row.admin_source)) row.display_ip = "IP autorizada";
    else row.display_ip = row.ip;
  }

  // El tráfico SSH del tailnet es actividad privada administrativa. Se omite
  // para que tanto la recolección periódica como los accesos propios no tapen
  // los intentos procedentes de Internet.
  const visibleRows = rows.filter(row => !(
    isTailscaleAddress(row.ip) && (row.kind.startsWith("ssh_") || isFirewallAllowed(row))
  ));

  const blocked = visibleRows.filter(isFirewallBlocked);
  const accepted = visibleRows.filter(isFirewallAllowed);
  const other = visibleRows.filter(row => !isFirewallBlocked(row) && !isFirewallAllowed(row));
  const sshFailures = visibleRows.filter(row => row.kind === "ssh_failure" || row.kind === "ssh_invalid_user");
  const sshSuccess = visibleRows.filter(row => row.kind === "ssh_success");
  const uniqueIps = new Set(visibleRows.map(row => row.ip)).size;
  const packets = providerSnapshot.reduce((sum, row) => sum + Number(row.packets || 0), 0);
  const providerLogAgg = new Map(aggregate(blocked, row => row.provider_slug || row.provider, row => row.provider, 200).map(row => [row.key, row]));
  const providers = providerSnapshot.map(row => ({
    ...row,
    logged_events: providerLogAgg.get(row.slug)?.count || 0,
    unique_ips: providerLogAgg.get(row.slug)?.unique_ips || 0,
  })).sort((a, b) => b.packets - a.packets);
  // Este resumen se calcula directamente sobre todo el período. No hereda el
  // límite de 50.000 filas usado para mantener ágil la cronología principal.
  const countriesAll = firewallCountriesSince(since);
  const countries = countriesAll.slice(0, 8);
  const ports = aggregate(blocked, row => `${row.protocol}/${row.port}`, row => `${row.protocol}/${row.port} — ${row.service || serviceFor(row.protocol,row.port)}`, 20);
  const sshUsers = aggregate(sshFailures, row => row.ssh_user || "desconocido", row => row.ssh_user || "desconocido", 20);
  const critical = sshSuccess.filter(row => !row.authorized).length;
  const activeServices = (system.services || []).filter(row => row.state === "active").length;

  return {
    mode: rows.length ? "live" : "empty",
    hours: safeHours,
    connection: { ...connection, host: config.ssh.host, refresh_seconds: Number(config.refreshSeconds || 20) },
    summary: {
      drop_packets: packets,
      logged_events: blocked.length,
      accepted_events: accepted.length,
      total_events: visibleRows.length,
      unique_ips: uniqueIps,
      providers: providerSnapshot.length,
      ssh_failures: sshFailures.length,
      ssh_success: sshSuccess.length,
      critical,
      active_services: activeServices,
    },
    countries, countries_all: countriesAll, providers: providers.slice(0, 60), ports, ssh_users: sshUsers,
    timeline: timeline(visibleRows, safeHours),
    events: visibleRows.slice(0, 1000),
    // La tabla principal conserva los eventos recientes, pero cada filtro de
    // resultado recibe su propia ventana. De este modo, miles de bloqueos no
    // desplazan del resultado a las conexiones aceptadas del mismo período.
    activity_events: {
      accepted: accepted.slice(0, 1000),
      blocked: blocked.slice(0, 1000),
      other: other.slice(0, 1000),
    },
    ssh_events: visibleRows.filter(row => row.kind.startsWith("ssh_")).slice(0, 500),
    system,
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
  const conditions = ["e.timestamp>=?", "is_tailscale_ip(e.ip)=0", sshCondition];
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
    WHERE e.timestamp>=? AND is_tailscale_ip(e.ip)=0 AND ${sshCondition}
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
    WHERE e.timestamp>=? AND is_tailscale_ip(e.ip)=0
      AND e.kind IN ('ssh_failure','ssh_invalid_user') AND e.ssh_user<>''
    GROUP BY e.ssh_user ORDER BY count DESC, e.ssh_user ASC LIMIT 500
  `).all(since);
  const trusted = new Set(config.trustedSshIps || []);
  if (connection.sourceIp) trusted.add(connection.sourceIp);

  for (const row of rows) {
    const blocked = row.kind === "firewall" || row.kind === "firewall_block";
    row.ssh_result = blocked ? "blocked" : row.kind === "ssh_success" ? "success" : "failed";
    row.result_label = blocked ? "Bloqueado por firewall" : row.kind === "ssh_success" ? "Exitoso" : "Fallido";
    row.authorized = row.kind === "ssh_success" && trusted.has(row.ip);
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

async function securityCtl(command, payload = null) {
  if (!new Set(["status", "list", "block", "unblock", "provider-block", "provider-unblock", "sync", "report-ssh"]).has(command)) {
    throw new Error("Operación remota no permitida");
  }
  const usesInput = ["block", "unblock", "provider-block", "provider-unblock", "report-ssh"].includes(command);
  const remote = `sudo -n ${SECURITY_CTL} ${command}${usesInput ? " --json-input" : ""}`;
  try {
    const timeout = command === "report-ssh" ? 31 * 60 * 1000 : command.startsWith("provider-") ? 120000 : 35000;
    const raw = await runRemote(remote, usesInput ? JSON.stringify(payload || {}) : "", timeout);
    return parseRemoteJson(raw, "El controlador del VPS devolvió una respuesta no válida");
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

function runLocalReportDownloader() {
  if (!REPORT_DOWNLOAD_BAT) {
    return Promise.reject(new Error("No está configurado el BAT de descarga"));
  }
  if (!existsSync(REPORT_DOWNLOAD_BAT)) {
    return Promise.reject(new Error(`No se encontró el BAT de descarga en ${REPORT_DOWNLOAD_BAT}`));
  }
  return new Promise((resolve, reject) => {
    const commandInterpreter = process.env.ComSpec || "C:\\Windows\\System32\\cmd.exe";
    const child = spawn(commandInterpreter, ["/d", "/c", `${REPORT_DOWNLOAD_BAT} --panel`], {
      cwd: dirname(REPORT_DOWNLOAD_BAT),
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    let settled = false;
    const append = chunk => { output = `${output}${chunk}`.slice(-8000); };
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", append);
    child.stderr.on("data", append);
    const timeout = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      reject(new Error("La descarga local superó los 5 minutos permitidos"));
    }, 5 * 60 * 1000);
    child.on("error", error => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      reject(error);
    });
    child.on("close", code => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (code === 0) resolve(output.trim());
      else reject(new Error(output.trim() || `El BAT de descarga terminó con código ${code}`));
    });
  });
}

function startSshReportDownload() {
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
  void (async () => {
    try {
      await runLocalReportDownloader();
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
  })();
  return reportPublicState();
}

function startSshReport(days) {
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
    message: `Analizando los últimos ${days} ${days === 1 ? "día" : "días"} en el VPS…`,
    error: "",
  };

  void (async () => {
    try {
      const remote = await securityCtl("report-ssh", { minutes: days * 24 * 60 });
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
        throw new Error(remote.warning || "El VPS no generó un archivo nuevo");
      }
      sshReportJob = {
        ...sshReportJob,
        status: "downloading",
        message: "Reporte generado. Descargando y abriendo el TXT más reciente…",
      };
      await runLocalReportDownloader();
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
  })();
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

function readJsonBody(request, limit = 16384) {
  return new Promise((resolve, reject) => {
    let raw = "";
    let tooLarge = false;
    request.setEncoding("utf8");
    request.on("data", chunk => {
      if (tooLarge) return;
      raw += chunk;
      if (Buffer.byteLength(raw) > limit) {
        tooLarge = true;
        raw = "";
      }
    });
    request.on("end", () => {
      if (tooLarge) { reject(new Error("La solicitud es demasiado grande")); return; }
      try {
        const body = raw ? JSON.parse(raw) : {};
        if (!body || Array.isArray(body) || typeof body !== "object") throw new Error();
        resolve(body);
      } catch {
        reject(new Error("El cuerpo JSON no es válido"));
      }
    });
    request.on("error", reject);
  });
}

function requireActionToken(request) {
  const token = String(request.headers["x-server-security-token"] || "");
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
  const url = new URL(`https://stat.ripe.net/data/${endpoint}/data.json`);
  url.searchParams.set("resource", resource);
  const response = await fetch(url, {
    signal: AbortSignal.timeout(15000),
    headers: { "User-Agent":"Server-Security-Dashboard/5.0" },
  });
  if (!response.ok) throw new Error(`RIPEstat respondió HTTP ${response.status}`);
  const payload = await response.json();
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

  if (!addressFamily && !asn) throw new Error("Ingresa una IP pública o un ASN, por ejemplo AS64500");
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
  } else if (residentialTerms.test(identity)) {
    assessment = "not-recommended";
    label = "No recomendado";
    reasons.push("La identidad contiene señales de red residencial, móvil, educativa o de telecomunicaciones mixta.");
  } else if (hostingTerms.test(identity)) {
    reasons.push("La identidad observada es compatible con hosting, nube o centro de datos.");
  } else {
    reasons.push("La identidad no permite confirmar por sí sola que todo el ASN sea exclusivamente hosting/VPS.");
  }
  if (officialFeed) reasons.push("Existe una fuente oficial de rangos que debe compararse antes de aprobar un bloqueo masivo.");
  else if (!already) reasons.push("RIPEstat confirma anuncios BGP, pero eso no demuestra que todos pertenezcan sólo a clientes VPS.");

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
  const relative = url.pathname === "/" ? "index.html" : decodeURIComponent(url.pathname.slice(1));
  if (relative.includes("..")) { response.writeHead(403); response.end(); return; }
  const path = join(STATIC_ROOT, relative);
  if (!existsSync(path) || !statSync(path).isFile()) { response.writeHead(404); response.end("No encontrado"); return; }
  const types = { ".html":"text/html; charset=utf-8", ".css":"text/css; charset=utf-8", ".js":"text/javascript; charset=utf-8", ".svg":"image/svg+xml" };
  response.writeHead(200, { "Content-Type":types[extname(path)] || "application/octet-stream", "Cache-Control":"no-cache" });
  response.end(readFileSync(path));
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    if (url.pathname === "/api/dashboard") {
      const data = dashboard(url.searchParams.get("hours"));
      // Nunca sustituir una conexión pendiente por cifras ficticias. El panel
      // debe mostrar exclusivamente datos recopilados del VPS.
      sendJson(response, 200, data);
      return;
    }
    if (url.pathname === "/api/health") {
      sendJson(response, 200, {
        ok:true,
        app:"server-security",
        version:13,
        ssh_transport:"persistent",
        ssh_transport_connected:connection.transportConnected,
      });
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
          remote_output_dir: REPORT_REMOTE_OUTPUT,
          downloader_ready: Boolean(REPORT_DOWNLOAD_BAT && existsSync(REPORT_DOWNLOAD_BAT)),
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
      collectNow();
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
      if (!/^[0-9A-Fa-f:.]{3,45}$/.test(address)) { sendJson(response,400,{error:"IP no válida"}); return; }
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
    sendJson(response, 500, { error:String(error.message || error) });
  }
});

server.on("error", error => {
  if (error.code === "EADDRINUSE") {
    console.log(`Server Security ya está funcionando en http://${config.listenHost}:${config.listenPort}`);
    process.exitCode = 0;
    return;
  }
  console.error(`No se pudo iniciar Server Security: ${error.message}`);
  process.exitCode = 1;
});

const listenPort = Number(config.listenPort || 8765);
server.listen(listenPort, config.listenHost || "127.0.0.1", () => {
  console.log(`Server Security disponible en http://${config.listenHost}:${listenPort}`);
  collectNow();
  refreshTimer = setInterval(collectNow, Math.max(10, Number(config.refreshSeconds || 20)) * 1000);
});

function shutdown() {
  clearInterval(refreshTimer);
  stopOwnedSshMaster();
  server.close(() => process.exit(0));
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
