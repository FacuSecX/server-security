// Aggregate the whole selected period in SQLite; only the detail tables are capped.
export function dashboardData(db, { hours, now, trusted, decorate, serviceFor, authorizedSql=null }) {
  const since = now - hours * 3600;
  // Collector IPs are canonical. Keep this check inside SQLite instead of making
  // millions of synchronous SQLite -> JavaScript callbacks on large histories.
  const tailnet = `((e.ip LIKE '100.%' AND CAST(SUBSTR(e.ip,5,3) AS INTEGER) BETWEEN 64 AND 127)
    OR LOWER(e.ip) LIKE 'fd7a:115c:a1e0:%')`;
  const visible = authorizedSql?`e.timestamp>=? AND NOT (CASE WHEN (e.kind LIKE 'ssh_%' OR e.kind='firewall_allow') AND ${tailnet} THEN ${authorizedSql} ELSE 0 END)`:`e.timestamp>=? AND NOT ((e.kind LIKE 'ssh_%' OR e.kind='firewall_allow') AND ${tailnet})`;
  const blocked = "e.kind IN ('firewall','firewall_block')";
  const accepted = "e.kind='firewall_allow'";
  const failed = "e.kind IN ('ssh_failure','ssh_invalid_user')";
  const addresses = authorizedSql?[]:[...trusted];
  const untrusted = authorizedSql?`NOT(${authorizedSql})`:addresses.length ? `e.ip NOT IN (${addresses.map(() => '?').join(',')})` : '1';
  const critical=authorizedSql?`CASE WHEN e.kind='ssh_success' THEN NOT(${authorizedSql}) ELSE 0 END`:`e.kind='ssh_success' AND ${untrusted}`;
  const summary = db.prepare(`SELECT COUNT(*) total_events, COUNT(DISTINCT e.ip) unique_ips,
    COALESCE(SUM(${blocked}),0) logged_events, COALESCE(SUM(${accepted}),0) accepted_events,
    COALESCE(SUM(${failed}),0) ssh_failures, COALESCE(SUM(e.kind='ssh_success'),0) ssh_success,
    COALESCE(SUM(${critical}),0) critical
    FROM events e WHERE ${visible}`).get(...addresses, since);
  function recent(condition, limit) {
    // For the large two-kind DROP group, use chronological LIMIT rather than
    // sorting every blocked row from both kind indexes before taking 1000.
    const scan = condition === blocked ? 'INDEXED BY events_timestamp_idx' : '';
    return db.prepare(`SELECT e.*, COALESCE(g.country_code,'') country_code,
      COALESCE(NULLIF(g.country,''),'Desconocido') country,
      COALESCE(g.isp,'') isp, COALESCE(g.asn,'') asn
      FROM events e ${scan} LEFT JOIN geo_cache g ON g.ip=e.ip
      WHERE ${visible} AND (${condition}) ORDER BY e.timestamp DESC, e.id DESC LIMIT ?`)
      .all(since, limit).map(decorate);
  }
  const countries = db.prepare(`WITH ip_counts AS (
    SELECT e.ip,SUM(${blocked}) blocked,SUM(${accepted}) accepted,COUNT(*) total
    FROM events e INDEXED BY events_timestamp_idx
    WHERE ${visible} AND (${blocked} OR ${accepted}) GROUP BY e.ip
  ) SELECT COALESCE(NULLIF(g.country_code,''),'XX') key,
    COALESCE(NULLIF(g.country,''),'Desconocido') label,
    SUM(i.blocked) blocked,SUM(i.accepted) accepted,SUM(i.total) total,SUM(i.total) count,
    COUNT(*) unique_ips FROM ip_counts i LEFT JOIN geo_cache g ON g.ip=i.ip
    GROUP BY key ORDER BY total DESC,label`)
    .all(since);
  const ports = db.prepare(`SELECT e.protocol,e.port,MAX(e.service) service,
    COUNT(*) count, COUNT(DISTINCT e.ip) unique_ips FROM events e
    WHERE ${visible} AND ${blocked} GROUP BY e.protocol,e.port ORDER BY count DESC LIMIT 20`)
    .all(since).map(row => ({ ...row, key: `${row.protocol}/${row.port}`,
      label: `${row.protocol}/${row.port} — ${row.service || serviceFor(row.protocol,row.port)}` }));
  const users = db.prepare(`SELECT COALESCE(NULLIF(e.ssh_user,''),'desconocido') key,
    COUNT(*) count, COUNT(DISTINCT e.ip) unique_ips FROM events e
    WHERE ${visible} AND ${failed} GROUP BY key ORDER BY count DESC,key LIMIT 20`)
    .all(since).map(row => ({ ...row, label:row.key }));
  const providers = db.prepare(`SELECT e.provider_slug key,COUNT(*) count,
    COUNT(DISTINCT e.ip) unique_ips FROM events e WHERE ${visible} AND ${blocked}
    GROUP BY e.provider_slug`).all(since);
  const buckets = hours <= 24 ? 24 : hours <= 168 ? 28 : 30;
  const width = hours * 3600 / buckets;
  const timeline = Array.from({length:buckets}, (_,index) => ({
    timestamp:Math.floor(since + index * width), blocked:0,accepted:0,ssh:0,unique:0,
  }));
  for (const row of db.prepare(`SELECT MIN(${buckets - 1}, MAX(0,
    CAST((e.timestamp-${since})/${width} AS INTEGER))) bucket,
    SUM(${blocked}) blocked,SUM(${accepted}) accepted,SUM(e.kind LIKE 'ssh_%') ssh,
    COUNT(DISTINCT e.ip) unique_ips FROM events e WHERE ${visible} GROUP BY bucket`).all(since)) {
    Object.assign(timeline[row.bucket], {blocked:row.blocked,accepted:row.accepted,ssh:row.ssh,unique:row.unique_ips});
  }
  return { as_of:now, summary, countries, ports, users, providers, timeline,
    events:recent('1',1000), ssh_events:recent("e.kind LIKE 'ssh_%'",500),
    activity_events:{ blocked:recent(blocked,1000), accepted:recent(accepted,1000),
      other:recent(`NOT (${blocked} OR ${accepted})`,1000) } };
}

// Reuse aggregates for simultaneous tabs and intermediate browser polls.
// Any database write invalidates them; the TTL also expires sliding windows.
export class DashboardCache {
  constructor(clock=Date.now) { this.clock=clock; this.entries=new Map(); }
  get(key, revision, calculate) {
    const now=this.clock(), cached=this.entries.get(key);
    if(cached && cached.revision===revision && now-cached.time<15000) return cached.value;
    const value=calculate();
    if(this.entries.size>=3&&!this.entries.has(key))this.entries.delete(this.entries.keys().next().value);
    this.entries.set(key,{revision,time:now,value});
    return value;
  }
}

// Materialization keeps SQLite from moving the IP validator back into the event
// scan. The existing covering index groups history before any JS callback.
export function pendingGeoIps(db, now, limit) {
  return db.prepare(`WITH ip_latest AS MATERIALIZED (
    SELECT ip, MAX(timestamp) latest FROM events GROUP BY ip
  ) SELECT e.ip FROM ip_latest e LEFT JOIN geo_cache g ON g.ip=e.ip
    WHERE is_geo_candidate(e.ip)=1 AND (g.ip IS NULL OR
      (? - g.updated_at) >= CASE WHEN g.ok=1 AND g.country_code<>'' THEN 2592000 ELSE 1800 END)
    ORDER BY e.latest DESC,e.ip LIMIT ?`).all(now, limit);
}
