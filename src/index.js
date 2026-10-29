import AGENT_PY from "./agent.py";
import INSTALL_SH from "./install.sh";
import PANEL_HTML from "./panel.html";

const ONLINE_MS = 60_000;
const VERSION = "1.1.0";
const enc = new TextEncoder();

// ---------- helpers ----------
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

const text = (body, status = 200, type = "text/plain; charset=utf-8") =>
  new Response(body, { status, headers: { "content-type": type, "cache-control": "no-store" } });

const clip = (v, n) => String(v ?? "").slice(0, n);
const toInt = (v, d = 0) => (Number.isFinite(Number(v)) ? Math.trunc(Number(v)) : d);

async function safeEq(a, b) {
  const [x, y] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const u = new Uint8Array(x), v = new Uint8Array(y);
  let d = 0;
  for (let i = 0; i < u.length; i++) d |= u[i] ^ v[i];
  return d === 0;
}

// 面板登录：必须显式配置，没有弱口令默认值
async function webAuth(req, env) {
  if (!env.WEB_USER || !env.WEB_PASS) return "unset";
  const h = req.headers.get("Authorization") || "";
  if (!h.startsWith("Basic ")) return false;
  let dec;
  try { dec = atob(h.slice(6)); } catch { return false; }
  const i = dec.indexOf(":");
  if (i < 0) return false;
  const okU = await safeEq(dec.slice(0, i), env.WEB_USER);
  const okP = await safeEq(dec.slice(i + 1), env.WEB_PASS);
  return okU && okP;
}

async function agentAuth(req, env) {
  if (!env.AGENT_TOKEN) return false;
  const h = req.headers.get("Authorization") || "";
  if (!h.startsWith("Bearer ")) return false;
  return safeEq(h.slice(7), env.AGENT_TOKEN);
}

// ---------- D1 ----------
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
let initP = null;
function init(db) {
  return (initP ??= doInit(db).catch((e) => { initP = null; throw e; }));
}
async function doInit(db) {
  await db.batch([
    db.prepare(
      "CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, status TEXT, exit_ip TEXT, country TEXT, isp TEXT, hosting INTEGER DEFAULT 0, latency INTEGER DEFAULT 0, host TEXT, port INTEGER, rotate_nonce INTEGER DEFAULT 0, last_seen INTEGER)"
    ),
    db.prepare("CREATE TABLE IF NOT EXISTS policy (k TEXT PRIMARY KEY, v TEXT)"),
    db.prepare(
      "CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, node_id TEXT, ts INTEGER, line TEXT)"
    ),
    db.prepare(
      `CREATE TABLE IF NOT EXISTS scan_ips (
        node_id TEXT, ip TEXT, host TEXT, port INTEGER, proto TEXT,
        cc TEXT, country TEXT, region TEXT, city TEXT, isp TEXT, org TEXT,
        hosting INTEGER, proxy INTEGER, mobile INTEGER, residential INTEGER,
        latency INTEGER, method TEXT, score INTEGER, scan_id INTEGER, scanned_at INTEGER,
        PRIMARY KEY (node_id, ip))`
    ),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_scan_cc ON scan_ips (cc, residential)"),
  ]);
  // 老版本数据库补列
  const cols = ((await db.prepare("PRAGMA table_info(nodes)").all()).results || []).map((c) => c.name);
  for (const [n, t] of [["scan_nonce", "INTEGER DEFAULT 0"], ["scan_state", "TEXT"], ["scan_at", "INTEGER DEFAULT 0"]])
    if (!cols.includes(n)) await db.prepare(`ALTER TABLE nodes ADD COLUMN ${n} ${t}`).run();
}

async function getPolicy(db) {
  const rows = (await db.prepare("SELECT k, v FROM policy").all()).results || [];
  const p = { country: "US", port: "7920" };
  for (const r of rows) p[r.k] = r.v;
  return { country: p.country, port: toInt(p.port, 7920) };
}

// ---------- handlers ----------
async function heartbeat(req, env) {
  let b;
  try { b = await req.json(); } catch { return json({ error: "bad json" }, 400); }
  const id = clip(b.node_id, 64);
  if (!/^[\w.-]+$/.test(id)) return json({ error: "bad node_id" }, 400);

  const now = Date.now();
  const host = /^\d{1,3}(\.\d{1,3}){3}$/.test(b.public_ip || "")
  ? b.public_ip
  : req.headers.get("CF-Connecting-IP") || "";
  const db = env.DB;

  await db
    .prepare(
      `INSERT INTO nodes (id,status,exit_ip,country,isp,hosting,latency,host,port,last_seen,scan_state,scan_at)
       VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
       ON CONFLICT(id) DO UPDATE SET status=?2,exit_ip=?3,country=?4,isp=?5,hosting=?6,latency=?7,host=?8,port=?9,last_seen=?10,scan_state=?11,scan_at=?12`
    )
    .bind(
      id, clip(b.status, 20), clip(b.exit_ip, 64), clip(b.country, 8), clip(b.isp, 120),
      b.hosting ? 1 : 0, toInt(b.latency), host, toInt(b.port), now,
      clip(b.scan_state, 12), toInt(b.scan_at)
    )
    .run();

  const lines = Array.isArray(b.logs) ? b.logs.slice(0, 20) : [];
  if (lines.length) {
    await db.batch(
      lines.map((l) =>
        db.prepare("INSERT INTO logs (node_id, ts, line) VALUES (?1,?2,?3)").bind(id, now, clip(l, 300))
      )
    );
    await db.prepare("DELETE FROM logs WHERE id < (SELECT MAX(id) FROM logs) - 300").run();
  }

  const node = await db.prepare("SELECT rotate_nonce, scan_nonce FROM nodes WHERE id=?1").bind(id).first();
  const policy = await getPolicy(db);
  return json({
    policy: {
      country: policy.country,
      port: policy.port,
      proxy_user: env.PROXY_USER || "",
      proxy_pass: env.PROXY_PASS || "",
    },
    rotate_nonce: node?.rotate_nonce ?? 0,
    scan_nonce: node?.scan_nonce ?? 0,
  });
}

// ---------- 住宅 IP 扫描 ----------
const bool01 = (v) => (v ? 1 : 0);

async function scanIngest(req, env) {
  let b;
  try { b = await req.json(); } catch { return json({ error: "bad json" }, 400); }
  const id = clip(b.node_id, 64);
  if (!/^[\w.-]+$/.test(id)) return json({ error: "bad node_id" }, 400);
  const db = env.DB;
  const now = Date.now();
  const scanId = toInt(b.scan_id);
  const items = Array.isArray(b.items) ? b.items.slice(0, 100) : [];

  const stmts = [];
  for (const x of items) {
    const ip = clip(x?.ip, 45);
    if (!IPV4.test(ip)) continue;
    stmts.push(
      db.prepare(
        `INSERT INTO scan_ips (node_id,ip,host,port,proto,cc,country,region,city,isp,org,hosting,proxy,mobile,residential,latency,method,score,scan_id,scanned_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)
         ON CONFLICT(node_id,ip) DO UPDATE SET host=excluded.host,port=excluded.port,proto=excluded.proto,cc=excluded.cc,
           country=excluded.country,region=excluded.region,city=excluded.city,isp=excluded.isp,org=excluded.org,
           hosting=excluded.hosting,proxy=excluded.proxy,mobile=excluded.mobile,residential=excluded.residential,
           latency=excluded.latency,method=excluded.method,score=excluded.score,scan_id=excluded.scan_id,scanned_at=excluded.scanned_at`
      ).bind(
        id, ip, clip(x.host, 80), toInt(x.port), clip(x.proto, 4), clip(x.cc, 4).toUpperCase(),
        clip(x.country, 60), clip(x.region, 60), clip(x.city, 60), clip(x.isp, 120), clip(x.org, 120),
        bool01(x.hosting), bool01(x.proxy), bool01(x.mobile), bool01(x.residential),
        x.latency == null ? null : toInt(x.latency), clip(x.method, 10), toInt(x.score), scanId, now
      )
    );
  }
  // 最后一批：清掉本节点上一轮留下、这一轮已不在列表里的 IP
  if (b.last && scanId)
    stmts.push(db.prepare("DELETE FROM scan_ips WHERE node_id=?1 AND scan_id != ?2").bind(id, scanId));
  if (stmts.length) await db.batch(stmts);
  return json({ ok: true, accepted: items.length });
}

async function scanList(req, env) {
  const q = new URL(req.url).searchParams;
  const rows = (await env.DB.prepare("SELECT * FROM scan_ips").all()).results || [];
  const type = q.get("type") || "all"; // all | residential | hosting
  const ccs = (q.get("country") || "").toUpperCase().split(",").filter(Boolean);
  const maxLat = toInt(q.get("max_latency"), 0);
  const onlyReach = q.get("reachable") === "1";

  let items = rows.filter((r) => {
    if (type === "residential" && !r.residential) return false;
    if (type === "hosting" && !r.hosting) return false;
    if (ccs.length && !ccs.includes(r.cc)) return false;
    if (onlyReach && r.latency == null) return false;
    if (maxLat && (r.latency == null || r.latency > maxLat)) return false;
    return true;
  });
  // 延迟升序（不可测的排最后），其次评分降序
  items.sort((a, b) => (a.latency ?? 1e9) - (b.latency ?? 1e9) || b.score - a.score);
  const limit = Math.min(Math.max(toInt(q.get("limit"), 500), 1), 2000);
  items = items.slice(0, limit);

  if (q.get("format") === "text")
    return text(items.filter((r) => r.latency != null).map((r) => `${r.host}:${r.port}`).join("\n") + (items.length ? "\n" : ""));

  const byCc = new Map();
  for (const r of rows) {
    const e = byCc.get(r.cc) || { cc: r.cc, country: r.country, total: 0, residential: 0 };
    e.total++;
    if (r.residential) e.residential++;
    byCc.set(r.cc, e);
  }
  return json({
    updated: rows.reduce((m, r) => Math.max(m, r.scanned_at || 0), 0),
    total: rows.length,
    residential: rows.filter((r) => r.residential).length,
    reachable_residential: rows.filter((r) => r.residential && r.latency != null).length,
    countries: [...byCc.values()].sort((a, b) => b.residential - a.residential),
    items: items.map((r) => ({
      ...r, hosting: !!r.hosting, proxy: !!r.proxy, mobile: !!r.mobile, residential: !!r.residential,
    })),
  });
}

async function scanNow(req, env) {
  let b = {};
  try { b = await req.json(); } catch {}
  if (b.node_id) await env.DB.prepare("UPDATE nodes SET scan_nonce = scan_nonce + 1 WHERE id=?1").bind(clip(b.node_id, 64)).run();
  else await env.DB.prepare("UPDATE nodes SET scan_nonce = scan_nonce + 1").run();
  return json({ ok: true });
}

async function state(req, env) {
  const db = env.DB;
  const now = Date.now();
  const nodes = ((await db.prepare("SELECT * FROM nodes ORDER BY last_seen DESC").all()).results || []).map(
    (n) => ({ ...n, online: now - n.last_seen < ONLINE_MS })
  );
  const logs = (await db.prepare("SELECT node_id, ts, line FROM logs ORDER BY id DESC LIMIT 100").all()).results || [];
  const origin = new URL(req.url).origin;
  return json({
    now,
    version: VERSION,
    nodes,
    logs,
    policy: await getPolicy(db),
    install_cmd: `curl -fsSL -H "Authorization: Bearer ${env.AGENT_TOKEN}" ${origin}/install.sh | sudo bash`,
    proxy_auth_set: Boolean(env.PROXY_USER && env.PROXY_PASS),
  });
}

async function readJson(req) {
  try { return await req.json(); } catch { return null; }
}

async function setPolicy(req, env) {
  const b = await readJson(req);
  if (!b) return json({ error: "bad json" }, 400);
  const country = String(b.country || "").toUpperCase();
  const port = toInt(b.port);
  if (!/^([A-Z]{2}|ANY)$/.test(country)) return json({ error: "country 需为两位国家代码，或 ANY" }, 400);
  if (port < 1024 || port > 65535) return json({ error: "port 需在 1024-65535" }, 400);
  await env.DB.batch([
    env.DB.prepare("INSERT INTO policy (k,v) VALUES ('country',?1) ON CONFLICT(k) DO UPDATE SET v=?1").bind(country),
    env.DB.prepare("INSERT INTO policy (k,v) VALUES ('port',?1) ON CONFLICT(k) DO UPDATE SET v=?1").bind(String(port)),
  ]);
  return json({ ok: true });
}

async function rotate(req, env) {
  const { node_id } = (await readJson(req)) || {};
  await env.DB.prepare("UPDATE nodes SET rotate_nonce = rotate_nonce + 1 WHERE id=?1").bind(clip(node_id, 64)).run();
  return json({ ok: true });
}

async function removeNode(req, env) {
  const { node_id } = (await readJson(req)) || {};
  const id = clip(node_id, 64);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM nodes WHERE id=?1").bind(id),
    env.DB.prepare("DELETE FROM scan_ips WHERE node_id=?1").bind(id),
  ]);
  return json({ ok: true });
}

async function proxies(req, env) {
  const url = new URL(req.url);
  const scheme = url.searchParams.get("scheme") === "http" ? "http" : "socks5";
  const now = Date.now();
  const rows = (await env.DB.prepare("SELECT * FROM nodes WHERE status='up'").all()).results || [];
  const list = rows
    .filter((n) => now - n.last_seen < ONLINE_MS && n.host && n.port)
    .map((n) => ({
      node: n.id,
      country: n.country,
      exit_ip: n.exit_ip,
      latency: n.latency,
      url: `${scheme}://${encodeURIComponent(env.PROXY_USER || "")}:${encodeURIComponent(env.PROXY_PASS || "")}@${n.host}:${n.port}`,
    }));
  if (url.searchParams.get("format") === "json") return json(list);
  return text(list.map((x) => x.url).join("\n") + (list.length ? "\n" : ""));
}

// ---------- router ----------
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;

    if (!env.DB) return text("D1 未绑定：请在 wrangler.toml 配置 binding = DB", 500);
    await init(env.DB);

    // agent 通道（Bearer AGENT_TOKEN）
    if ((path === "/api/agent/heartbeat" || path === "/api/agent/scan") && req.method === "POST") {
      if (!(await agentAuth(req, env))) return json({ error: "unauthorized" }, 401);
      return path === "/api/agent/scan" ? scanIngest(req, env) : heartbeat(req, env);
    }
    if (path === "/agent.py" || path === "/install.sh") {
      if (!(await agentAuth(req, env))) return text("unauthorized", 401);
      if (path === "/agent.py") return text(AGENT_PY);
      return text(INSTALL_SH.replaceAll("__HUB__", url.origin).replaceAll("__TOKEN__", env.AGENT_TOKEN));
    }

    // 面板通道（Basic Auth）
    const auth = await webAuth(req, env);
    if (auth === "unset")
      return text("请先用 wrangler secret put 设置 WEB_USER / WEB_PASS（本项目不提供默认口令）", 503);
    if (!auth)
      return new Response("Unauthorized", {
        status: 401,
        headers: { "WWW-Authenticate": 'Basic realm="resi-proxy-hub", charset="UTF-8"' },
      });

    if (req.method === "POST" && !(req.headers.get("content-type") || "").includes("application/json"))
      return json({ error: "content-type must be application/json" }, 415);

    try {
      if (path === "/" && req.method === "GET")
        return new Response(PANEL_HTML, {
          headers: {
            "content-type": "text/html; charset=utf-8",
            "cache-control": "no-store",
            "content-security-policy":
              "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
          },
        });
      if (path === "/api/state" && req.method === "GET") return await state(req, env);
      if (path === "/api/proxies" && req.method === "GET") return await proxies(req, env);
      if (path === "/api/scan" && req.method === "GET") return await scanList(req, env);
      if (path === "/api/scan/now" && req.method === "POST") return await scanNow(req, env);
      if (path === "/api/policy" && req.method === "POST") return await setPolicy(req, env);
      if (path === "/api/rotate" && req.method === "POST") return await rotate(req, env);
      if (path === "/api/nodes/delete" && req.method === "POST") return await removeNode(req, env);
    } catch (e) {
      return json({ error: String(e?.message || e) }, 500);
    }
    return text("Not found", 404);
  },
};
