// Zero-dependency onboarding control plane. Serves the UI and makes every
// onboarding step real, hardened with CSRF protection, SSRF checks, rate
// limiting, optional bearer authentication, and encrypted secrets at rest.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { timingSafeEqual } from "node:crypto";
import { config as defaultConfig } from "./config.mjs";
import { createOnboardingStore } from "./store.mjs";
import { checkReachability, fetchGitHubRepo, validateTargetUrl } from "./checks.mjs";
import { applyGateway, applyExternal, applyCodebase, applySafety, applyMonitoring, serviceHealth } from "./apply.mjs";

const log = (level, event, fields = {}) =>
  console.log(JSON.stringify({ level, event, service: "control-plane", timestamp: new Date().toISOString(), ...fields }));

function sendJson(res, status, obj) {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY"
  });
  res.end(JSON.stringify(obj));
}
const ok = (res, obj) => sendJson(res, 200, { success: true, ...obj });
const fail = (res, status, message, extra = {}) => sendJson(res, status, { success: false, error: message, ...extra });

class RateLimiter {
  constructor(max, windowMs = 60000) { this.max = max; this.windowMs = windowMs; this.buckets = new Map(); }
  allow(key, now = Date.now()) {
    if (!this.max || this.max <= 0) return true;
    const k = key || "global";
    let b = this.buckets.get(k);
    if (!b || now - b.start >= this.windowMs) { b = { start: now, count: 0 }; this.buckets.set(k, b); }
    b.count += 1;
    if (this.buckets.size > 2000) for (const [ek, eb] of this.buckets) if (now - eb.start >= this.windowMs) this.buckets.delete(ek);
    return b.count <= this.max;
  }
}

function readJson(req, limit = 65536) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", c => { size += c.length; if (size > limit) { reject(new Error("body too large")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {}); } catch { reject(new Error("invalid JSON")); } });
    req.on("error", reject);
  });
}

const indexHtml = fs.readFileSync(new URL("./public/index.html", import.meta.url), "utf8");

export function verifyCsrf(req, cfg = defaultConfig) {
  if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") return null;

  // 1. Require explicit JSON Content-Type (prevents HTML <form> and CORS simple-request CSRF).
  const ct = String(req.headers["content-type"] || "").toLowerCase();
  if (!ct.startsWith("application/json")) {
    return "Content-Type must be application/json";
  }

  // 2. Reject explicit cross-site Fetch Metadata requests.
  const fetchSite = String(req.headers["sec-fetch-site"] || "").toLowerCase();
  if (fetchSite === "cross-site") {
    return "Cross-site request blocked (CSRF)";
  }

  // 3. When Origin is present, verify same-origin against Host (or ALLOWED_ORIGINS).
  const origin = req.headers["origin"];
  if (typeof origin === "string" && origin.length > 0) {
    const allowedOrigins = new Set(
      String(cfg.ALLOWED_ORIGINS || "")
        .split(",")
        .map(s => s.trim())
        .filter(Boolean)
    );
    if (!allowedOrigins.has(origin)) {
      let originHost;
      try { originHost = new URL(origin).host.toLowerCase(); } catch { return "Invalid Origin header"; }
      const reqHost = String(req.headers["host"] || "").toLowerCase();
      if (!reqHost || originHost !== reqHost) {
        return "Cross-origin state-changing request blocked (CSRF)";
      }
    }
  }

  return null;
}

export function createControlPlaneServer(overrides = {}) {
  const cfg = overrides.config || defaultConfig;
  const store = overrides.store || createOnboardingStore(cfg);
  store.load();

  const limiter = new RateLimiter(cfg.RATE_LIMIT_PER_MIN, 60000);
  const checkReach = overrides.checkReachability || ((u, opts) => checkReachability(u, { ...opts, cfg }));
  const fetchRepo = overrides.fetchGitHubRepo || ((u, t, opts) => fetchGitHubRepo(u, t, { ...opts, cfg }));

  function authed(req) {
    if (!cfg.CONTROL_PLANE_TOKEN) return true;
    const h = req.headers["authorization"] || "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : "";
    const expected = cfg.CONTROL_PLANE_TOKEN;
    return token.length === expected.length && timingSafeEqual(Buffer.from(token), Buffer.from(expected));
  }

  return http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    const p = url.pathname;
    try {
      if (req.method === "GET" && (p === "/" || p === "/index.html")) {
        res.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8",
          "X-Content-Type-Options": "nosniff",
          "X-Frame-Options": "DENY"
        });
        return res.end(indexHtml);
      }

      if (req.method === "GET" && p === "/health") {
        return ok(res, { service: "control-plane", status: "healthy" });
      }

      if (p.startsWith("/api/")) {
        const ip = req.socket.remoteAddress || "local";
        if (cfg.NODE_ENV !== "test" && !limiter.allow(ip)) {
          return fail(res, 429, "Too many requests; retry shortly");
        }
        const csrfErr = verifyCsrf(req, cfg);
        if (csrfErr) return fail(res, 403, csrfErr);
        if (!authed(req)) return fail(res, 401, "Control plane bearer token required", { authRequired: true });
      }

      if (p === "/api/state" && req.method === "GET") {
        return ok(res, { state: store.redacted(), services: await serviceHealth(cfg) });
      }

      // STEP 01 — Gateway
      if (p === "/api/gateway" && req.method === "POST") {
        const body = await readJson(req);
        if (!body.targetUrl) return fail(res, 400, "targetUrl is required");
        const targetCheck = await validateTargetUrl(body.targetUrl, { httpOnly: true, cfg, skipDns: true });
        if (!targetCheck.ok) return fail(res, 400, targetCheck.error);
        if (targetCheck.url.username || targetCheck.url.password) {
          return fail(res, 400, "targetUrl must not embed credentials");
        }
        store.patch("gateway", { targetUrl: body.targetUrl.trim(), port: Number(body.port) || 8080 });
        const apply = await applyGateway(store.get(), cfg);
        log("info", "gateway_configured", { targetUrl: body.targetUrl, apply });
        return ok(res, { gateway: store.get().gateway, apply });
      }
      if (p === "/api/gateway/check" && req.method === "POST") {
        await readJson(req);
        const target = store.get().gateway.targetUrl;
        const check = await checkReach(target, {});
        store.patch("gateway", { lastCheck: { ...check, at: new Date().toISOString() } });
        return ok(res, { check });
      }

      // STEP 02 — External access
      if (p === "/api/external" && req.method === "POST") {
        const body = await readJson(req);
        for (const [label, val] of [["authEndpoint", body.authEndpoint], ["databaseEndpoint", body.databaseEndpoint]]) {
          if (typeof val === "string" && val.trim()) {
            const v = await validateTargetUrl(val.trim(), { cfg, skipDns: true });
            if (!v.ok) return fail(res, 400, `${label}: ${v.error}`);
          }
        }
        store.patch("external", {
          authEndpoint: typeof body.authEndpoint === "string" ? body.authEndpoint.trim() : "",
          databaseEndpoint: typeof body.databaseEndpoint === "string" ? body.databaseEndpoint.trim() : "",
          ...(typeof body.apiKey === "string" && body.apiKey ? { apiKey: body.apiKey } : {})
        });
        return ok(res, { external: store.redacted().external });
      }
      if (p === "/api/external/test" && req.method === "POST") {
        await readJson(req);
        const ext = store.get().external;
        const [auth, database] = await Promise.all([
          ext.authEndpoint ? checkReach(ext.authEndpoint, { token: ext.apiKey }) : { ok: false, reachable: false, error: "not configured" },
          ext.databaseEndpoint ? checkReach(ext.databaseEndpoint, {}) : { ok: false, reachable: false, error: "not configured" }
        ]);
        const reachable = [auth, database].filter(r => r.reachable).length;
        store.patch("external", { lastTest: { auth, database, reachable, at: new Date().toISOString() } });
        const apply = await applyExternal(store.get(), cfg);
        return ok(res, { auth, database, reachable, total: 2, apply });
      }

      // STEP 03 — Codebase link (real GitHub API)
      if (p === "/api/codebase" && req.method === "POST") {
        const body = await readJson(req);
        if (!body.repoUrl) return fail(res, 400, "repoUrl is required");
        let repo;
        try { repo = await fetchRepo(body.repoUrl, body.token, {}); }
        catch (e) { return fail(res, 400, e.message); }
        store.patch("codebase", {
          repoUrl: repo.repoUrl,
          fullName: repo.fullName,
          commits: repo.commits,
          connectedAt: new Date().toISOString(),
          ...(body.token ? { token: body.token } : {})
        });
        const apply = await applyCodebase(store.get(), cfg);
        log("info", "codebase_linked", { fullName: repo.fullName, commits: repo.commits.length, apply });
        return ok(res, { codebase: { fullName: repo.fullName, repoUrl: repo.repoUrl, defaultBranch: repo.defaultBranch, commits: repo.commits }, apply });
      }

      // STEP 04 — Safety limits
      if (p === "/api/safety" && req.method === "POST") {
        const body = await readJson(req);
        const patchObj = {};
        if (typeof body.dryRun === "boolean") patchObj.dryRun = body.dryRun;
        if (typeof body.autoRollback === "boolean") patchObj.autoRollback = body.autoRollback;
        if (typeof body.escalationThreshold === "number" && body.escalationThreshold >= 0 && body.escalationThreshold <= 1) patchObj.escalationThreshold = body.escalationThreshold;
        store.patch("safety", patchObj);
        const apply = await applySafety(store.get(), cfg);
        return ok(res, { safety: store.get().safety, apply });
      }

      // Monitoring switch
      if (p === "/api/monitoring/start" && req.method === "POST") {
        await readJson(req);
        store.patch("monitoring", { active: true, startedAt: new Date().toISOString() });
        const apply = await applyMonitoring(true, cfg);
        log("info", "monitoring_started", { apply });
        return ok(res, { monitoring: store.get().monitoring, apply });
      }
      if (p === "/api/monitoring/stop" && req.method === "POST") {
        await readJson(req);
        store.patch("monitoring", { active: false });
        const apply = await applyMonitoring(false, cfg);
        return ok(res, { monitoring: store.get().monitoring, apply });
      }

      // Live incident feed (proxied from agent-core) for the monitoring view.
      if (p === "/api/incidents" && req.method === "GET") {
        const controller = new AbortController();
        const t = setTimeout(() => controller.abort(), cfg.REQUEST_TIMEOUT_MS);
        try {
          const r = await fetch(`${cfg.AGENT_CORE_URL}/incidents?limit=10`, { headers: { Authorization: `Bearer ${cfg.AGENT_CORE_TOKEN}` }, signal: controller.signal });
          const data = await r.json();
          return ok(res, { incidents: data.incidents || [], context: data.context || {} });
        } catch { return ok(res, { incidents: [], context: {} }); }
        finally { clearTimeout(t); }
      }

      return fail(res, 404, "Not found");
    } catch (e) {
      log("error", "request_failed", { path: p, error: e.message });
      return fail(res, 400, e.message);
    }
  });
}

export const server = createControlPlaneServer();

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  if (defaultConfig.NODE_ENV === "production" && !defaultConfig.CONTROL_PLANE_TOKEN) {
    log("warn", "control_plane_unauthenticated", { message: "CONTROL_PLANE_TOKEN is not set; set CONTROL_PLANE_TOKEN if exposing port 4300 beyond localhost" });
  }
  server.listen(defaultConfig.PORT, () => log("info", "control_plane_listening", { port: defaultConfig.PORT, authEnabled: Boolean(defaultConfig.CONTROL_PLANE_TOKEN) }));
  function shutdown(signal) { log("info", "control_plane_shutdown", { signal }); server.close(() => process.exit(0)); setTimeout(() => process.exit(1), 5000).unref(); }
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}
