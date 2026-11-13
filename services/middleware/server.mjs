// Zero-dependency SBWK edge middleware: native node:http reverse proxy +
// anomaly detection (status, slow responses, upstream failures) + resilient
// dispatch to Agent Core. Target/detection are runtime-configurable by the control plane.
import http from "node:http";
import https from "node:https";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { config as defaultConfig } from "./config.mjs";
import { classifyStatus, categoryForUpstreamError, buildIncident, DispatchThrottle, RateLimiter, sanitizeIp } from "./detector.mjs";

const log = (level, event, fields = {}) =>
  console.log(JSON.stringify({ level, event, service: "middleware", timestamp: new Date().toISOString(), ...fields }));

const sleep = ms => new Promise(r => setTimeout(r, ms));

export function createMiddlewareServer(cfg = defaultConfig) {
  const throttle = new DispatchThrottle(cfg.DISPATCH_COOLDOWN_MS);
  const adminLimiter = new RateLimiter(cfg.ADMIN_RATE_LIMIT_PER_MIN, 60000);
  const proxyLimiter = new RateLimiter(cfg.PROXY_RATE_LIMIT_PER_MIN, 60000);

  // Resolve the proxy target per request so onboarding can re-point it live.
  function resolveTarget() {
    const t = new URL(cfg.TARGET_SERVER_URL);
    return { url: t, lib: t.protocol === "https:" ? https : http, port: Number(t.port) || (t.protocol === "https:" ? 443 : 80) };
  }

  const recent = [];
  function storeAdd(entry) { recent.push(entry); if (recent.length > cfg.MAX_RECENT_INCIDENTS) recent.shift(); return entry; }
  function storeCounts() {
    const byCategory = {};
    for (const r of recent) byCategory[r.incident.category] = (byCategory[r.incident.category] || 0) + 1;
    return { total: recent.length, dispatched: recent.filter(r => r.dispatched).length, byCategory };
  }

  async function dispatchOnce(incident) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), cfg.DISPATCH_TIMEOUT_MS);
    try {
      const res = await fetch(new URL("/incidents", cfg.AGENT_CORE_URL), {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${cfg.AGENT_CORE_TOKEN}`, "X-Request-Id": incident.requestId },
        body: JSON.stringify(incident),
        signal: controller.signal
      });
      return { ok: res.ok, status: res.status, retryable: res.status === 429 || res.status >= 500 };
    } catch (err) {
      return { ok: false, status: 0, retryable: true, error: err.message };
    } finally {
      clearTimeout(timeout);
    }
  }

  async function dispatchIncident(incident) {
    const maxRetries = Math.max(0, cfg.DISPATCH_MAX_RETRIES ?? 2);
    const baseMs = Math.max(10, cfg.DISPATCH_RETRY_BASE_MS ?? 250);
    let last;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      if (attempt > 0) {
        const delay = Math.round(baseMs * Math.pow(2, attempt - 1) * (0.75 + Math.random() * 0.5));
        await sleep(delay);
      }
      last = await dispatchOnce(incident);
      if (last.ok) {
        log("info", "incident_dispatched", { incidentId: incident.id, status: last.status, attempts: attempt + 1 });
        return true;
      }
      if (!last.retryable) break;
    }
    if (last?.status) log("warn", "incident_dispatch_rejected", { incidentId: incident.id, status: last.status });
    else log("warn", "incident_dispatch_failed", { incidentId: incident.id, error: last?.error });
    // Release throttle slot so a transient Agent Core outage doesn't suppress the next incident.
    throttle.release(incident);
    return false;
  }

  function recordAndDispatch(incident) {
    const dispatch = throttle.shouldDispatch(incident);
    const entry = storeAdd({ incident, dispatched: dispatch });
    log("warn", "anomaly_detected", { incidentId: incident.id, requestId: incident.requestId, method: incident.method, path: incident.path, statusCode: incident.statusCode, category: incident.category, dispatched: dispatch });
    if (dispatch) dispatchIncident(incident).then(ok => { entry.dispatchOk = ok; });
  }

  function sendJson(res, status, obj) { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); }

  function adminAuthed(req) {
    if (cfg.NODE_ENV === "test" && !cfg.ENFORCE_AUTH_IN_TEST) return true;
    const h = req.headers["authorization"] || "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : "";
    const expected = cfg.MIDDLEWARE_ADMIN_TOKEN;
    return token.length === expected.length && timingSafeEqual(Buffer.from(token), Buffer.from(expected));
  }

  function clientIp(req) {
    if (cfg.TRUST_PROXY) {
      const fwd = req.headers["x-forwarded-for"];
      if (typeof fwd === "string" && fwd.length) return sanitizeIp(fwd.split(",")[0]);
    }
    return sanitizeIp(req.socket.remoteAddress || "");
  }

  function forwardedHeader(req) {
    const sockIp = sanitizeIp(req.socket.remoteAddress || "") || "unknown";
    if (cfg.TRUST_PROXY && typeof req.headers["x-forwarded-for"] === "string" && req.headers["x-forwarded-for"].trim()) {
      const chain = req.headers["x-forwarded-for"].split(",").map(s => sanitizeIp(s)).filter(ip => ip && ip !== "unknown");
      if (chain.length) return [...chain, sockIp].join(", ");
    }
    return sockIp;
  }

  function readJson(req, limit = 32768) {
    return new Promise((resolve, reject) => {
      let size = 0; const chunks = [];
      req.on("data", c => { size += c.length; if (size > limit) { reject(new Error("body too large")); req.destroy(); } else chunks.push(c); });
      req.on("end", () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {}); } catch { reject(new Error("invalid JSON")); } });
      req.on("error", reject);
    });
  }

  async function handleAdmin(req, res, url, requestId) {
    const ip = clientIp(req);
    if (cfg.NODE_ENV !== "test" && !adminLimiter.allow(ip)) {
      return sendJson(res, 429, { success: false, error: { code: "RATE_LIMITED", message: "Too many admin requests; retry shortly" } });
    }
    if (!adminAuthed(req)) return sendJson(res, 401, { success: false, error: { code: "UNAUTHORIZED", message: "Valid middleware admin bearer token required" } });

    if (url.pathname === "/_sbwk/status" && req.method === "GET") {
      return sendJson(res, 200, { success: true, service: "middleware", target: cfg.TARGET_SERVER_URL, agentCore: cfg.AGENT_CORE_URL, detection: { minStatus: cfg.DETECT_STATUS_MIN, slowMs: cfg.DETECT_SLOW_MS, upstreamErrors: cfg.DETECT_UPSTREAM_ERRORS, cooldownMs: cfg.DISPATCH_COOLDOWN_MS }, incidents: storeCounts() });
    }
    if (url.pathname === "/_sbwk/incidents" && req.method === "GET") {
      const limit = Math.min(Math.max(1, Number(url.searchParams.get("limit")) || 50), cfg.MAX_RECENT_INCIDENTS);
      return sendJson(res, 200, { success: true, incidents: recent.slice(-limit).reverse() });
    }
    // Runtime configuration from the control plane (onboarding Step 01).
    if (url.pathname === "/_sbwk/config" && req.method === "POST") {
      const body = await readJson(req);
      const changed = [];
      if (typeof body.targetServerUrl === "string" && body.targetServerUrl) {
        let parsed;
        try { parsed = new URL(body.targetServerUrl); }
        catch { return sendJson(res, 400, { success: false, error: { code: "VALIDATION_ERROR", message: "targetServerUrl must be a valid URL" } }); }
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
          return sendJson(res, 400, { success: false, error: { code: "VALIDATION_ERROR", message: "targetServerUrl must use http or https" } });
        }
        if (parsed.username || parsed.password) {
          return sendJson(res, 400, { success: false, error: { code: "VALIDATION_ERROR", message: "targetServerUrl must not embed credentials" } });
        }
        cfg.TARGET_SERVER_URL = parsed.toString().replace(/\/$/, "");
        changed.push("targetServerUrl");
      }
      if (body.detectStatusMin !== undefined) {
        const min = Number(body.detectStatusMin);
        if (!Number.isFinite(min) || min < 100 || min > 599) {
          return sendJson(res, 400, { success: false, error: { code: "VALIDATION_ERROR", message: "detectStatusMin must be between 100 and 599" } });
        }
        cfg.DETECT_STATUS_MIN = min;
        changed.push("detectStatusMin");
      }
      if (body.detectSlowMs !== undefined) {
        const slow = Number(body.detectSlowMs);
        if (!Number.isFinite(slow) || slow < 0 || slow > 300000) {
          return sendJson(res, 400, { success: false, error: { code: "VALIDATION_ERROR", message: "detectSlowMs must be between 0 and 300000" } });
        }
        cfg.DETECT_SLOW_MS = slow;
        changed.push("detectSlowMs");
      }
      log("info", "middleware_config_updated", { requestId, actorIp: ip, changed, target: cfg.TARGET_SERVER_URL, minStatus: cfg.DETECT_STATUS_MIN, slowMs: cfg.DETECT_SLOW_MS });
      return sendJson(res, 200, { success: true, target: cfg.TARGET_SERVER_URL, detection: { minStatus: cfg.DETECT_STATUS_MIN, slowMs: cfg.DETECT_SLOW_MS } });
    }
    return sendJson(res, 404, { success: false, error: { code: "NOT_FOUND", message: "Route not found" } });
  }

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");
    const incoming = req.headers["x-request-id"];
    const requestId = incoming && /^[a-zA-Z0-9._:-]{1,100}$/.test(incoming) ? incoming : randomUUID();
    res.setHeader("X-Request-Id", requestId);
    const start = process.hrtime.bigint();
    const elapsed = () => Number(process.hrtime.bigint() - start) / 1e6;

    if (url.pathname === "/health" && req.method === "GET") return sendJson(res, 200, { success: true, service: "middleware", status: "healthy" });
    if (url.pathname.startsWith("/_sbwk/")) return void handleAdmin(req, res, url, requestId).catch(e => sendJson(res, 400, { success: false, error: { code: "BAD_REQUEST", message: e.message } }));

    const ip = clientIp(req);
    if (cfg.PROXY_RATE_LIMIT_PER_MIN > 0 && !proxyLimiter.allow(ip)) {
      return sendJson(res, 429, { success: false, error: { code: "RATE_LIMITED", message: "Too many requests" } });
    }

    const target = resolveTarget();
    const headers = { ...req.headers, host: target.url.host, "x-forwarded-for": forwardedHeader(req), "x-forwarded-proto": "http", "x-request-id": requestId };
    const proxyReq = target.lib.request({ protocol: target.url.protocol, hostname: target.url.hostname, port: target.port, path: req.url, method: req.method, headers }, proxyRes => {
      const status = proxyRes.statusCode || 0;
      const statusDecision = classifyStatus(status, cfg.DETECT_STATUS_MIN);
      res.writeHead(status, proxyRes.headers);
      proxyRes.pipe(res);

      const max = cfg.RESPONSE_SAMPLE_BYTES;
      const chunks = []; let size = 0;
      proxyRes.on("data", c => { if (size < max) { chunks.push(c); size += c.length; } });
      proxyRes.on("end", () => {
        const durationMs = elapsed();
        let decision = statusDecision;
        if (!decision.detect && cfg.DETECT_SLOW_MS > 0 && durationMs > cfg.DETECT_SLOW_MS) {
          decision = { detect: true, category: "slow_response", reason: `Response took ${Math.round(durationMs)}ms (threshold ${cfg.DETECT_SLOW_MS}ms)` };
        }
        log("info", "http_request_proxied", { requestId, method: req.method, path: req.url, statusCode: status, durationMs: Math.round(durationMs * 100) / 100, anomaly: decision.detect });
        if (decision.detect) {
          const sample = max > 0 && decision.category !== "slow_response" ? Buffer.concat(chunks).subarray(0, max).toString("utf8") : undefined;
          recordAndDispatch(buildIncident({
            id: randomUUID(), requestId, method: req.method, url: req.url, statusCode: status, durationMs,
            upstream: cfg.TARGET_SERVER_URL, category: decision.category, reason: decision.reason,
            responseSample: sample, redact: cfg.REDACT_PII, clientIp: ip, userAgent: req.headers["user-agent"]
          }));
        }
      });
    });

    proxyReq.setTimeout(cfg.PROXY_TIMEOUT_MS, () => { const e = new Error("Upstream request timed out"); e.code = "ETIMEDOUT"; proxyReq.destroy(e); });

    proxyReq.on("error", err => {
      const isTimeout = err.code === "ETIMEDOUT" || err.code === "ESOCKETTIMEDOUT" || /timeout/i.test(err.message);
      const status = isTimeout ? 504 : 502;
      log("error", "upstream_error", { requestId, method: req.method, path: req.url, code: err.code || "CONNECTION_FAILED", message: err.message });
      if (!res.headersSent) sendJson(res, status, { success: false, error: { code: isTimeout ? "GATEWAY_TIMEOUT" : "BAD_GATEWAY", message: "Upstream server is unavailable" } });
      else res.end();
      if (cfg.DETECT_UPSTREAM_ERRORS) {
        recordAndDispatch(buildIncident({
          id: randomUUID(), requestId, method: req.method, url: req.url, statusCode: status, durationMs: elapsed(),
          upstream: cfg.TARGET_SERVER_URL, category: categoryForUpstreamError(isTimeout ? "TIMEOUT" : "CONNECTION_FAILED"),
          reason: isTimeout ? "Upstream server timed out" : "Upstream server could not be reached",
          redact: cfg.REDACT_PII, clientIp: ip, userAgent: req.headers["user-agent"], error: { code: err.code || "CONNECTION_FAILED", message: err.message }
        }));
      }
    });

    req.pipe(proxyReq);
  });

  return server;
}

export const server = createMiddlewareServer(defaultConfig);

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  server.listen(defaultConfig.PORT, () => log("info", "middleware_listening", { port: defaultConfig.PORT, target: defaultConfig.TARGET_SERVER_URL, agentCore: defaultConfig.AGENT_CORE_URL, detectStatusMin: defaultConfig.DETECT_STATUS_MIN, detectSlowMs: defaultConfig.DETECT_SLOW_MS }));

  function shutdown(signal) { log("info", "middleware_shutdown", { signal }); server.close(() => process.exit(0)); setTimeout(() => process.exit(1), 10000).unref(); }
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}
