// Zero-dependency Agent Core HTTP API.
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { config as defaultConfig, investigateServices as defaultServices } from "./config.mjs";
import { IncidentStore } from "./store.mjs";
import { inspectCodebase } from "./codebase.mjs";
import { reason as defaultReason, redactDiagnosticText, sanitizeFixFile } from "./reason.mjs";
import { notifyEngineer as defaultNotify } from "./notify.mjs";
import { createInvestigator, makeConnectorClient } from "./investigate.mjs";

const log = (level, event, fields = {}) =>
  console.log(JSON.stringify({ level, event, service: "agent-core", timestamp: new Date().toISOString(), ...fields }));

class RateLimiter {
  constructor(max, windowMs = 60000) { this.max = max; this.windowMs = windowMs; this.buckets = new Map(); }
  allow(key, now = Date.now()) {
    if (!this.max || this.max <= 0) return true;
    const k = key || "global";
    let b = this.buckets.get(k);
    if (!b || now - b.start >= this.windowMs) { b = { start: now, count: 0 }; this.buckets.set(k, b); }
    b.count += 1;
    if (this.buckets.size > 3000) for (const [ek, eb] of this.buckets) if (now - eb.start >= this.windowMs) this.buckets.delete(ek);
    return b.count <= this.max;
  }
}

function sendJson(res, status, obj) { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); }
const err = (res, status, code, message) => sendJson(res, status, { success: false, error: { code, message } });

function readJson(req, limit = 65536) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", c => { size += c.length; if (size > limit) { reject(new Error("body too large")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {}); } catch { reject(new Error("invalid JSON")); } });
    req.on("error", reject);
  });
}

function sanitizeCommitEntry(c) {
  if (!c || typeof c !== "object") return null;
  const sha = typeof c.sha === "string" && /^[0-9a-fA-F]{7,40}$/.test(c.sha.trim()) ? c.sha.trim() : null;
  if (!sha) return null;
  const message = typeof c.message === "string" ? c.message.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "").slice(0, 500) : "";
  const author = typeof c.author === "string" ? c.author.replace(/[\r\n\x00-\x1f\x7f]/g, "").slice(0, 100) : "unknown";
  const date = typeof c.date === "string" ? c.date.slice(0, 40) : null;
  const safeUrl = sanitizeFixFile(c.url);
  const url = safeUrl && safeUrl.startsWith("https://") ? safeUrl : null;
  return { sha, message, author, date, url };
}

export function normalizeAndValidateIncident(b) {
  if (!b || typeof b !== "object" || Array.isArray(b)) return { error: "incident must be a JSON object" };
  const normalized = { ...b };
  if (!normalized.path && typeof normalized.uri === "string" && normalized.uri) normalized.path = normalized.uri;
  if (!normalized.path && typeof normalized.url === "string" && normalized.url) {
    const q = normalized.url.indexOf("?");
    normalized.path = q === -1 ? normalized.url : normalized.url.slice(0, q);
  }
  if (!normalized.source || typeof normalized.source !== "string") normalized.source = "middleware";
  if (!normalized.detectedAt || typeof normalized.detectedAt !== "string") normalized.detectedAt = new Date().toISOString();

  for (const f of ["id", "requestId", "method", "path", "category", "reason", "detectedAt", "upstream"]) {
    if (typeof normalized[f] !== "string" || !normalized[f].trim()) return { error: `missing or invalid string field: ${f}` };
  }
  if (!Number.isInteger(normalized.statusCode) || normalized.statusCode < 0 || normalized.statusCode > 999) {
    return { error: "statusCode must be an integer (0-999)" };
  }
  if (typeof normalized.durationMs !== "number" || !Number.isFinite(normalized.durationMs) || normalized.durationMs < 0) {
    return { error: "durationMs must be a non-negative finite number" };
  }
  if (typeof normalized.responseSample === "string") {
    normalized.responseSample = redactDiagnosticText(normalized.responseSample.slice(0, 4096));
  }
  if (typeof normalized.query === "string") {
    normalized.query = redactDiagnosticText(normalized.query.slice(0, 1024));
  }
  return { incident: normalized, error: null };
}

export function createAgentCoreServer(overrides = {}) {
  const cfg = overrides.config || defaultConfig;
  if (!cfg.codebase) cfg.codebase = { repoUrl: undefined, fullName: undefined, commits: [] };
  const store = overrides.store || new IncidentStore(cfg.MAX_CONTEXT_INCIDENTS, cfg.DATA_DIR, { ttlMs: cfg.INCIDENT_TTL_MS });
  if (!overrides.store) store.load();

  const investigator = overrides.investigator || createInvestigator({
    store,
    investigateDependencies: overrides.investigateDependencies || makeConnectorClient(cfg),
    inspectCodebase: overrides.inspectCodebase || (inc => inspectCodebase(inc, { root: cfg.CODEBASE_PATH })),
    reason: overrides.reason || (input => defaultReason(input, cfg)),
    notifyEngineer: overrides.notifyEngineer || defaultNotify,
    config: cfg,
    services: overrides.services || defaultServices
  });

  const limiter = new RateLimiter(cfg.RATE_LIMIT_PER_MIN, 60000);

  function authed(req) {
    if (cfg.NODE_ENV === "test" && !cfg.ENFORCE_AUTH_IN_TEST) return true;
    const h = req.headers["authorization"] || "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : "";
    const expected = cfg.AGENT_CORE_TOKEN;
    return token.length === expected.length && timingSafeEqual(Buffer.from(token), Buffer.from(expected));
  }

  function publicConfig() {
    return {
      mode: cfg.AGENT_MODE,
      monitoringActive: cfg.MONITORING_ACTIVE,
      dryRun: cfg.DRY_RUN,
      autoRollback: cfg.AUTO_ROLLBACK,
      escalationThreshold: cfg.ESCALATION_CONFIDENCE_THRESHOLD,
      connectorUrl: cfg.CONNECTOR_URL,
      codebasePath: cfg.CODEBASE_PATH || null,
      codebase: { repoUrl: cfg.codebase.repoUrl || null, fullName: cfg.codebase.fullName || null, commitCount: cfg.codebase.commits.length }
    };
  }

  function applyConfig(body, meta) {
    const changed = [];
    if (body.escalationThreshold !== undefined) {
      if (typeof body.escalationThreshold !== "number" || !Number.isFinite(body.escalationThreshold) || body.escalationThreshold < 0 || body.escalationThreshold > 1) {
        throw new Error("escalationThreshold must be a number between 0 and 1");
      }
      cfg.ESCALATION_CONFIDENCE_THRESHOLD = body.escalationThreshold;
      changed.push("escalationThreshold");
    }
    if (typeof body.dryRun === "boolean") { cfg.DRY_RUN = body.dryRun; changed.push("dryRun"); }
    if (typeof body.autoRollback === "boolean") { cfg.AUTO_ROLLBACK = body.autoRollback; changed.push("autoRollback"); }
    if (typeof body.monitoringActive === "boolean") { cfg.MONITORING_ACTIVE = body.monitoringActive; changed.push("monitoringActive"); }

    if (body.codebase && typeof body.codebase === "object") {
      if (typeof body.codebase.repoUrl === "string") {
        if (!body.codebase.repoUrl) {
          cfg.codebase.repoUrl = undefined;
        } else {
          let u;
          try { u = new URL(body.codebase.repoUrl); } catch { throw new Error("codebase.repoUrl must be a valid URL"); }
          if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("codebase.repoUrl must use http or https");
          if (u.username || u.password) throw new Error("codebase.repoUrl must not embed credentials");
          cfg.codebase.repoUrl = u.toString();
        }
        changed.push("codebase.repoUrl");
      }
      if (typeof body.codebase.fullName === "string") {
        const fn = body.codebase.fullName.trim();
        if (fn && !/^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/.test(fn)) {
          throw new Error("codebase.fullName must match owner/repo");
        }
        cfg.codebase.fullName = fn || undefined;
        changed.push("codebase.fullName");
      }
      if (Array.isArray(body.codebase.commits)) {
        cfg.codebase.commits = body.codebase.commits.slice(0, 5).map(sanitizeCommitEntry).filter(Boolean);
        changed.push("codebase.commits");
      }
    }
    log("info", "agent_core_config_updated", { ...meta, changed, config: publicConfig() });
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    const reqPath = url.pathname;
    const incoming = req.headers["x-request-id"];
    const requestId = incoming && /^[a-zA-Z0-9._:-]{1,100}$/.test(incoming) ? incoming : randomUUID();
    res.setHeader("X-Request-Id", requestId);
    const start = process.hrtime.bigint();
    res.on("finish", () => log(res.statusCode >= 500 ? "error" : "info", "http_request_completed", { requestId, method: req.method, path: reqPath, statusCode: res.statusCode, durationMs: Math.round(Number(process.hrtime.bigint() - start) / 1e6 * 100) / 100 }));

    try {
      if (reqPath === "/health" && req.method === "GET") return sendJson(res, 200, { success: true, service: "agent-core", status: "healthy", mode: cfg.AGENT_MODE, monitoringActive: cfg.MONITORING_ACTIVE });

      const actorIp = req.socket.remoteAddress || "local";
      if (cfg.NODE_ENV !== "test" && !limiter.allow(actorIp)) {
        return err(res, 429, "RATE_LIMITED", "Too many requests to agent-core; retry shortly");
      }

      // Runtime configuration from the control plane (onboarding Steps 03 + 04).
      if (reqPath === "/config") {
        if (!authed(req)) return err(res, 401, "UNAUTHORIZED", "Valid agent-core bearer token required");
        if (req.method === "GET") return sendJson(res, 200, { success: true, config: publicConfig() });
        if (req.method === "POST") {
          applyConfig(await readJson(req), { requestId, actorIp });
          return sendJson(res, 200, { success: true, config: publicConfig() });
        }
      }

      if (!reqPath.startsWith("/incidents")) return err(res, 404, "NOT_FOUND", "Route not found");
      if (!authed(req)) return err(res, 401, "UNAUTHORIZED", "Valid agent-core bearer token required");

      if (reqPath === "/incidents" && req.method === "POST") {
        const body = await readJson(req);
        const { incident, error: problem } = normalizeAndValidateIncident(body);
        if (problem) return err(res, 400, "VALIDATION_ERROR", problem);

        // Monitoring switch (onboarding "Start monitoring"): when paused, record but don't investigate.
        if (!cfg.MONITORING_ACTIVE) {
          const record = store.create(incident);
          record.status = "received";
          store.persist();
          return sendJson(res, 202, { success: true, incident: { id: record.incident.id, status: "received" }, monitoringActive: false });
        }

        const { record, completion } = investigator.startInvestigation(incident);
        if (url.searchParams.get("wait") === "true") {
          const waitMs = Math.max(100, cfg.WAIT_TIMEOUT_MS ?? 8000);
          let timer;
          const timeoutSentinel = new Promise(resolve => { timer = setTimeout(() => resolve("__WAIT_TIMEOUT__"), waitMs); });
          const outcome = await Promise.race([completion, timeoutSentinel]);
          clearTimeout(timer);
          if (outcome === "__WAIT_TIMEOUT__") {
            completion.catch(() => {});
            return sendJson(res, 202, {
              success: true,
              timedOutWaiting: true,
              incident: { id: record.incident.id, status: record.status },
              statusUrl: `/incidents/${record.incident.id}`
            });
          }
          return sendJson(res, 200, { success: true, incident: outcome });
        }
        completion.catch(() => {});
        return sendJson(res, 202, { success: true, incident: { id: record.incident.id, status: record.status }, statusUrl: `/incidents/${record.incident.id}` });
      }

      if (reqPath === "/incidents" && req.method === "GET") {
        const limit = Math.min(Math.max(1, Number(url.searchParams.get("limit")) || 50), cfg.MAX_CONTEXT_INCIDENTS);
        return sendJson(res, 200, { success: true, incidents: store.list(limit), context: store.contextSummary() });
      }

      if (reqPath === "/incidents/context" && req.method === "GET") return sendJson(res, 200, { success: true, context: store.contextSummary() });

      const m = reqPath.match(/^\/incidents\/([^/]+)(\/feedback)?$/);
      if (m) {
        const id = decodeURIComponent(m[1]);
        const isFeedback = Boolean(m[2]);

        if (!isFeedback && req.method === "GET") {
          const record = store.get(id);
          return record ? sendJson(res, 200, { success: true, incident: record }) : err(res, 404, "NOT_FOUND", "Incident not found");
        }

        if (isFeedback && req.method === "POST") {
          const body = await readJson(req);
          if (!["resolved", "unresolved"].includes(body.status)) return err(res, 400, "VALIDATION_ERROR", "status must be resolved or unresolved");
          const existing = store.get(id);
          if (!existing) return err(res, 404, "NOT_FOUND", "Incident not found");
          const cleanNote = typeof body.note === "string" ? redactDiagnosticText(body.note.slice(0, 1000)) : undefined;
          const record = store.setFeedback(id, body.status, cleanNote);
          if (body.status === "unresolved" && record.analysis) {
            const notification = await (overrides.notifyEngineer || defaultNotify)(record.incident, record.analysis, `engineer marked unresolved${cleanNote ? `: ${cleanNote}` : ""}`);
            store.setNotification(id, notification);
            log("warn", "incident_escalated_by_feedback", { incidentId: id });
          }
          return sendJson(res, 200, { success: true, incident: store.get(id) });
        }
      }

      return err(res, 404, "NOT_FOUND", "Route not found");
    } catch (e) {
      return err(res, 400, "BAD_REQUEST", e.message);
    }
  });

  server.store = store;
  return server;
}

export const server = createAgentCoreServer();

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  server.listen(defaultConfig.PORT, () => log("info", "agent_core_listening", { port: defaultConfig.PORT, mode: defaultConfig.AGENT_MODE, connector: defaultConfig.CONNECTOR_URL, codebase: defaultConfig.CODEBASE_PATH || "(none)", llm: defaultConfig.AGENT_MODE === "live" && defaultConfig.GROQ_API_KEY ? defaultConfig.GROQ_MODEL : "heuristic" }));

  function shutdown(signal) {
    log("info", "agent_core_shutdown", { signal });
    server.store?.flushSync();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10000).unref();
  }
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}
