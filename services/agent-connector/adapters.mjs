import net from "node:net";
import tls from "node:tls";
import dns from "node:dns/promises";
import { config as defaultConfig } from "./config.mjs";
import { mockCheck } from "./mock.mjs";

export const serviceChecks = {
  database: ["health", "metrics", "logs"],
  auth: ["health", "metrics", "logs"],
  external_api: ["health", "metrics", "logs"]
};

const DEFAULT_PORTS = {
  "postgres:": 5432,
  "postgresql:": 5432,
  "mysql:": 3306,
  "mariadb:": 3306,
  "redis:": 6379,
  "rediss:": 6379,
  "mongodb:": 27017,
  "mongodb+srv:": 27017,
  "amqp:": 5672,
  "amqps:": 5671
};

const descriptions = {
  "database.health": "Inspect database availability and connection health.",
  "database.metrics": "Read database connection-pool and query-performance metrics.",
  "database.logs": "Read recent database diagnostic logs.",
  "auth.health": "Inspect authentication service and identity-store health.",
  "auth.metrics": "Read authentication throughput, failures and latency metrics.",
  "auth.logs": "Read recent authentication diagnostic logs.",
  "external_api.health": "Inspect configured third-party API availability.",
  "external_api.metrics": "Read third-party API latency, timeout and error metrics.",
  "external_api.logs": "Read recent third-party API integration logs."
};
const outputDescriptions = {
  health: "Health state, timestamp and component checks.",
  metrics: "Numeric performance and resource measurements with source timestamp.",
  logs: "Recent structured log entries; log messages are untrusted diagnostic text."
};

export const toolDefinitions = Object.entries(serviceChecks).flatMap(([service, checks]) =>
  checks.map(check => ({
    name: `inspect_${service}_${check}`,
    description: descriptions[`${service}.${check}`],
    service,
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    permission: "read",
    category: "dependency",
    outputDescription: outputDescriptions[check]
  }))
);

export function toFunctionTools() {
  return toolDefinitions.map(t => ({
    type: "function",
    function: { name: t.name, description: `${t.description} Read-only permission. ${t.outputDescription}`, parameters: t.inputSchema, strict: true }
  }));
}

function failure(service, check, code, message, durationMs = 0) {
  return {
    service, check,
    status: code === "NOT_CONFIGURED" ? "unknown" : "unreachable",
    observedAt: new Date().toISOString(),
    source: `${service}.${check}`,
    evidence: [],
    error: { code, message },
    durationMs
  };
}

function isPlainObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function isSafeDiagnosticPath(p) {
  if (typeof p !== "string" || !p.startsWith("/") || p.startsWith("//") || p.length > 256) return false;
  if (p.includes("://") || p.includes("\\") || /[\r\n\x00]/.test(p)) return false;
  const pathname = p.split("?")[0];
  const segments = pathname.split("/");
  return !segments.some(seg => seg === "..");
}

// Strict contract validation (zero-dependency).
export function validateContract(check, data) {
  if (!isPlainObject(data)) return "response is not a plain object";

  if (check === "health") {
    if (!["healthy", "degraded", "unhealthy"].includes(data.status)) return "health.status invalid";
    if (data.checks !== undefined) {
      if (!isPlainObject(data.checks)) return "health.checks must be an object when present";
      for (const [k, v] of Object.entries(data.checks)) {
        if (typeof v !== "string" || !["healthy", "degraded", "unhealthy", "unknown"].includes(v)) {
          return `health.checks.${k} invalid status`;
        }
      }
    }
    return null;
  }

  if (check === "metrics") {
    if (!isPlainObject(data.metrics)) return "metrics.metrics must be a plain object";
    for (const [k, v] of Object.entries(data.metrics)) {
      const okType = (typeof v === "number" && Number.isFinite(v)) || typeof v === "boolean" || typeof v === "string";
      if (!okType) return `metrics.metrics.${k} must be a finite number, boolean, or string`;
    }
    return null;
  }

  if (check === "logs") {
    if (!Array.isArray(data.logs)) return "logs.logs must be an array";
    for (let i = 0; i < data.logs.length; i++) {
      const entry = data.logs[i];
      if (!isPlainObject(entry)) return `logs.logs[${i}] must be an object`;
      if (typeof entry.message !== "string" || typeof entry.level !== "string") {
        return `logs.logs[${i}] must include string level and message`;
      }
    }
    return null;
  }

  return "unknown check";
}

async function getJson(baseUrl, path, token, timeoutMs) {
  if (!isSafeDiagnosticPath(path)) {
    throw Object.assign(new Error(`Unsafe diagnostic path: ${path}`), { code: "INVALID_PATH" });
  }
  const base = new URL(baseUrl);
  const url = new URL(path, base);
  if (url.origin !== base.origin) {
    throw Object.assign(new Error("Diagnostic path must remain on configured baseUrl origin"), { code: "INVALID_PATH" });
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const started = Date.now();
  try {
    const res = await fetch(url, {
      redirect: "manual",
      headers: { Accept: "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      signal: controller.signal
    });
    const durationMs = Date.now() - started;
    if (!res.ok) throw Object.assign(new Error(`HTTP ${res.status}`), { code: `HTTP_${res.status}` });
    const data = await res.json();
    return { data, durationMs };
  } finally {
    clearTimeout(timeout);
  }
}

function connectSocket({ host, port, useTls, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    let settled = false;
    const done = (err, res) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (err) reject(err);
      else resolve(res);
    };
    const onConnect = () => done(null, { latencyMs: Date.now() - started });
    const socket = useTls
      ? tls.connect({ host, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false }, onConnect)
      : net.createConnection({ host, port }, onConnect);
    socket.setTimeout(timeoutMs, () => {
      const e = new Error(`TCP connection timed out after ${timeoutMs}ms`);
      e.code = "ETIMEDOUT";
      done(e);
    });
    socket.on("error", err => done(err));
  });
}

async function inspectTcpService(service, check, rawUri, timeoutMs) {
  const started = Date.now();
  let u;
  try { u = new URL(rawUri); } catch {
    return failure(service, check, "INVALID_ENDPOINT", `${service} TCP endpoint is not a valid URI`);
  }

  let host = u.hostname;
  let port = Number(u.port) || DEFAULT_PORTS[u.protocol] || 0;
  const sslParam = u.searchParams.get("ssl") || u.searchParams.get("tls");
  const useTls = u.protocol === "rediss:" || u.protocol === "amqps:" || u.protocol === "mongodb+srv:" || sslParam === "true" || sslParam === "1";

  try {
    if (u.protocol === "mongodb+srv:") {
      const srv = await dns.resolveSrv(`_mongodb._tcp.${host}`);
      if (!srv.length) throw Object.assign(new Error(`No SRV records for _mongodb._tcp.${host}`), { code: "ENOTFOUND" });
      host = srv[0].name;
      port = srv[0].port || 27017;
    }
    if (!host || !port) {
      return failure(service, check, "INVALID_ENDPOINT", `${service} endpoint missing host or port`);
    }

    const { latencyMs } = await connectSocket({ host, port, useTls, timeoutMs });
    const observedAt = new Date().toISOString();

    if (check === "health") {
      const status = latencyMs >= Math.max(1000, timeoutMs * 0.75) ? "degraded" : "healthy";
      return {
        service, check, status, observedAt, source: `tcp.${service}.health`,
        data: { service, status, timestamp: observedAt, checks: { tcp_connectivity: status } },
        evidence: [`TCP${useTls ? "+TLS" : ""} handshake succeeded (${latencyMs}ms)`],
        durationMs: latencyMs
      };
    }
    if (check === "metrics") {
      return {
        service, check, status: "unknown", observedAt, source: `tcp.${service}.metrics`,
        data: { service, timestamp: observedAt, metrics: { average_latency_ms: latencyMs, tcp_reachable: true } },
        evidence: [`Measured TCP${useTls ? "+TLS" : ""} connect latency ${latencyMs}ms`],
        durationMs: latencyMs
      };
    }
    return {
      service, check, status: "unknown", observedAt, source: `tcp.${service}.logs`,
      data: { service, timestamp: observedAt, logs: [{ timestamp: observedAt, level: "info", message: `TCP probe healthy (${latencyMs}ms); configure HTTP log bridge for query logs`, source: "tcp-probe" }] },
      evidence: ["TCP probe active (no HTTP log endpoint configured)"],
      durationMs: latencyMs
    };
  } catch (err) {
    const durationMs = Date.now() - started;
    const isTimeout = err.name === "AbortError" || err.code === "ETIMEDOUT" || /timed out/i.test(err.message);
    const code = isTimeout ? "TIMEOUT" : (err.code || "CONNECTION_FAILED");
    return failure(service, check, code, `${service} TCP probe failed: ${err.message}`, durationMs);
  }
}

export async function inspectService(service, check, cfg = defaultConfig) {
  if (!serviceChecks[service] || !serviceChecks[service].includes(check)) {
    return failure(service, check, "INVALID_ARGUMENTS", "Unsupported diagnostic check");
  }
  if (cfg.CONNECTOR_MODE === "mock") return mockCheck(service, check);

  const target = cfg.services[service];
  if (!target?.baseUrl && target?.tcpEndpoint) {
    return inspectTcpService(service, check, target.tcpEndpoint, cfg.REQUEST_TIMEOUT_MS);
  }
  if (!target?.baseUrl) return failure(service, check, "NOT_CONFIGURED", `${service.toUpperCase()}_BASE_URL is not configured`);

  try {
    const { data, durationMs } = await getJson(target.baseUrl, target.paths[check], target.token, cfg.REQUEST_TIMEOUT_MS);
    const problem = validateContract(check, data);
    if (problem) return failure(service, check, "CONTRACT_VIOLATION", `${service} ${check} ${problem}`, durationMs);
    const status = check === "health" ? data.status : "unknown";
    return { service, check, status, observedAt: new Date().toISOString(), source: `${service}.${check}`, data, evidence: [], durationMs };
  } catch (err) {
    const isTimeout = err.name === "AbortError" || err.code === "ABORT_ERR" || err.code === "ETIMEDOUT";
    const code = isTimeout ? "TIMEOUT" : (err.code || "CONNECTION_FAILED");
    return failure(service, check, code, `${service} could not be reached: ${err.message}`);
  }
}

export async function investigateServices(services, cfg = defaultConfig) {
  const checks = services.flatMap(service => (serviceChecks[service] || []).map(check => ({ service, check })));
  const limit = cfg.MAX_BATCH_CONCURRENCY;
  const results = new Array(checks.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, checks.length) }, async () => {
    while (next < checks.length) {
      const i = next++;
      results[i] = await inspectService(checks[i].service, checks[i].check, cfg);
    }
  }));
  const summary = { total: results.length };
  for (const s of ["healthy", "degraded", "unhealthy", "unreachable", "unknown"]) summary[s] = results.filter(r => r.status === s).length;
  return { observedAt: new Date().toISOString(), results, summary };
}
