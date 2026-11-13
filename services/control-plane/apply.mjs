// Push onboarding configuration to the running services (real, over HTTP).
import { config as defaultConfig } from "./config.mjs";

const TCP_PROTOCOLS = new Set([
  "postgres:", "postgresql:", "mysql:", "mariadb:",
  "redis:", "rediss:", "mongodb:", "mongodb+srv:",
  "amqp:", "amqps:"
]);

async function post(url, token, body, timeoutMs) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, ...(res.ok ? {} : { error: data?.error?.message || `HTTP ${res.status}` }) };
  } catch (e) {
    return { ok: false, error: e.name === "AbortError" ? "timeout" : (e.message || "unreachable") };
  } finally {
    clearTimeout(t);
  }
}

/**
 * Intelligently maps a user-supplied dependency URL to Connector configuration:
 * - Avoids blindly setting `paths.logs = u.pathname` when the user enters a `/health`
 *   endpoint or bare origin (`https://auth.example.com`).
 * - Maps non-HTTP database/cache URIs (`postgres://`, `mongodb+srv://`, `redis://`) to
 *   `tcpEndpoint` so the Connector can run real TCP/TLS probes instead of dropping them.
 */
export function mapExternalEndpoint(endpoint) {
  if (!endpoint || typeof endpoint !== "string") return null;
  let u;
  try { u = new URL(endpoint.trim()); } catch { return null; }

  if (u.protocol === "http:" || u.protocol === "https:") {
    const pathname = u.pathname.replace(/\/+$/, "");
    if (!pathname) {
      return { baseUrl: u.origin, mode: "http", note: "using default /internal/{health,metrics,logs} paths" };
    }
    if (/\/(health|healthz|status)$/i.test(pathname)) {
      const prefix = pathname.replace(/\/(health|healthz|status)$/i, "");
      return {
        baseUrl: u.origin,
        paths: { health: pathname, metrics: `${prefix}/metrics`, logs: `${prefix}/logs` },
        mode: "http",
        note: `mapped ${pathname} as health check (inferred ${prefix || ""}/metrics and ${prefix || ""}/logs)`
      };
    }
    if (/\/metrics$/i.test(pathname)) {
      const prefix = pathname.replace(/\/metrics$/i, "");
      return {
        baseUrl: u.origin,
        paths: { health: `${prefix}/health`, metrics: pathname, logs: `${prefix}/logs` },
        mode: "http",
        note: `mapped ${pathname} as metrics check`
      };
    }
    if (/\/logs$/i.test(pathname)) {
      const prefix = pathname.replace(/\/logs$/i, "");
      return {
        baseUrl: u.origin,
        paths: { health: `${prefix}/health`, metrics: `${prefix}/metrics`, logs: pathname },
        mode: "http",
        note: `mapped ${pathname} as logs check`
      };
    }
    return {
      baseUrl: u.origin,
      paths: { health: `${pathname}/health`, metrics: `${pathname}/metrics`, logs: `${pathname}/logs` },
      mode: "http",
      note: `treated ${pathname} as base path prefix`
    };
  }

  if (TCP_PROTOCOLS.has(u.protocol)) {
    return { tcpEndpoint: endpoint.trim(), mode: "tcp", note: `configured ${u.protocol} TCP/TLS diagnostics` };
  }

  return null;
}

export function applyGateway(state, cfg = defaultConfig) {
  return post(`${cfg.MIDDLEWARE_URL}/_sbwk/config`, cfg.MIDDLEWARE_ADMIN_TOKEN, { targetServerUrl: state.gateway.targetUrl }, cfg.REQUEST_TIMEOUT_MS);
}

export async function applyExternal(state, cfg = defaultConfig) {
  const services = {};
  const mapping = {};

  const auth = mapExternalEndpoint(state.external.authEndpoint);
  if (auth) {
    services.auth = {
      ...(auth.baseUrl ? { baseUrl: auth.baseUrl } : {}),
      ...(auth.tcpEndpoint ? { tcpEndpoint: auth.tcpEndpoint } : {}),
      ...(auth.paths ? { paths: auth.paths } : {}),
      token: state.external.apiKey || undefined
    };
    mapping.auth = { mode: auth.mode, note: auth.note };
  }

  const db = mapExternalEndpoint(state.external.databaseEndpoint);
  if (db) {
    services.database = {
      ...(db.baseUrl ? { baseUrl: db.baseUrl } : {}),
      ...(db.tcpEndpoint ? { tcpEndpoint: db.tcpEndpoint } : {}),
      ...(db.paths ? { paths: db.paths } : {})
    };
    mapping.database = { mode: db.mode, note: db.note };
  }

  if (!Object.keys(services).length) {
    return { ok: true, skipped: "no valid endpoints configured to push" };
  }
  const res = await post(`${cfg.CONNECTOR_URL}/connector/config`, cfg.CONNECTOR_API_TOKEN, { mode: "live", services }, cfg.REQUEST_TIMEOUT_MS);
  return { ...res, mapping };
}

export function applyCodebase(state, cfg = defaultConfig) {
  return post(`${cfg.AGENT_CORE_URL}/config`, cfg.AGENT_CORE_TOKEN, {
    codebase: { repoUrl: state.codebase.repoUrl, fullName: state.codebase.fullName, commits: state.codebase.commits }
  }, cfg.REQUEST_TIMEOUT_MS);
}

export function applySafety(state, cfg = defaultConfig) {
  return post(`${cfg.AGENT_CORE_URL}/config`, cfg.AGENT_CORE_TOKEN, {
    dryRun: state.safety.dryRun, autoRollback: state.safety.autoRollback, escalationThreshold: state.safety.escalationThreshold
  }, cfg.REQUEST_TIMEOUT_MS);
}

export function applyMonitoring(active, cfg = defaultConfig) {
  return post(`${cfg.AGENT_CORE_URL}/config`, cfg.AGENT_CORE_TOKEN, { monitoringActive: active }, cfg.REQUEST_TIMEOUT_MS);
}

export async function serviceHealth(cfg = defaultConfig) {
  const targets = { middleware: `${cfg.MIDDLEWARE_URL}/health`, agentCore: `${cfg.AGENT_CORE_URL}/health`, connector: `${cfg.CONNECTOR_URL}/health` };
  const out = {};
  await Promise.all(Object.entries(targets).map(async ([name, url]) => {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 3000);
    try { const res = await fetch(url, { signal: controller.signal }); out[name] = res.ok ? "healthy" : `http ${res.status}`; }
    catch { out[name] = "unreachable"; }
    finally { clearTimeout(t); }
  }));
  return out;
}
