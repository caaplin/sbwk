// Zero-dependency Agent Connector — built-in node:http only.
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { timingSafeEqual, randomUUID } from "node:crypto";
import { config as defaultConfig } from "./config.mjs";
import { toolDefinitions, toFunctionTools, inspectService, investigateServices, isSafeDiagnosticPath } from "./adapters.mjs";
import { getMockScenario, setMockScenario, mockScenarios } from "./mock.mjs";

const log = (level, event, fields = {}) =>
  console.log(JSON.stringify({ level, event, service: "agent-connector", timestamp: new Date().toISOString(), ...fields }));

const ALLOWED_TCP_SCHEMES = new Set([
  "postgres:", "postgresql:", "mysql:", "mariadb:", "redis:", "rediss:",
  "mongodb:", "mongodb+srv:", "amqp:", "amqps:"
]);

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

function sendJson(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(obj));
}

function readJson(req, limit = 32768) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", c => {
      size += c.length;
      if (size > limit) { reject(new Error("body too large")); req.destroy(); }
      else chunks.push(c);
    });
    req.on("end", () => {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {}); }
      catch { reject(new Error("invalid JSON")); }
    });
    req.on("error", reject);
  });
}

const err = (res, status, code, message) => sendJson(res, status, { success: false, error: { code, message } });

export function createConnectorServer(cfg = defaultConfig) {
  const limiter = new RateLimiter(cfg.RATE_LIMIT_PER_MIN, 60000);

  function authed(req) {
    if (cfg.NODE_ENV === "test" && !cfg.ENFORCE_AUTH_IN_TEST) return true;
    const h = req.headers["authorization"] || "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : "";
    const expected = cfg.CONNECTOR_API_TOKEN;
    if (token.length !== expected.length) return false;
    return timingSafeEqual(Buffer.from(token), Buffer.from(expected));
  }

  return http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    const reqPath = url.pathname;
    const incoming = req.headers["x-request-id"];
    const requestId = incoming && /^[a-zA-Z0-9._:-]{1,100}$/.test(incoming) ? incoming : randomUUID();
    res.setHeader("X-Request-Id", requestId);
    const start = process.hrtime.bigint();
    res.on("finish", () => log(res.statusCode >= 500 ? "error" : "info", "http_request_completed", {
      requestId, method: req.method, path: reqPath, statusCode: res.statusCode,
      durationMs: Math.round(Number(process.hrtime.bigint() - start) / 1e6 * 100) / 100
    }));

    try {
      if (reqPath === "/health" && req.method === "GET") return sendJson(res, 200, { success: true, service: "agent-connector", status: "healthy" });
      if (!reqPath.startsWith("/connector/")) return err(res, 404, "NOT_FOUND", "Route not found");

      const ip = req.socket.remoteAddress || "local";
      if (cfg.NODE_ENV !== "test" && !limiter.allow(ip)) {
        return err(res, 429, "RATE_LIMITED", "Too many connector requests; retry shortly");
      }
      if (!authed(req)) return err(res, 401, "UNAUTHORIZED", "Valid connector bearer token required");

      if (reqPath === "/connector/tools" && req.method === "GET") {
        const format = url.searchParams.get("format");
        if (format && format !== "native" && format !== "openai") return err(res, 400, "INVALID_FORMAT", "format must be native or openai");
        if (format === "openai") return sendJson(res, 200, { success: true, providerFormat: "openai-function-tools", readOnly: true, tools: toFunctionTools() });
        return sendJson(res, 200, { success: true, name: "sleepy-bot-agent-connector", version: "2.0.0", readOnly: true, invocation: { method: "POST", path: "/connector/execute" }, tools: toolDefinitions });
      }

      if (reqPath === "/connector/execute" && req.method === "POST") {
        const body = await readJson(req);
        const def = toolDefinitions.find(t => t.name === body.tool);
        if (!def) return err(res, 400, "UNKNOWN_TOOL", "Tool is not registered");
        if (body.arguments && Object.keys(body.arguments).length) return err(res, 400, "INVALID_ARGUMENTS", "This diagnostic tool accepts no arguments");
        const check = def.name.replace(`inspect_${def.service}_`, "");
        return sendJson(res, 200, { success: true, result: await inspectService(def.service, check, cfg) });
      }

      if (reqPath === "/connector/investigate" && req.method === "POST") {
        const body = await readJson(req);
        const services = Array.isArray(body.services) ? body.services.filter(s => ["database", "auth", "external_api"].includes(s)) : [];
        if (!services.length || services.length > 6) return err(res, 400, "VALIDATION_ERROR", "services must be 1-6 of database|auth|external_api");
        return sendJson(res, 200, { success: true, ...(await investigateServices(services, cfg)) });
      }

      if (reqPath === "/connector/status" && req.method === "GET") {
        return sendJson(res, 200, { success: true, connector: "sleepy-bot-agent-connector", mode: cfg.CONNECTOR_MODE, readOnly: true, availableServices: ["database", "auth", "external_api"] });
      }

      if (reqPath === "/connector/demo/scenario") {
        if (cfg.CONNECTOR_MODE !== "mock") return err(res, 404, "NOT_FOUND", "Demo controls are disabled in live mode");
        if (req.method === "GET") return sendJson(res, 200, { success: true, scenario: getMockScenario(), availableScenarios: mockScenarios });
        if (req.method === "POST") {
          const body = await readJson(req);
          if (!mockScenarios.includes(body.scenario)) return err(res, 400, "VALIDATION_ERROR", "Unknown demo scenario");
          return sendJson(res, 200, { success: true, scenario: setMockScenario(body.scenario) });
        }
      }

      // Runtime configuration from the control plane (onboarding Step 02).
      if (reqPath === "/connector/config" && req.method === "POST") {
        const body = await readJson(req);
        const updatedServices = [];

        if (body.mode !== undefined) {
          if (body.mode !== "mock" && body.mode !== "live") return err(res, 400, "VALIDATION_ERROR", "mode must be mock or live");
          cfg.CONNECTOR_MODE = body.mode;
        }

        if (body.services && typeof body.services === "object") {
          for (const svc of ["database", "auth", "external_api"]) {
            const s = body.services[svc];
            if (!s || typeof s !== "object") continue;

            if (typeof s.baseUrl === "string") {
              if (!s.baseUrl) {
                cfg.services[svc].baseUrl = undefined;
              } else {
                let u;
                try { u = new URL(s.baseUrl); } catch { return err(res, 400, "VALIDATION_ERROR", `${svc}.baseUrl must be a valid URL`); }
                if (u.protocol === "http:" || u.protocol === "https:") {
                  if (u.username || u.password) return err(res, 400, "VALIDATION_ERROR", `${svc}.baseUrl must not embed credentials`);
                  cfg.services[svc].baseUrl = u.origin;
                  cfg.services[svc].tcpEndpoint = undefined;
                } else if (ALLOWED_TCP_SCHEMES.has(u.protocol)) {
                  cfg.services[svc].baseUrl = undefined;
                  cfg.services[svc].tcpEndpoint = s.baseUrl;
                } else {
                  return err(res, 400, "VALIDATION_ERROR", `${svc}.baseUrl uses unsupported protocol ${u.protocol}`);
                }
              }
            }

            if (typeof s.tcpEndpoint === "string") {
              if (!s.tcpEndpoint) {
                cfg.services[svc].tcpEndpoint = undefined;
              } else {
                let u;
                try { u = new URL(s.tcpEndpoint); } catch { return err(res, 400, "VALIDATION_ERROR", `${svc}.tcpEndpoint must be a valid URI`); }
                if (!ALLOWED_TCP_SCHEMES.has(u.protocol)) {
                  return err(res, 400, "VALIDATION_ERROR", `${svc}.tcpEndpoint uses unsupported protocol ${u.protocol}`);
                }
                cfg.services[svc].tcpEndpoint = s.tcpEndpoint;
              }
            }

            if (typeof s.token === "string") cfg.services[svc].token = s.token || undefined;

            if (s.paths && typeof s.paths === "object") {
              for (const [checkKey, pathVal] of Object.entries(s.paths)) {
                if (!["health", "metrics", "logs"].includes(checkKey)) {
                  return err(res, 400, "VALIDATION_ERROR", `Unsupported check path key: ${checkKey}`);
                }
                if (!isSafeDiagnosticPath(pathVal)) {
                  return err(res, 400, "VALIDATION_ERROR", `${svc}.paths.${checkKey} must be a safe relative path starting with /`);
                }
                cfg.services[svc].paths[checkKey] = pathVal;
              }
            }
            updatedServices.push(svc);
          }
        }

        log("info", "connector_config_updated", { requestId, actorIp: ip, mode: cfg.CONNECTOR_MODE, updatedServices });
        return sendJson(res, 200, {
          success: true, mode: cfg.CONNECTOR_MODE,
          services: Object.fromEntries(Object.entries(cfg.services).map(([k, v]) => [
            k,
            { configured: Boolean(v.baseUrl || v.tcpEndpoint), protocol: v.baseUrl ? "http" : (v.tcpEndpoint ? "tcp" : null), paths: v.paths }
          ]))
        });
      }

      return err(res, 404, "NOT_FOUND", "Route not found");
    } catch (e) {
      return err(res, 400, "BAD_REQUEST", e.message);
    }
  });
}

export const server = createConnectorServer(defaultConfig);

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  server.listen(defaultConfig.PORT, () => log("info", "connector_listening", { port: defaultConfig.PORT, mode: defaultConfig.CONNECTOR_MODE }));

  function shutdown(signal) {
    log("info", "connector_shutdown", { signal });
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10000).unref();
  }
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}
