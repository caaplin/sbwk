// Zero-dependency end-to-end smoke demo across all 5 SBWK services on ephemeral ports.
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createConnectorServer } from "../services/agent-connector/server.mjs";
import { setMockScenario } from "../services/agent-connector/mock.mjs";
import { createAgentCoreServer } from "../services/agent-core/server.mjs";
import { createMiddlewareServer } from "../services/middleware/server.mjs";
import { createControlPlaneServer } from "../services/control-plane/server.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const listen = srv => new Promise(r => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
const close = srv => new Promise(r => srv.close(() => r()));

let failMode = "normal";
const dummy = http.createServer((req, res) => {
  if (req.url === "/users" && failMode === "database") {
    res.writeHead(500, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "Database error: connection pool exhausted (100/100)" }));
  }
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ ok: true }));
});

const dummyPort = await listen(dummy);
const connectorCfg = {
  NODE_ENV: "development",
  CONNECTOR_API_TOKEN: "demo-connector-token-0123456789abcdef",
  CONNECTOR_MODE: "mock",
  REQUEST_TIMEOUT_MS: 3000,
  RATE_LIMIT_PER_MIN: 180,
  MAX_BATCH_CONCURRENCY: 4,
  services: {
    database: { paths: { health: "/internal/health", metrics: "/internal/metrics", logs: "/internal/logs" } },
    auth: { paths: { health: "/internal/health", metrics: "/internal/metrics", logs: "/internal/logs" } },
    external_api: { paths: { health: "/health", metrics: "/metrics", logs: "/logs" } }
  }
};
const connector = createConnectorServer(connectorCfg);
const connectorPort = await listen(connector);

const coreCfg = {
  NODE_ENV: "development",
  AGENT_CORE_TOKEN: "demo-agent-core-token-0123456789abcdef",
  AGENT_MODE: "mock",
  CONNECTOR_URL: `http://127.0.0.1:${connectorPort}`,
  CONNECTOR_API_TOKEN: connectorCfg.CONNECTOR_API_TOKEN,
  REQUEST_TIMEOUT_MS: 3000,
  WAIT_TIMEOUT_MS: 5000,
  RATE_LIMIT_PER_MIN: 120,
  CODEBASE_PATH: path.join(root, "services", "dummy-server"),
  CODEBASE_MAX_FILES: 100,
  CODEBASE_MAX_FINDINGS: 4,
  MAX_CONTEXT_INCIDENTS: 50,
  ESCALATION_CONFIDENCE_THRESHOLD: 0.8,
  DRY_RUN: true,
  AUTO_ROLLBACK: true,
  MONITORING_ACTIVE: true,
  codebase: { repoUrl: undefined, fullName: undefined, commits: [] }
};
const core = createAgentCoreServer({ config: coreCfg });
const corePort = await listen(core);

const mwCfg = {
  NODE_ENV: "development",
  TARGET_SERVER_URL: `http://127.0.0.1:${dummyPort}`,
  AGENT_CORE_URL: `http://127.0.0.1:${corePort}`,
  AGENT_CORE_TOKEN: coreCfg.AGENT_CORE_TOKEN,
  MIDDLEWARE_ADMIN_TOKEN: "demo-middleware-admin-token-0123456789",
  DETECT_STATUS_MIN: 500,
  DETECT_SLOW_MS: 1000,
  DETECT_UPSTREAM_ERRORS: true,
  DISPATCH_COOLDOWN_MS: 5000,
  DISPATCH_TIMEOUT_MS: 3000,
  DISPATCH_MAX_RETRIES: 2,
  DISPATCH_RETRY_BASE_MS: 50,
  RESPONSE_SAMPLE_BYTES: 2048,
  REDACT_PII: true,
  TRUST_PROXY: false,
  ADMIN_RATE_LIMIT_PER_MIN: 120,
  PROXY_RATE_LIMIT_PER_MIN: 0,
  PROXY_TIMEOUT_MS: 5000,
  MAX_RECENT_INCIDENTS: 50
};
const mw = createMiddlewareServer(mwCfg);
const mwPort = await listen(mw);

const cpCfg = {
  NODE_ENV: "development",
  REQUEST_TIMEOUT_MS: 3000,
  RATE_LIMIT_PER_MIN: 120,
  PERSIST_SECRETS: false,
  BLOCK_PRIVATE_NETWORKS: false,
  MIDDLEWARE_URL: `http://127.0.0.1:${mwPort}`,
  MIDDLEWARE_ADMIN_TOKEN: mwCfg.MIDDLEWARE_ADMIN_TOKEN,
  CONNECTOR_URL: `http://127.0.0.1:${connectorPort}`,
  CONNECTOR_API_TOKEN: connectorCfg.CONNECTOR_API_TOKEN,
  AGENT_CORE_URL: `http://127.0.0.1:${corePort}`,
  AGENT_CORE_TOKEN: coreCfg.AGENT_CORE_TOKEN,
  DEFAULT_TARGET_URL: `http://127.0.0.1:${dummyPort}`
};
const cp = createControlPlaneServer({ config: cpCfg });
const cpPort = await listen(cp);

try {
  // Inject simulated database failure and trigger a request through the Edge middleware.
  failMode = "database";
  setMockScenario("database_failure");

  const clientRes = await fetch(`http://127.0.0.1:${mwPort}/users`);
  console.log(`[demo] Client GET /users via Edge -> HTTP ${clientRes.status}`);

  await new Promise(r => setTimeout(r, 150));

  const feedRes = await fetch(`http://127.0.0.1:${cpPort}/api/incidents`);
  const feed = await feedRes.json();
  const latest = feed.incidents[0];
  console.log(`[demo] Incident diagnosed: severity=${latest.analysis.severity} confidence=${latest.analysis.confidence} escalate=${latest.analysis.escalate}`);
  console.log(`[demo] Root cause: ${latest.analysis.rootCause.summary}`);
  console.log(`[demo] Top code match: ${latest.analysis.codeFindings[0]?.file}:${latest.analysis.codeFindings[0]?.line}`);
} finally {
  setMockScenario("normal");
  await Promise.all([close(cp), close(mw), close(core), close(connector), close(dummy)]);
}
