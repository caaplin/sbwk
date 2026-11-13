// Zero-dependency config. Optionally loads a local .env (KEY=VALUE) if present.
import fs from "node:fs";

try {
  for (const rel of ["./.env", "../../.env"]) {
    try {
      const txt = fs.readFileSync(new URL(rel, import.meta.url), "utf8");
      for (const rawLine of txt.split(/\r?\n/)) {
        const trimmed = rawLine.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const m = trimmed.match(/^([A-Za-z0-9_]+)\s*=\s*(.*)$/);
        if (!m || process.env[m[1]] !== undefined) continue;
        let val = m[2].trim();
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) val = val.slice(1, -1);
        else val = val.replace(/\s+#.*$/, "").trim();
        process.env[m[1]] = val;
      }
    } catch { /* optional .env */ }
  }
} catch { /* no .env — use process.env */ }

const env = process.env;
const num = (v, d) => (v !== undefined && v !== "" && Number.isFinite(Number(v)) ? Number(v) : d);
const str = (v, d) => (v && v.trim() ? v.trim() : d);

export function isWeakToken(token) {
  if (typeof token !== "string" || token.length < 32) return true;
  const lower = token.toLowerCase();
  if (
    lower.startsWith("development-only") ||
    lower.startsWith("replace-with") ||
    lower.startsWith("replace-this") ||
    lower.includes("changeme") ||
    lower.includes("example")
  ) return true;
  if (new Set(token).size < 6) return true;
  return false;
}

function integration(prefix, defHealth, defMetrics, defLogs) {
  const rawBase = str(env[`${prefix}_BASE_URL`], undefined);
  const rawTcp = str(env[`${prefix}_TCP_ENDPOINT`], undefined);
  let baseUrl = rawBase;
  let tcpEndpoint = rawTcp;
  if (rawBase && !/^https?:\/\//i.test(rawBase)) {
    baseUrl = undefined;
    tcpEndpoint = tcpEndpoint || rawBase;
  }
  return {
    baseUrl,
    tcpEndpoint,
    token: str(env[`${prefix}_API_TOKEN`], str(env[`${prefix}_TOKEN`], undefined)),
    paths: {
      health: str(env[`${prefix}_HEALTH_PATH`], defHealth),
      metrics: str(env[`${prefix}_METRICS_PATH`], defMetrics),
      logs: str(env[`${prefix}_LOGS_PATH`], defLogs)
    }
  };
}

export const config = {
  NODE_ENV: str(env.NODE_ENV, "development"),
  PORT: num(env.PORT, 4100),
  CONNECTOR_API_TOKEN: str(env.CONNECTOR_API_TOKEN, "development-only-change-this-token-123456"),
  CONNECTOR_MODE: env.CONNECTOR_MODE === "live" ? "live" : "mock",
  REQUEST_TIMEOUT_MS: num(env.REQUEST_TIMEOUT_MS, 4000),
  RATE_LIMIT_PER_MIN: num(env.RATE_LIMIT_PER_MIN, 180),
  MAX_BATCH_CONCURRENCY: Math.min(Math.max(1, num(env.MAX_BATCH_CONCURRENCY, 4)), 12),
  services: {
    database: integration("DATABASE", "/internal/health", "/internal/metrics", "/internal/logs"),
    auth: integration("AUTH", "/internal/health", "/internal/metrics", "/internal/logs"),
    external_api: integration("EXTERNAL_API", "/health", "/metrics", "/logs")
  }
};

if (config.NODE_ENV === "production" && isWeakToken(config.CONNECTOR_API_TOKEN)) {
  console.error("Set a strong unique CONNECTOR_API_TOKEN (>= 32 high-entropy chars) before production.");
  process.exit(1);
}
