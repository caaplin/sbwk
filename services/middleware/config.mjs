// Zero-dependency config. Optionally loads a local .env (KEY=VALUE) if present.
import fs from "node:fs";

try {
  const txt = fs.readFileSync(new URL("./.env", import.meta.url), "utf8");
  for (const line of txt.split("\n")) {
    const m = line.match(/^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  }
} catch { /* no .env */ }

const env = process.env;
const num = (v, d) => (v !== undefined && v !== "" && Number.isFinite(Number(v)) ? Number(v) : d);
const str = (v, d) => (v && v.trim() ? v.trim() : d);
const bool = (v, d) => (v === undefined ? d : ["true", "1", "yes", "on"].includes(String(v).toLowerCase()));

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

export const config = {
  NODE_ENV: str(env.NODE_ENV, "development"),
  PORT: num(env.PORT, 8080),
  TARGET_SERVER_URL: str(env.TARGET_SERVER_URL, "http://localhost:8000"),
  AGENT_CORE_URL: str(env.AGENT_CORE_URL, "http://localhost:4200"),
  AGENT_CORE_TOKEN: str(env.AGENT_CORE_TOKEN, "development-only-change-this-agent-token-123456"),
  MIDDLEWARE_ADMIN_TOKEN: str(env.MIDDLEWARE_ADMIN_TOKEN, "development-only-change-this-admin-token-123456"),
  DETECT_STATUS_MIN: num(env.DETECT_STATUS_MIN, 500),
  DETECT_SLOW_MS: num(env.DETECT_SLOW_MS, 0),
  DETECT_UPSTREAM_ERRORS: bool(env.DETECT_UPSTREAM_ERRORS, true),
  DISPATCH_COOLDOWN_MS: num(env.DISPATCH_COOLDOWN_MS, 15000),
  DISPATCH_TIMEOUT_MS: num(env.DISPATCH_TIMEOUT_MS, 5000),
  DISPATCH_MAX_RETRIES: num(env.DISPATCH_MAX_RETRIES, 2),
  DISPATCH_RETRY_BASE_MS: num(env.DISPATCH_RETRY_BASE_MS, 250),
  RESPONSE_SAMPLE_BYTES: num(env.RESPONSE_SAMPLE_BYTES, 2048),
  REDACT_PII: bool(env.REDACT_PII, true),
  TRUST_PROXY: bool(env.TRUST_PROXY, false),
  ADMIN_RATE_LIMIT_PER_MIN: num(env.ADMIN_RATE_LIMIT_PER_MIN, 120),
  PROXY_RATE_LIMIT_PER_MIN: num(env.PROXY_RATE_LIMIT_PER_MIN, 0),
  PROXY_TIMEOUT_MS: num(env.PROXY_TIMEOUT_MS, 30000),
  MAX_RECENT_INCIDENTS: num(env.MAX_RECENT_INCIDENTS, 200)
};

if (config.NODE_ENV === "production") {
  if (isWeakToken(config.AGENT_CORE_TOKEN)) {
    console.error("Set a strong unique AGENT_CORE_TOKEN (>= 32 high-entropy chars) before production.");
    process.exit(1);
  }
  if (isWeakToken(config.MIDDLEWARE_ADMIN_TOKEN)) {
    console.error("Set a strong unique MIDDLEWARE_ADMIN_TOKEN (>= 32 high-entropy chars) before production.");
    process.exit(1);
  }
}
