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
  PORT: num(env.PORT, 4200),
  AGENT_CORE_TOKEN: str(env.AGENT_CORE_TOKEN, "development-only-change-this-agent-token-123456"),
  AGENT_MODE: env.AGENT_MODE === "live" ? "live" : "mock",
  GROQ_API_KEY: str(env.GROQ_API_KEY, undefined),
  GROQ_MODEL: str(env.GROQ_MODEL, "llama-3.3-70b-versatile"),
  GROQ_BASE_URL: str(env.GROQ_BASE_URL, "https://api.groq.com/openai/v1"),
  LLM_TIMEOUT_MS: num(env.LLM_TIMEOUT_MS, 20000),
  LLM_MAX_RETRIES: num(env.LLM_MAX_RETRIES, 1),
  WAIT_TIMEOUT_MS: num(env.WAIT_TIMEOUT_MS, 8000),
  RATE_LIMIT_PER_MIN: num(env.RATE_LIMIT_PER_MIN, 120),
  CONNECTOR_URL: str(env.CONNECTOR_URL, "http://localhost:4100"),
  CONNECTOR_API_TOKEN: str(env.CONNECTOR_API_TOKEN, "development-only-change-this-token-123456"),
  REQUEST_TIMEOUT_MS: num(env.REQUEST_TIMEOUT_MS, 5000),
  CODEBASE_PATH: str(env.CODEBASE_PATH, undefined),
  CODEBASE_EXCLUDE_DIRS: str(env.CODEBASE_EXCLUDE_DIRS, ""),
  CODEBASE_MAX_FILES: num(env.CODEBASE_MAX_FILES, 400),
  CODEBASE_MAX_FINDINGS: num(env.CODEBASE_MAX_FINDINGS, 6),
  MAX_CONTEXT_INCIDENTS: num(env.MAX_CONTEXT_INCIDENTS, 200),
  INCIDENT_TTL_MS: num(env.INCIDENT_TTL_MS, 0),
  DATA_DIR: str(env.DATA_DIR, undefined),
  // Unified across agent-core, control-plane, and docker-compose (80%).
  ESCALATION_CONFIDENCE_THRESHOLD: num(env.ESCALATION_CONFIDENCE_THRESHOLD, 0.8),
  NOTIFICATION_WEBHOOK_URL: str(env.NOTIFICATION_WEBHOOK_URL, undefined),
  // Safety limits (onboarding Step 04). Runtime-mutable via POST /config.
  DRY_RUN: bool(env.DRY_RUN, true),
  AUTO_ROLLBACK: bool(env.AUTO_ROLLBACK, true),
  MONITORING_ACTIVE: bool(env.MONITORING_ACTIVE, true)
};

// Runtime codebase link (onboarding Step 03): GitHub repo metadata + last commits.
// Populated by POST /config from the control plane. Never stores the access token.
config.codebase = { repoUrl: undefined, fullName: undefined, commits: [] };

export const investigateServices = str(env.INVESTIGATE_SERVICES, "database,auth,external_api")
  .split(",").map(s => s.trim())
  .filter(s => ["database", "auth", "external_api"].includes(s));

if (config.NODE_ENV === "production") {
  if (isWeakToken(config.AGENT_CORE_TOKEN)) {
    console.error("Set a strong unique AGENT_CORE_TOKEN (>= 32 high-entropy chars) before production.");
    process.exit(1);
  }
  if (isWeakToken(config.CONNECTOR_API_TOKEN)) {
    console.error("Set a strong unique CONNECTOR_API_TOKEN (>= 32 high-entropy chars) before production.");
    process.exit(1);
  }
}
