// Zero-dependency config. Loads service .env and repo-root .env (KEY=VALUE) if present.
import fs from "node:fs";

function loadEnvFile(relPath) {
  try {
    const txt = fs.readFileSync(new URL(relPath, import.meta.url), "utf8");
    for (const rawLine of txt.split(/\r?\n/)) {
      const trimmed = rawLine.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const m = trimmed.match(/^([A-Za-z0-9_]+)\s*=\s*(.*)$/);
      if (!m || process.env[m[1]] !== undefined) continue;
      let val = m[2].trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      } else {
        val = val.replace(/\s+#.*$/, "").trim();
      }
      process.env[m[1]] = val;
    }
  } catch { /* optional .env */ }
}

loadEnvFile("./.env");
loadEnvFile("../../.env");

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

function resolveLlmConfig() {
  const groqKey = str(env.GROQ_API_KEY, undefined);
  const openaiKey = str(env.OPENAI_API_KEY, undefined);
  const openrouterKey = str(env.OPENROUTER_API_KEY, undefined);
  const genericKey = str(env.LLM_API_KEY, undefined);
  const apiKey = groqKey || genericKey || openaiKey || openrouterKey;

  const explicitBase = str(env.LLM_BASE_URL, str(env.GROQ_BASE_URL, str(env.OPENAI_BASE_URL, undefined)));
  const explicitModel = str(env.LLM_MODEL, str(env.GROQ_MODEL, str(env.OPENAI_MODEL, undefined)));

  if (!groqKey && (openrouterKey || (apiKey && apiKey.startsWith("sk-or-")))) {
    return {
      apiKey,
      baseUrl: explicitBase || "https://openrouter.ai/api/v1",
      model: explicitModel || "meta-llama/llama-3.3-70b-instruct"
    };
  }
  if (!groqKey && (openaiKey || (apiKey && apiKey.startsWith("sk-") && !apiKey.startsWith("gsk_")))) {
    return {
      apiKey,
      baseUrl: explicitBase || "https://api.openai.com/v1",
      model: explicitModel || "gpt-4o-mini"
    };
  }
  return {
    apiKey,
    baseUrl: explicitBase || "https://api.groq.com/openai/v1",
    model: explicitModel || "llama-3.3-70b-versatile"
  };
}

const llm = resolveLlmConfig();
const rawAgentMode = str(env.AGENT_MODE, undefined)?.toLowerCase();
// Auto-enable "live" if an LLM API key is provided and AGENT_MODE wasn't explicitly set to "mock".
const resolvedAgentMode = rawAgentMode === "live"
  ? "live"
  : (rawAgentMode === "mock" ? "mock" : (llm.apiKey ? "live" : "mock"));

export const config = {
  NODE_ENV: str(env.NODE_ENV, "development"),
  PORT: num(env.PORT, 4200),
  AGENT_CORE_TOKEN: str(env.AGENT_CORE_TOKEN, "development-only-change-this-agent-token-123456"),
  AGENT_MODE: resolvedAgentMode,
  GROQ_API_KEY: llm.apiKey,
  GROQ_MODEL: llm.model,
  GROQ_BASE_URL: llm.baseUrl,
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
