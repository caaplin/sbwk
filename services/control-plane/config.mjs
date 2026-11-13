// Zero-dependency config for the onboarding control plane.
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
  PORT: num(env.PORT, 4300),
  DATA_DIR: str(env.DATA_DIR, undefined),
  REQUEST_TIMEOUT_MS: num(env.REQUEST_TIMEOUT_MS, 6000),
  RATE_LIMIT_PER_MIN: num(env.RATE_LIMIT_PER_MIN, 120),
  GITHUB_API_BASE: str(env.GITHUB_API_BASE, "https://api.github.com"),
  // Optional bearer auth for the control-plane UI/API when exposed beyond localhost.
  CONTROL_PLANE_TOKEN: str(env.CONTROL_PLANE_TOKEN, undefined),
  // Encryption secret for sensitive tokens in onboarding.json (falls back to AGENT_CORE_TOKEN).
  CONTROL_PLANE_SECRET: str(env.CONTROL_PLANE_SECRET, undefined),
  PERSIST_SECRETS: bool(env.PERSIST_SECRETS, true),
  // SSRF / network controls. Cloud metadata & link-local IPs are ALWAYS blocked.
  BLOCK_PRIVATE_NETWORKS: bool(env.BLOCK_PRIVATE_NETWORKS, false),
  SSRF_ALLOWLIST_HOSTS: str(env.SSRF_ALLOWLIST_HOSTS, ""),
  ALLOWED_ORIGINS: str(env.ALLOWED_ORIGINS, ""),
  // Downstream services the control plane configures.
  MIDDLEWARE_URL: str(env.MIDDLEWARE_URL, "http://localhost:8080"),
  MIDDLEWARE_ADMIN_TOKEN: str(env.MIDDLEWARE_ADMIN_TOKEN, "development-only-change-this-admin-token-123456"),
  CONNECTOR_URL: str(env.CONNECTOR_URL, "http://localhost:4100"),
  CONNECTOR_API_TOKEN: str(env.CONNECTOR_API_TOKEN, "development-only-change-this-token-123456"),
  AGENT_CORE_URL: str(env.AGENT_CORE_URL, "http://localhost:4200"),
  AGENT_CORE_TOKEN: str(env.AGENT_CORE_TOKEN, "development-only-change-this-agent-token-123456"),
  // Default gateway target shown in the UI (the dummy backend).
  DEFAULT_TARGET_URL: str(env.DEFAULT_TARGET_URL, "http://localhost:8000")
};

if (config.NODE_ENV === "production") {
  if (isWeakToken(config.MIDDLEWARE_ADMIN_TOKEN)) {
    console.error("Set a strong unique MIDDLEWARE_ADMIN_TOKEN (>= 32 high-entropy chars) before production.");
    process.exit(1);
  }
  if (isWeakToken(config.CONNECTOR_API_TOKEN)) {
    console.error("Set a strong unique CONNECTOR_API_TOKEN (>= 32 high-entropy chars) before production.");
    process.exit(1);
  }
  if (isWeakToken(config.AGENT_CORE_TOKEN)) {
    console.error("Set a strong unique AGENT_CORE_TOKEN (>= 32 high-entropy chars) before production.");
    process.exit(1);
  }
  if (config.CONTROL_PLANE_TOKEN && isWeakToken(config.CONTROL_PLANE_TOKEN)) {
    console.error("CONTROL_PLANE_TOKEN must be >= 32 high-entropy chars when set in production.");
    process.exit(1);
  }
}
