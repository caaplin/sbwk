// Zero-dependency config for the onboarding control plane.
import fs from "node:fs";

try {
  const txt = fs.readFileSync(new URL("./.env", import.meta.url), "utf8");
  for (const line of txt.split("\n")) {
    const m = line.match(/^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  }
} catch { /* no .env */ }

const env = process.env;
const num = (v, d) => (Number.isFinite(Number(v)) ? Number(v) : d);
const str = (v, d) => (v && v.trim() ? v : d);

export const config = {
  NODE_ENV: str(env.NODE_ENV, "development"),
  PORT: num(env.PORT, 4300),
  DATA_DIR: str(env.DATA_DIR, undefined),
  REQUEST_TIMEOUT_MS: num(env.REQUEST_TIMEOUT_MS, 6000),
  GITHUB_API_BASE: str(env.GITHUB_API_BASE, "https://api.github.com"),
  GITHUB_TOKEN: str(env.GITHUB_TOKEN, ""),
  GITHUB_REPO: str(env.GITHUB_REPO, ""),
	CONTROL_PLANE_PASSWORD: str(env.CONTROL_PLANE_PASSWORD, ""),

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
