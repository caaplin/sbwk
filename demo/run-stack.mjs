// Zero-dependency local stack launcher (spawns all 5 SBWK services without Docker).
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sharedEnv = {
  ...process.env,
  NODE_ENV: process.env.NODE_ENV || "development",
  CODEBASE_PATH: process.env.CODEBASE_PATH || path.join(root, "services", "dummy-server"),
  DETECT_SLOW_MS: process.env.DETECT_SLOW_MS || "2000"
};

const services = [
  { name: "dummy-server", cwd: "services/dummy-server", port: 8000 },
  { name: "agent-connector", cwd: "services/agent-connector", port: 4100 },
  { name: "agent-core", cwd: "services/agent-core", port: 4200 },
  { name: "middleware", cwd: "services/middleware", port: 8080 },
  { name: "control-plane", cwd: "services/control-plane", port: 4300 }
];

const children = services.map(svc => {
  const child = spawn(process.execPath, ["server.mjs"], {
    cwd: path.join(root, svc.cwd),
    env: { ...sharedEnv, PORT: String(svc.port) },
    stdio: "inherit"
  });
  return child;
});

function shutdown() {
  for (const c of children) {
    try { c.kill("SIGTERM"); } catch { /* ignore */ }
  }
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
