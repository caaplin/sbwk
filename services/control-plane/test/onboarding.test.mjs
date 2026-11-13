import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { checkReachability, isBlockedIp } from "../checks.mjs";
import { mapExternalEndpoint, applyExternal } from "../apply.mjs";
import { createOnboardingStore } from "../store.mjs";
import { createControlPlaneServer } from "../server.mjs";

function listen(srv) {
  return new Promise(resolve => srv.listen(0, "127.0.0.1", () => resolve(srv.address().port)));
}
function close(srv) {
  return new Promise(resolve => srv.close(() => resolve()));
}

test("SSRF guard blocks cloud metadata, unspecified IPs, IPv4-mapped metadata, and non-network schemes", async () => {
  assert.equal(isBlockedIp("169.254.169.254"), true);
  assert.equal(isBlockedIp("::ffff:169.254.169.254"), true);
  assert.equal(isBlockedIp("0.0.0.0"), true);
  assert.equal(isBlockedIp("100.100.100.200"), true);
  assert.equal(isBlockedIp("127.0.0.1", { blockPrivate: false }), false);
  assert.equal(isBlockedIp("127.0.0.1", { blockPrivate: true }), true);
  assert.equal(isBlockedIp("10.1.2.3", { blockPrivate: true }), true);

  const imds = await checkReachability("http://169.254.169.254/latest/meta-data/");
  assert.equal(imds.reachable, false);
  assert.match(imds.error, /blocked/i);

  const fileUrl = await checkReachability("file:///etc/passwd");
  assert.equal(fileUrl.reachable, false);
});

test("checkReachability performs a real TCP socket probe for non-HTTP database URIs", async () => {
  const tcpServer = net.createServer(sock => sock.end());
  const port = await listen(tcpServer);

  const openRes = await checkReachability(`postgres://readonly:pw@127.0.0.1:${port}/prod`, { timeoutMs: 1000 });
  assert.equal(openRes.reachable, true);
  assert.equal(openRes.method, "tcp");

  await close(tcpServer);
  const closedRes = await checkReachability(`postgres://readonly:pw@127.0.0.1:${port}/prod`, { timeoutMs: 500 });
  assert.equal(closedRes.reachable, false);
  assert.equal(closedRes.method, "tcp");
});

test("mapExternalEndpoint and applyExternal map health/logs paths accurately and push TCP endpoints", async () => {
  // Health path is NOT mistakenly assigned to paths.logs!
  const healthMap = mapExternalEndpoint("https://auth.example.com/internal/health");
  assert.equal(healthMap.paths.health, "/internal/health");
  assert.equal(healthMap.paths.logs, "/internal/logs");

  const bareOrigin = mapExternalEndpoint("https://auth.example.com");
  assert.equal(bareOrigin.baseUrl, "https://auth.example.com");
  assert.equal(bareOrigin.paths, undefined);

  const pgMap = mapExternalEndpoint("postgres://user:pw@db.internal:5432/app");
  assert.equal(pgMap.mode, "tcp");
  assert.equal(pgMap.tcpEndpoint, "postgres://user:pw@db.internal:5432/app");

  let pushedPayload = null;
  const mockConnector = http.createServer((req, res) => {
    let b = "";
    req.on("data", c => (b += c));
    req.on("end", () => {
      pushedPayload = JSON.parse(b);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: true }));
    });
  });
  const connPort = await listen(mockConnector);
  try {
    const state = {
      external: {
        authEndpoint: "https://auth.example.com/v1/health",
        databaseEndpoint: "postgres://readonly@db.internal:5432/app",
        apiKey: "ro-key"
      }
    };
    const res = await applyExternal(state, {
      CONNECTOR_URL: `http://127.0.0.1:${connPort}`,
      CONNECTOR_API_TOKEN: "tok",
      REQUEST_TIMEOUT_MS: 2000
    });
    assert.equal(res.ok, true);
    assert.equal(pushedPayload.services.auth.paths.health, "/v1/health");
    assert.equal(pushedPayload.services.auth.paths.logs, "/v1/logs");
    assert.equal(pushedPayload.services.database.tcpEndpoint, "postgres://readonly@db.internal:5432/app");
  } finally {
    await close(mockConnector);
  }
});

test("OnboardingStore encrypts secrets at rest with AES-256-GCM and 0600 permissions", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "sbwk-cp-store-"));
  try {
    const cfg = {
      DATA_DIR: dir,
      DEFAULT_TARGET_URL: "http://localhost:8000",
      CONTROL_PLANE_SECRET: "super-strong-encryption-secret-key-0123456789",
      PERSIST_SECRETS: true
    };
    const s1 = createOnboardingStore(cfg);
    s1.patch("external", { apiKey: "my-secret-api-key" });
    s1.patch("codebase", { token: "ghp_secretGitHubToken12345" });

    const filePath = path.join(dir, "onboarding.json");
    const rawDisk = await fs.readFile(filePath, "utf8");
    const stat = await fs.stat(filePath);
    assert.equal(stat.mode & 0o777, 0o600);
    assert.ok(!rawDisk.includes("my-secret-api-key"));
    assert.ok(!rawDisk.includes("ghp_secretGitHubToken12345"));
    assert.match(rawDisk, /enc:v1:/);

    const s2 = createOnboardingStore(cfg);
    s2.load();
    assert.equal(s2.get().external.apiKey, "my-secret-api-key");
    assert.equal(s2.get().codebase.token, "ghp_secretGitHubToken12345");
    assert.equal(s2.redacted().external.apiKey, undefined);
    assert.equal(s2.redacted().external.hasApiKey, true);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("Control-plane HTTP surface enforces CSRF, SSRF on gateway, and optional CONTROL_PLANE_TOKEN", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "sbwk-cp-http-"));
  const downstreamCalls = [];
  const mockDownstream = http.createServer((req, res) => {
    let b = "";
    req.on("data", c => (b += c));
    req.on("end", () => {
      downstreamCalls.push({ method: req.method, url: req.url, body: b ? JSON.parse(b) : null });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: true }));
    });
  });
  const dsPort = await listen(mockDownstream);

  const cfg = {
    NODE_ENV: "test",
    DATA_DIR: dir,
    REQUEST_TIMEOUT_MS: 2000,
    RATE_LIMIT_PER_MIN: 120,
    CONTROL_PLANE_TOKEN: "cp-secret-token-for-testing-auth-12345",
    CONTROL_PLANE_SECRET: "cp-encryption-key-for-testing-12345678",
    PERSIST_SECRETS: true,
    BLOCK_PRIVATE_NETWORKS: false,
    SSRF_ALLOWLIST_HOSTS: "",
    ALLOWED_ORIGINS: "",
    MIDDLEWARE_URL: `http://127.0.0.1:${dsPort}`,
    MIDDLEWARE_ADMIN_TOKEN: "mw-tok",
    CONNECTOR_URL: `http://127.0.0.1:${dsPort}`,
    CONNECTOR_API_TOKEN: "conn-tok",
    AGENT_CORE_URL: `http://127.0.0.1:${dsPort}`,
    AGENT_CORE_TOKEN: "core-tok",
    DEFAULT_TARGET_URL: `http://127.0.0.1:${dsPort}`
  };
  const cp = createControlPlaneServer({ config: cfg });
  const cpPort = await listen(cp);

  try {
    // 1. Unauthenticated /api/state returns 401 when CONTROL_PLANE_TOKEN is set.
    const unauth = await fetch(`http://127.0.0.1:${cpPort}/api/state`);
    assert.equal(unauth.status, 401);

    // 2. Cross-origin POST is rejected by CSRF protection even with valid bearer token.
    const csrfRes = await fetch(`http://127.0.0.1:${cpPort}/api/safety`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${cfg.CONTROL_PLANE_TOKEN}`,
        Origin: "https://attacker.example"
      },
      body: JSON.stringify({ dryRun: true })
    });
    assert.equal(csrfRes.status, 403);

    // 3. Form-encoded POST without application/json is rejected by CSRF protection.
    const formCsrf = await fetch(`http://127.0.0.1:${cpPort}/api/safety`, {
      method: "POST",
      headers: {
        "Content-Type": "text/plain",
        Authorization: `Bearer ${cfg.CONTROL_PLANE_TOKEN}`
      },
      body: "dryRun=false"
    });
    assert.equal(formCsrf.status, 403);

    // 4. SSRF targetUrl (169.254.169.254) on /api/gateway is rejected.
    const ssrfGw = await fetch(`http://127.0.0.1:${cpPort}/api/gateway`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${cfg.CONTROL_PLANE_TOKEN}`
      },
      body: JSON.stringify({ targetUrl: "http://169.254.169.254/latest/meta-data/" })
    });
    assert.equal(ssrfGw.status, 400);

    // 5. Valid authenticated same-origin /api/gateway + /api/safety push to downstream services.
    const okGw = await fetch(`http://127.0.0.1:${cpPort}/api/gateway`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${cfg.CONTROL_PLANE_TOKEN}`,
        Origin: `http://127.0.0.1:${cpPort}`
      },
      body: JSON.stringify({ targetUrl: `http://127.0.0.1:${dsPort}`, port: 8080 })
    });
    assert.equal(okGw.status, 200);
    assert.ok(downstreamCalls.some(c => c.url === "/_sbwk/config"));
  } finally {
    await Promise.all([close(cp), close(mockDownstream)]);
    await fs.rm(dir, { recursive: true, force: true });
  }
});
