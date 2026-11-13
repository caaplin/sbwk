import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { mockCheck } from "../mock.mjs";
import { validateContract, inspectService, isSafeDiagnosticPath } from "../adapters.mjs";
import { createConnectorServer } from "../server.mjs";

function listen(srv) {
  return new Promise(resolve => srv.listen(0, "127.0.0.1", () => resolve(srv.address().port)));
}
function close(srv) {
  return new Promise(resolve => srv.close(() => resolve()));
}

test("validateContract enforces inner structure of health, metrics, and logs", () => {
  assert.equal(validateContract("health", { status: "healthy", checks: { db: "healthy" } }), null);
  assert.match(validateContract("health", { status: "healthy", checks: null }), /checks/);
  assert.match(validateContract("health", { status: "healthy", checks: { db: 123 } }), /invalid status/);
  assert.match(validateContract("metrics", { metrics: [1, 2, 3] }), /plain object/);
  assert.match(validateContract("metrics", { metrics: { bad: { nested: 1 } } }), /finite number/);
  assert.equal(validateContract("metrics", { metrics: { pool: 80, ok: true } }), null);
  assert.match(validateContract("logs", { logs: [{ level: "error" }] }), /message/);
  assert.equal(validateContract("logs", { logs: [{ level: "error", message: "timeout" }] }), null);
});

test("mockCheck handles unknown service without throwing", () => {
  const res = mockCheck("nonexistent", "health");
  assert.equal(res.status, "unknown");
  assert.equal(res.error.code, "INVALID_ARGUMENTS");
});

test("isSafeDiagnosticPath blocks full URLs, protocol-relative URLs, and .. traversal", () => {
  assert.equal(isSafeDiagnosticPath("/internal/health"), true);
  assert.equal(isSafeDiagnosticPath("https://evil.example/health"), false);
  assert.equal(isSafeDiagnosticPath("//evil.example/health"), false);
  assert.equal(isSafeDiagnosticPath("/internal/../../etc/passwd"), false);
});

test("live HTTP timeout normalizes AbortError to TIMEOUT", async () => {
  const slowServer = http.createServer((_req, res) => {
    setTimeout(() => { res.writeHead(200); res.end("{}"); }, 300);
  });
  const port = await listen(slowServer);
  try {
    const cfg = {
      CONNECTOR_MODE: "live",
      REQUEST_TIMEOUT_MS: 40,
      services: {
        database: { baseUrl: `http://127.0.0.1:${port}`, paths: { health: "/health", metrics: "/metrics", logs: "/logs" } }
      }
    };
    const res = await inspectService("database", "health", cfg);
    assert.equal(res.status, "unreachable");
    assert.equal(res.error.code, "TIMEOUT");
  } finally {
    await close(slowServer);
  }
});

test("live TCP probe verifies real non-HTTP database port availability", async () => {
  const tcpDb = net.createServer(sock => sock.end());
  const port = await listen(tcpDb);
  try {
    const cfg = {
      CONNECTOR_MODE: "live",
      REQUEST_TIMEOUT_MS: 500,
      services: {
        database: { tcpEndpoint: `postgres://readonly:secret@127.0.0.1:${port}/app`, paths: { health: "/h", metrics: "/m", logs: "/l" } }
      }
    };
    const okHealth = await inspectService("database", "health", cfg);
    assert.equal(okHealth.status, "healthy");
    assert.equal(okHealth.data.checks.tcp_connectivity, "healthy");

    await close(tcpDb);
    const downHealth = await inspectService("database", "health", cfg);
    assert.equal(downHealth.status, "unreachable");
  } finally {
    try { await close(tcpDb); } catch { /* already closed */ }
  }
});

test("/connector/config validates paths and baseUrls against SSRF/traversal", async () => {
  const cfg = {
    NODE_ENV: "test",
    CONNECTOR_API_TOKEN: "test-token",
    CONNECTOR_MODE: "mock",
    REQUEST_TIMEOUT_MS: 1000,
    RATE_LIMIT_PER_MIN: 180,
    MAX_BATCH_CONCURRENCY: 4,
    services: {
      database: { baseUrl: undefined, tcpEndpoint: undefined, token: undefined, paths: { health: "/h", metrics: "/m", logs: "/l" } },
      auth: { baseUrl: undefined, tcpEndpoint: undefined, token: undefined, paths: { health: "/h", metrics: "/m", logs: "/l" } },
      external_api: { baseUrl: undefined, tcpEndpoint: undefined, token: undefined, paths: { health: "/h", metrics: "/m", logs: "/l" } }
    }
  };
  const srv = createConnectorServer(cfg);
  const port = await listen(srv);
  try {
    const badPath = await fetch(`http://127.0.0.1:${port}/connector/config`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ services: { auth: { paths: { logs: "http://169.254.169.254/latest/meta-data" } } } })
    });
    assert.equal(badPath.status, 400);

    const goodTcp = await fetch(`http://127.0.0.1:${port}/connector/config`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ services: { database: { tcpEndpoint: "postgres://127.0.0.1:5432/db" } } })
    });
    assert.equal(goodTcp.status, 200);
    const data = await goodTcp.json();
    assert.equal(data.services.database.configured, true);
    assert.equal(data.services.database.protocol, "tcp");
  } finally {
    await close(srv);
  }
});
