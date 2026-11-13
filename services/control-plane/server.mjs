// Zero-dependency onboarding control plane. Serves the UI and makes every
// onboarding step real: gateway healthcheck, external connection tests, optional GitHub
// repo + last-5-commits link, safety limits, request logs, and AI incident feed.
import http from "node:http";
import fs from "node:fs";
import { config } from "./config.mjs";
import * as store from "./store.mjs";
import { ensureWritableDataDir } from "./preflight.mjs";
import { checkReachability, fetchGitHubRepo } from "./checks.mjs";
import { applyGateway, applyExternal, applyCodebase, applySafety, applyMonitoring, serviceHealth } from "./apply.mjs";
import { saveConfig } from "./config-service.mjs";
import { initAuth, verifyPassword, createSession, destroySession, sessionFromRequest, sessionCookie, clearCookie } from "./auth.mjs";
import { getAiConfig, saveAiConfig, runPromptTest } from "./ai.mjs";
import { fetchGitStatus, rollbackToParent } from "./git-service.mjs";

// Make the mounted DATA_DIR usable before anything tries to write to it. The
// Docker entrypoint normally did this already (as root, before dropping to node);
// this covers `node server.mjs` and containers started as a non-root user.
const dataDirStatus = ensureWritableDataDir(config.DATA_DIR);
store.load();
initAuth();

const log = (level, event, fields = {}) => console.log(JSON.stringify({ level, event, service: "control-plane", timestamp: new Date().toISOString(), ...fields }));
function sendJson(res, status, obj) { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); }
const ok = (res, obj) => sendJson(res, 200, { success: true, ...obj });
const fail = (res, status, message) => sendJson(res, status, { success: false, error: message });

function readJson(req, limit = 65536) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", c => { size += c.length; if (size > limit) { reject(new Error("body too large")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {}); } catch { reject(new Error("invalid JSON")); } });
    req.on("error", reject);
  });
}

const indexHtml = fs.readFileSync(new URL("./public/index.html", import.meta.url), "utf8");
const loginHtml = fs.readFileSync(new URL("./public/login.html", import.meta.url), "utf8");

// --- login rate limit (per-IP, fixed window) -------------------------------
const LOGIN_WINDOW_MS = 60_000;
const LOGIN_MAX_FAILURES = 5;
const loginFailures = new Map(); // ip -> { count, resetAt }
function clientIp(req) { return req.socket.remoteAddress || "unknown"; }
function loginLimited(ip) {
  const entry = loginFailures.get(ip);
  if (!entry) return false;
  if (entry.resetAt < Date.now()) { loginFailures.delete(ip); return false; }
  return entry.count >= LOGIN_MAX_FAILURES;
}
function recordLoginFailure(ip) {
  const now = Date.now();
  const entry = loginFailures.get(ip);
  if (!entry || entry.resetAt < now) loginFailures.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
  else entry.count += 1;
}
function clearLoginFailures(ip) { loginFailures.delete(ip); }

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  const p = url.pathname;
  try {
    // ---- public routes ---------------------------------------------------
    if (p === "/login" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      return res.end(loginHtml);
    }
    if (p === "/api/login" && req.method === "POST") {
      const ip = clientIp(req);
      if (loginLimited(ip)) {
        log("warn", "login_rate_limited", { ip });
        return fail(res, 429, "too many attempts, try again in a minute");
      }
      const body = await readJson(req);
      // small constant delay regardless of outcome to blunt timing-based enumeration
      await new Promise(r => setTimeout(r, 150));
      if (!verifyPassword(body.password)) {
        recordLoginFailure(ip);
        log("warn", "login_failed", { ip });
        return fail(res, 401, "invalid password");
      }
      clearLoginFailures(ip);
      const token = createSession();
      const secure = req.socket.encrypted || config.NODE_ENV === "production";
      res.writeHead(200, { "Content-Type": "application/json", "Set-Cookie": sessionCookie(token, { secure }) });
      return res.end(JSON.stringify({ success: true }));
    }
    if (p === "/api/logout" && req.method === "POST") {
      const s = sessionFromRequest(req);
      if (s) destroySession(s.token);
      res.writeHead(200, { "Content-Type": "application/json", "Set-Cookie": clearCookie() });
      return res.end(JSON.stringify({ success: true }));
    }
    if (p === "/health" && req.method === "GET") {
      return ok(res, { status: "up" });
    }

    // ---- everything else requires a session -----------------------------
    const session = sessionFromRequest(req);
    if (!session) {
      if (p.startsWith("/api/")) return fail(res, 401, "authentication required");
      res.writeHead(302, { Location: "/login" });
      return res.end();
    }

    if (req.method === "GET" && (p === "/" || p === "/index.html")) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      return res.end(indexHtml);
    }

    if (p === "/api/state" && req.method === "GET") {
      return ok(res, {
        state: store.redacted(),
        services: await serviceHealth(),
        // "ok" | "reclaimed" | "readonly" | "disabled" — "readonly" means saves
        // will fail and the container needs its DATA_DIR chown (see README).
        dataDir: { path: config.DATA_DIR || null, status: dataDirStatus, writable: dataDirStatus !== "readonly" }
      });
    }

    // Atomic config save (the form in the Config tab). This route was missing:
    // the UI has always posted here, while only the per-step routes existed, so
    // "Save config" answered 404. saveConfig() validates everything first and
    // reports partial pushes instead of rolling back.
    if (p === "/api/config" && req.method === "POST") {
      const body = await readJson(req);
      const result = await saveConfig(body);
      log(result.body?.success ? "info" : "warn", "config_save", {
        status: result.status,
        partial: result.body?.partial,
        warnings: result.body?.warnings?.length || 0,
      });
      return sendJson(res, result.status, result.body);
    }

    // STEP 01 — Gateway
    if (p === "/api/gateway" && req.method === "POST") {
      const body = await readJson(req);
      if (!body.targetUrl) return fail(res, 400, "targetUrl is required");
      try { new URL(body.targetUrl); } catch { return fail(res, 400, "targetUrl must be a valid URL"); }
      store.patch("gateway", { targetUrl: body.targetUrl, port: Number(body.port) || 8080 });
      const apply = await applyGateway(store.get());
      log("info", "gateway_configured", { targetUrl: body.targetUrl, apply });
      return ok(res, { gateway: store.get().gateway, apply });
    }
    if (p === "/api/gateway/check" && req.method === "POST") {
      const target = store.get().gateway.targetUrl;
      const check = await checkReachability(target);
      // Label honestly: this probes the target from the control plane's network,
      // not from (or through) the edge container.
      const enriched = {
        ...check,
        probe: "target-server",
        note: "Probed the target URL from this control plane's network. Does not verify the edge container is routing traffic.",
        at: new Date().toISOString(),
      };
      store.patch("gateway", { lastCheck: enriched });
      return ok(res, { check: enriched });
    }

    // STEP 02 — External access
    if (p === "/api/external" && req.method === "POST") {
      const body = await readJson(req);
      store.patch("external", {
        authEndpoint: body.authEndpoint || "",
        databaseEndpoint: body.databaseEndpoint || "",
        ...(typeof body.apiKey === "string" && body.apiKey ? { apiKey: body.apiKey } : {}),
      });
      return ok(res, { external: store.redacted().external });
    }
    if (p === "/api/external/test" && req.method === "POST") {
      const ext = store.get().external;
      const [auth, database] = await Promise.all([
        ext.authEndpoint ? checkReachability(ext.authEndpoint, { token: ext.apiKey }) : { ok: false, reachable: false, error: "not configured" },
        ext.databaseEndpoint ? checkReachability(ext.databaseEndpoint) : { ok: false, reachable: false, error: "not configured" },
      ]);
      const reachable = [auth, database].filter(r => r.reachable).length;

      const warnings = [];
      if (database.reachable && database.method === "dns") {
        warnings.push(`${new URL(ext.databaseEndpoint).protocol} endpoint is DNS-reachable only; connector does not monitor it.`);
      }
      if (auth.reachable && auth.method === "http") {
        warnings.push("Auth check accepts any HTTP response (including 401/403); a wrong key can still show reachable.");
      }

      store.patch("external", { lastTest: { auth, database, reachable, warnings, at: new Date().toISOString() } });
      const apply = await applyExternal(store.get());
      return ok(res, {
        auth,
        database,
        reachable,
        total: 2,
        warnings,
        connectorApplied: !apply?.skipped,
        apply,
      });
    }

    // STEP 03 — Codebase link (Non-compulsory: empty repoUrl clears/skips Git integration)
    if (p === "/api/codebase" && req.method === "POST") {
      const body = await readJson(req);
      if (!body.repoUrl || !String(body.repoUrl).trim()) {
        store.patch("codebase", { repoUrl: "", fullName: "", commits: [], connectedAt: null, token: "" });
        const apply = await applyCodebase(store.get());
        log("info", "codebase_skipped_or_cleared", { apply });
        return ok(res, { skipped: true, codebase: { fullName: null, repoUrl: null, commits: [] }, apply });
      }
      let repo;
      try { repo = await fetchGitHubRepo(body.repoUrl, body.token); }
      catch (e) { return fail(res, 400, e.message); }
      // If no new token supplied, clear the old one — prevents a public repo link
      // from silently reusing a previously stored token.
      const tokenPatch = body.token ? { token: body.token } : { token: "" };
      store.patch("codebase", {
        repoUrl: repo.repoUrl,
        fullName: repo.fullName,
        commits: repo.commits,
        connectedAt: new Date().toISOString(),
        ...tokenPatch,
      });
      const apply = await applyCodebase(store.get());
      log("info", "codebase_linked", { fullName: repo.fullName, commits: repo.commits.length, tokenRotated: Boolean(body.token), apply });
      return ok(res, {
        codebase: { fullName: repo.fullName, repoUrl: repo.repoUrl, defaultBranch: repo.defaultBranch, commits: repo.commits },
        apply,
      });
    }

    // Git Branches tab — status, last 4 diffs, feed to agent, and rollback
    if (p === "/api/git/status" && req.method === "GET") {
      const state = store.get();
      const repoUrl = state.codebase?.repoUrl || config.GITHUB_REPO;
      const token = state.codebase?.githubToken || config.GITHUB_TOKEN;
      if (!repoUrl || !token) {
        return ok(res, { configured: false });
      }
      const status = await fetchGitStatus(repoUrl, token);
      return ok(res, status);
    }

    if (p === "/api/git/feed-agent" && req.method === "POST") {
      const state = store.get();
      const repoUrl = state.codebase?.repoUrl || config.GITHUB_REPO;
      const token = state.codebase?.githubToken || config.GITHUB_TOKEN;
      if (!repoUrl || !token) {
        return fail(res, 400, "GitHub repository URL and PAT must be configured first");
      }
      const status = await fetchGitStatus(repoUrl, token);
      if (!status.ok) return fail(res, 502, status.error || "Failed to fetch git diffs");
      const r = await fetch(`${config.AGENT_CORE_URL}/git-context`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${config.AGENT_CORE_TOKEN}`
        },
        body: JSON.stringify({
          repoUrl,
          fullName: status.repo?.fullName,
          branch: status.repo?.defaultBranch,
          diffs: status.diffs
        })
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) return fail(res, 502, data.error?.message || "Failed to feed diffs to agent-core");
      return ok(res, { fedCount: status.diffs.length, branch: status.repo?.defaultBranch });
    }

    if (p === "/api/git/rollback" && req.method === "POST") {
      const state = store.get();
      const repoUrl = state.codebase?.repoUrl || config.GITHUB_REPO;
      const token = state.codebase?.githubToken || config.GITHUB_TOKEN;
      if (!repoUrl || !token) {
        return fail(res, 400, "GitHub repository URL and PAT must be configured first");
      }
      const body = await readJson(req);
      const targetSha = body.targetSha;
      const branch = body.branch || state.codebase?.defaultBranch || "main";
      if (!targetSha) return fail(res, 400, "targetSha is required");
      const result = await rollbackToParent(repoUrl, token, targetSha, branch);
      if (!result.ok) return fail(res, 400, result.error || "Rollback failed");
      return ok(res, result);
    }

    // STEP 04 — Safety limits
    if (p === "/api/safety" && req.method === "POST") {
      const body = await readJson(req);
      const patch = {};
      if (typeof body.dryRun === "boolean") patch.dryRun = body.dryRun;
      if (typeof body.autoRollback === "boolean") patch.autoRollback = body.autoRollback;
      if (body.escalationThreshold !== undefined) {
        const n = Number(body.escalationThreshold);
        if (!Number.isFinite(n) || n < 0 || n > 1) return fail(res, 400, "escalationThreshold must be a number in [0,1]");
        patch.escalationThreshold = n;
      }
      store.patch("safety", patch);
      const apply = await applySafety(store.get());
      log("info", "safety_updated", { patch, apply });
      return ok(res, { safety: store.get().safety, apply });
    }

    // Monitoring switch
    if (p === "/api/monitoring/start" && req.method === "POST") {
      store.patch("monitoring", { active: true, startedAt: new Date().toISOString() });
      const apply = await applyMonitoring(true);
      log("info", "monitoring_started", { apply });
      return ok(res, { monitoring: store.get().monitoring, apply });
    }
    if (p === "/api/monitoring/stop" && req.method === "POST") {
      store.patch("monitoring", { active: false });
      const apply = await applyMonitoring(false);
      return ok(res, { monitoring: store.get().monitoring, apply });
    }

    // Live request logs (proxied from middleware) for the Logs tab.
    if (p === "/api/logs" && req.method === "GET") {
      const limit = Math.min(Number(url.searchParams.get("limit")) || 100, 500);
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), config.REQUEST_TIMEOUT_MS);
      try {
        const r = await fetch(`${config.MIDDLEWARE_URL}/_sbwk/logs?limit=${limit}`, {
          headers: { Authorization: `Bearer ${config.MIDDLEWARE_ADMIN_TOKEN}` },
          signal: controller.signal,
        });
        if (!r.ok) {
          return ok(res, { logs: [], unreachable: true, error: `middleware HTTP ${r.status}` });
        }
        const data = await r.json();
        return ok(res, { logs: data.logs || [] });
      } catch (e) {
        return ok(res, { logs: [], unreachable: true, error: e.name === "AbortError" ? "timeout" : "unreachable" });
      } finally { clearTimeout(t); }
    }
    if (p === "/api/logs" && req.method === "DELETE") {
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), config.REQUEST_TIMEOUT_MS);
      try {
        await fetch(`${config.MIDDLEWARE_URL}/_sbwk/logs`, {
          method: "DELETE",
          headers: { Authorization: `Bearer ${config.MIDDLEWARE_ADMIN_TOKEN}` },
          signal: controller.signal,
        });
        return ok(res, { logs: [] });
      } catch (e) {
        return ok(res, { logs: [], unreachable: true, error: e.name === "AbortError" ? "timeout" : "unreachable" });
      } finally { clearTimeout(t); }
    }

    // ── AI settings: Liquid d1 router + Groq prompt engineering ──────────────
    if (p === "/api/ai" && req.method === "GET") {
      const r = await getAiConfig();
      if (!r.ok) {
        log("warn", "ai_config_unavailable", { error: r.error });
        return ok(res, { unreachable: true, error: r.error, config: null });
      }
      return ok(res, { config: r.config });
    }
    if (p === "/api/ai" && req.method === "POST") {
      const body = await readJson(req);
      const r = await saveAiConfig(body);
      if (!r.ok) return fail(res, r.status === 0 ? 502 : r.status, r.error);
      log("info", "ai_config_saved", {
        profile: r.config?.llm?.profile,
        liquidConfigured: r.config?.liquid?.configured,
        temperature: r.config?.llm?.temperature
      });
      return ok(res, { config: r.config });
    }
    if (p === "/api/ai/test" && req.method === "POST") {
      const body = await readJson(req);
      const r = await runPromptTest(body);
      if (!r.ok) return fail(res, r.status === 0 ? 502 : r.status, r.error);
      log("info", "ai_prompt_test_run", {
        incidentId: r.incident?.incident?.id,
        route: r.incident?.analysis?.routing?.route,
        mode: r.incident?.analysis?.mode
      });
      return ok(res, { incident: r.incident });
    }

    // Live incident & AI analysis feed (proxied from agent-core).
    if (p === "/api/incidents" && req.method === "GET") {
      const limit = Math.min(Number(url.searchParams.get("limit")) || 25, 100);
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), config.REQUEST_TIMEOUT_MS);
      try {
        const r = await fetch(`${config.AGENT_CORE_URL}/incidents?limit=${limit}`, {
          headers: { Authorization: `Bearer ${config.AGENT_CORE_TOKEN}` },
          signal: controller.signal,
        });
        if (!r.ok) {
          return ok(res, { incidents: [], context: {}, unreachable: true, error: `agent-core HTTP ${r.status}` });
        }
        const data = await r.json();
        return ok(res, { incidents: data.incidents || [], context: data.context || {} });
      } catch (e) {
        return ok(res, { incidents: [], context: {}, unreachable: true, error: e.name === "AbortError" ? "timeout" : "unreachable" });
      } finally { clearTimeout(t); }
    }

    return fail(res, 404, "Not found");
  } catch (e) {
    log("error", "request_failed", { path: p, error: e.message });
    return fail(res, 500, e.message);
  }
});

server.listen(config.PORT, () => log("info", "control_plane_listening", { port: config.PORT }));
function shutdown(signal) { log("info", "control_plane_shutdown", { signal }); server.close(() => process.exit(0)); setTimeout(() => process.exit(1), 5000).unref(); }
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
