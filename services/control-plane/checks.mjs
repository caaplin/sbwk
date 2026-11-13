// Real network checks used by the onboarding UI, hardened with SSRF protections
// and real TCP/TLS + SRV probes for non-HTTP database/cache endpoints.
import dns from "node:dns/promises";
import net from "node:net";
import tls from "node:tls";
import { config as defaultConfig } from "./config.mjs";

const ALLOWED_PROTOCOLS = new Set([
  "http:", "https:",
  "postgres:", "postgresql:", "mysql:", "mariadb:",
  "redis:", "rediss:", "mongodb:", "mongodb+srv:",
  "amqp:", "amqps:"
]);

const DEFAULT_PORTS = {
  "postgres:": 5432,
  "postgresql:": 5432,
  "mysql:": 3306,
  "mariadb:": 3306,
  "redis:": 6379,
  "rediss:": 6379,
  "mongodb:": 27017,
  "mongodb+srv:": 27017,
  "amqp:": 5672,
  "amqps:": 5671
};

const METADATA_HOSTNAMES = new Set([
  "metadata.google.internal",
  "metadata.goog",
  "metadata",
  "instance-data"
]);

function ipv4Octets(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map(Number);
  return nums.every(n => Number.isInteger(n) && n >= 0 && n <= 255) ? nums : null;
}

/**
 * Checks whether a resolved IP address is blocked by SSRF policy.
 * - ALWAYS blocks cloud metadata (`169.254.0.0/16`, `100.100.100.200`), unspecified (`0.0.0.0`, `::`),
 *   link-local (`fe80::/10`), and multicast (`224.0.0.0/4`, `ff00::/8`).
 * - When `blockPrivate` is true, also blocks loopback (`127.0.0.0/8`, `::1`), RFC1918, CGNAT, and IPv6 ULA (`fc00::/7`).
 */
export function isBlockedIp(ip, { blockPrivate = false } = {}) {
  if (typeof ip !== "string" || !ip) return true;
  const norm = ip.trim().toLowerCase();

  // Unwrap IPv4-mapped IPv6 (e.g. ::ffff:169.254.169.254)
  if (norm.startsWith("::ffff:")) {
    const tail = norm.slice(7);
    if (ipv4Octets(tail)) return isBlockedIp(tail, { blockPrivate });
  }

  const v4 = ipv4Octets(norm);
  if (v4) {
    const [a, b, c, d] = v4;
    if (a === 0) return true; // 0.0.0.0/8 unspecified ("this network")
    if (a === 169 && b === 254) return true; // AWS/GCP/Azure link-local metadata
    if (a === 100 && b === 100 && c === 100 && d === 200) return true; // Alibaba Cloud metadata
    if (a >= 224) return true; // multicast & reserved
    if (blockPrivate) {
      if (a === 127) return true; // loopback
      if (a === 10) return true; // 10.0.0.0/8
      if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
      if (a === 192 && b === 168) return true; // 192.168.0.0/16
      if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
    }
    return false;
  }

  if (net.isIPv6(norm)) {
    if (norm === "::" || norm === "0:0:0:0:0:0:0:0") return true;
    if (/^fe[89ab][0-9a-f]:/.test(norm)) return true; // fe80::/10 link-local
    if (norm.startsWith("ff")) return true; // multicast
    if (blockPrivate) {
      if (norm === "::1" || norm === "0:0:0:0:0:0:0:1") return true;
      if (norm.startsWith("fc") || norm.startsWith("fd")) return true; // fc00::/7 ULA
    }
    return false;
  }

  return false;
}

function buildAllowlist(cfg) {
  const hosts = new Set(
    String(cfg.SSRF_ALLOWLIST_HOSTS || "")
      .split(",")
      .map(s => s.trim().toLowerCase())
      .filter(Boolean)
  );
  for (const raw of [cfg.DEFAULT_TARGET_URL, cfg.MIDDLEWARE_URL, cfg.AGENT_CORE_URL, cfg.CONNECTOR_URL]) {
    try { if (raw) hosts.add(new URL(raw).hostname.toLowerCase()); } catch { /* ignore */ }
  }
  return hosts;
}

/**
 * Validates URL syntax, protocol allowlist, and SSRF target restrictions (including DNS resolution).
 */
export async function validateTargetUrl(rawUrl, { httpOnly = false, cfg = defaultConfig, skipDns = false } = {}) {
  let url;
  try { url = new URL(rawUrl); } catch { return { ok: false, error: "Invalid URL" }; }

  if (httpOnly && url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, error: "URL must use http or https" };
  }
  if (!ALLOWED_PROTOCOLS.has(url.protocol)) {
    return { ok: false, error: `Unsupported URL protocol: ${url.protocol}` };
  }

  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!host) return { ok: false, error: "No host in URL" };
  if (METADATA_HOSTNAMES.has(host) || host.endsWith(".metadata.google.internal")) {
    return { ok: false, error: "Blocked metadata host" };
  }

  const allowlist = buildAllowlist(cfg);
  const blockPrivate = Boolean(cfg.BLOCK_PRIVATE_NETWORKS) && !allowlist.has(host);

  if (net.isIP(host)) {
    if (isBlockedIp(host, { blockPrivate })) {
      return { ok: false, error: "Target IP address is blocked by SSRF policy" };
    }
    return { ok: true, url, resolvedAddress: host };
  }

  if (skipDns || url.protocol === "mongodb+srv:") return { ok: true, url };

  try {
    const records = await dns.lookup(host, { all: true });
    if (!records.length) return { ok: false, error: "ENOTFOUND", dnsFailed: true };
    for (const r of records) {
      if (isBlockedIp(r.address, { blockPrivate })) {
        return { ok: false, error: "Target resolves to a blocked IP range" };
      }
    }
    return { ok: true, url, resolvedAddress: records[0].address };
  } catch (e) {
    return { ok: false, error: e.code || e.message || "DNS lookup failed", dnsFailed: true };
  }
}

async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try { return await fetch(url, { ...options, signal: controller.signal }); }
  finally { clearTimeout(t); }
}

function tcpConnect({ host, port, useTls, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    let settled = false;
    const finish = (err, val) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (err) reject(err);
      else resolve(val);
    };
    const onConnect = () => finish(null, { latencyMs: Date.now() - started });
    const socket = useTls
      ? tls.connect({ host, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false }, onConnect)
      : net.createConnection({ host, port }, onConnect);
    socket.setTimeout(timeoutMs, () => {
      const e = new Error("Timed out");
      e.code = "ETIMEDOUT";
      finish(e);
    });
    socket.on("error", err => finish(err));
  });
}

/**
 * Real reachability check:
 * - http(s): performs an actual non-redirecting HTTP GET; ANY HTTP response (even 3xx/401/404) means reachable.
 * - database/cache URIs (postgres, mysql, redis, mongodb, mongodb+srv, amqp): resolves DNS/SRV
 *   AND performs a real TCP/TLS socket connection handshake so down listeners are detected.
 */
export async function checkReachability(rawUrl, { token, timeoutMs = defaultConfig.REQUEST_TIMEOUT_MS, cfg = defaultConfig } = {}) {
  const started = Date.now();
  const v = await validateTargetUrl(rawUrl, { cfg });
  if (!v.ok) {
    return {
      ok: false,
      reachable: false,
      ...(v.dnsFailed ? { method: "dns" } : {}),
      error: v.error,
      latencyMs: Date.now() - started
    };
  }
  const { url } = v;

  if (url.protocol === "http:" || url.protocol === "https:") {
    try {
      const res = await fetchWithTimeout(
        url.toString(),
        { method: "GET", redirect: "manual", headers: token ? { Authorization: `Bearer ${token}` } : {} },
        timeoutMs
      );
      return { ok: true, reachable: true, method: "http", status: res.status, latencyMs: Date.now() - started };
    } catch (e) {
      return { ok: false, reachable: false, method: "http", error: e.name === "AbortError" ? "Timed out" : (e.cause?.code || e.message || "Unreachable"), latencyMs: Date.now() - started };
    }
  }

  // Non-HTTP: resolve SRV (for mongodb+srv) + validate target IPs + real TCP/TLS port handshake.
  let targetHost = url.hostname.replace(/^\[|\]$/g, "");
  let targetPort = Number(url.port) || DEFAULT_PORTS[url.protocol] || 0;
  const sslParam = url.searchParams.get("ssl") || url.searchParams.get("tls");
  const useTls = url.protocol === "rediss:" || url.protocol === "amqps:" || url.protocol === "mongodb+srv:" || sslParam === "true" || sslParam === "1";

  try {
    if (url.protocol === "mongodb+srv:") {
      const srv = await dns.resolveSrv(`_mongodb._tcp.${targetHost}`);
      if (!srv.length) return { ok: false, reachable: false, method: "srv", error: "No SRV records found", latencyMs: Date.now() - started };
      targetHost = srv[0].name;
      targetPort = srv[0].port || 27017;
      const srvCheck = await validateTargetUrl(`mongodb://${targetHost}:${targetPort}`, { cfg });
      if (!srvCheck.ok) return { ok: false, reachable: false, method: "tcp", error: srvCheck.error, latencyMs: Date.now() - started };
    }

    if (!targetPort) return { ok: false, reachable: false, method: "tcp", error: "No port specified for non-HTTP endpoint", latencyMs: Date.now() - started };

    await tcpConnect({ host: targetHost, port: targetPort, useTls, timeoutMs });
    return {
      ok: true,
      reachable: true,
      method: useTls ? "tls" : "tcp",
      address: v.resolvedAddress || targetHost,
      port: targetPort,
      latencyMs: Date.now() - started,
      note: `${url.protocol} verified via ${useTls ? "TLS" : "TCP"} socket handshake on port ${targetPort}`
    };
  } catch (e) {
    return {
      ok: false,
      reachable: false,
      method: useTls ? "tls" : "tcp",
      error: e.code === "ETIMEDOUT" ? "Timed out" : (e.code || e.message || "TCP connection failed"),
      latencyMs: Date.now() - started
    };
  }
}

/** Parse owner/repo from a GitHub URL, git remote, or "owner/repo" shorthand. */
export function parseRepoUrl(input) {
  if (!input || typeof input !== "string") return null;
  const s = input.trim().replace(/\.git$/, "");
  let m = s.match(/github\.com[/:]([^/\s]+)\/([^/\s]+)$/i);
  if (m) return { owner: m[1], repo: m[2] };
  m = s.match(/^([^/\s:@]+)\/([^/\s:@]+)$/);
  if (m) return { owner: m[1], repo: m[2] };
  return null;
}

/** Fetch real repository metadata + the last 5 commits from the GitHub API. */
export async function fetchGitHubRepo(repoUrl, token, { timeoutMs = defaultConfig.REQUEST_TIMEOUT_MS, cfg = defaultConfig } = {}) {
  const parsed = parseRepoUrl(repoUrl);
  if (!parsed) throw new Error("Could not parse repository URL (expected https://github.com/owner/repo)");
  const { owner, repo } = parsed;
  if (!/^[A-Za-z0-9_.-]{1,100}$/.test(owner) || !/^[A-Za-z0-9_.-]{1,100}$/.test(repo)) {
    throw new Error("Invalid GitHub owner or repository name");
  }
  const headers = { Accept: "application/vnd.github+json", "User-Agent": "sbwk-control-plane", "X-GitHub-Api-Version": "2022-11-28" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const base = `${cfg.GITHUB_API_BASE.replace(/\/$/, "")}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;

  const metaRes = await fetchWithTimeout(base, { headers }, timeoutMs);
  if (metaRes.status === 404) throw new Error("Repository not found, or the token lacks access");
  if (metaRes.status === 401) throw new Error("Invalid or expired access token");
  if (metaRes.status === 403) throw new Error("GitHub API forbidden or rate-limited");
  if (!metaRes.ok) throw new Error(`GitHub returned HTTP ${metaRes.status}`);
  const meta = await metaRes.json();

  const commitsRes = await fetchWithTimeout(`${base}/commits?per_page=5`, { headers }, timeoutMs);
  if (!commitsRes.ok) throw new Error(`Could not read commits (HTTP ${commitsRes.status})`);
  const rawCommits = await commitsRes.json();
  const commits = (Array.isArray(rawCommits) ? rawCommits : []).slice(0, 5).map(c => ({
    sha: c.sha,
    message: c.commit?.message || "",
    author: c.author?.login || c.commit?.author?.name || "unknown",
    date: c.commit?.author?.date || null,
    url: typeof c.html_url === "string" && c.html_url.startsWith("https://") ? c.html_url : null
  }));

  return { fullName: meta.full_name, repoUrl: meta.html_url || repoUrl, defaultBranch: meta.default_branch, private: meta.private, description: meta.description || "", commits };
}
