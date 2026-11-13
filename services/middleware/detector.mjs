// Pure anomaly-detection, redaction, rate-limiting and throttling helpers (no dependencies).

export function classifyStatus(statusCode, minStatus) {
  if (statusCode >= 500) return { detect: statusCode >= minStatus, category: "server_error", reason: `Upstream returned server error HTTP ${statusCode}` };
  if (statusCode >= 400) return { detect: statusCode >= minStatus, category: "client_error", reason: `Upstream returned client error HTTP ${statusCode}` };
  return { detect: false, category: "server_error", reason: "Normal response" };
}

export function categoryForUpstreamError(code) {
  return code === "TIMEOUT" ? "timeout" : "upstream_unreachable";
}

export function sanitizeIp(raw) {
  if (typeof raw !== "string") return undefined;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 64) return "unknown";
  // Allow valid IPv4, IPv6, and IPv4-mapped IPv6 characters only (blocks header/prompt injection).
  return /^[0-9a-fA-F:.%]+$/.test(trimmed) ? trimmed : "unknown";
}

/**
 * Redacts credentials, bearer tokens, JWTs, API keys, connection-string passwords,
 * cookies, and emails from captured upstream response bodies / query strings while
 * preserving diagnostic error messages and stack traces.
 */
export function redactSensitive(text) {
  if (typeof text !== "string" || !text) return text;
  return text
    // Connection string credentials: postgres://user:pass@host -> postgres://[REDACTED]@host
    .replace(/([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([^/\s:@]+:[^/\s@]+)@/g, "$1[REDACTED]@")
    // Authorization / Bearer headers
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, "$1 [REDACTED]")
    // JWT tokens (3 base64url segments starting with eyJ)
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[REDACTED_JWT]")
    // Common provider PATs & API keys (GitHub, Groq, OpenAI, Slack, AWS)
    .replace(/\b(github_pat_[A-Za-z0-9_]{16,}|gh[pousr]_[A-Za-z0-9_]{16,}|gsk_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b/g, "[REDACTED_KEY]")
    // JSON key-value secrets: "password": "...", "api_key": "...", etc.
    .replace(/("(?:password|passwd|secret|client_secret|api_key|apiKey|apikey|access_token|refresh_token|id_token|token|authorization|cookie|set-cookie)"\s*:\s*)"[^"]*"/gi, '$1"[REDACTED]"')
    // URL query / form secrets: token=...&
    .replace(/(\b(?:password|passwd|secret|api_key|apikey|access_token|refresh_token|token|sig|signature)=)[^&\s"']+/gi, "$1[REDACTED]")
    // Email addresses (PII)
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, "[REDACTED_EMAIL]");
}

export class DispatchThrottle {
  constructor(cooldownMs) { this.cooldownMs = cooldownMs; this.last = new Map(); }
  static key(i) {
    return i.category ? `${i.method} ${i.path} ${i.statusCode} ${i.category}` : `${i.method} ${i.path} ${i.statusCode}`;
  }
  shouldDispatch(i, now = Date.now()) {
    const key = DispatchThrottle.key(i);
    const prev = this.last.get(key);
    if (prev !== undefined && now - prev < this.cooldownMs) return false;
    this.last.set(key, now);
    if (this.last.size > 1000) for (const [k, t] of this.last) if (now - t >= this.cooldownMs) this.last.delete(k);
    return true;
  }
  release(i) {
    this.last.delete(DispatchThrottle.key(i));
  }
}

export class RateLimiter {
  constructor(maxPerWindow, windowMs = 60000, maxKeys = 5000) {
    this.max = maxPerWindow;
    this.windowMs = windowMs;
    this.maxKeys = maxKeys;
    this.buckets = new Map();
  }
  allow(key, now = Date.now()) {
    if (!this.max || this.max <= 0) return true;
    const k = key || "global";
    let b = this.buckets.get(k);
    if (!b || now - b.start >= this.windowMs) {
      b = { start: now, count: 0 };
      this.buckets.set(k, b);
    }
    b.count += 1;
    if (this.buckets.size > this.maxKeys) {
      for (const [ek, eb] of this.buckets) if (now - eb.start >= this.windowMs) this.buckets.delete(ek);
      if (this.buckets.size > this.maxKeys) this.buckets.delete(this.buckets.keys().next().value);
    }
    return b.count <= this.max;
  }
}

export function buildIncident(input) {
  const idx = input.url.indexOf("?");
  const path = idx === -1 ? input.url : input.url.slice(0, idx);
  const rawQuery = idx === -1 ? "" : input.url.slice(idx + 1);
  const redact = input.redact !== false;
  const query = rawQuery ? (redact ? redactSensitive(rawQuery) : rawQuery) : "";
  const sample = input.responseSample
    ? (redact ? redactSensitive(input.responseSample) : input.responseSample)
    : undefined;
  const cleanUa = typeof input.userAgent === "string"
    ? input.userAgent.replace(/[\r\n\x00-\x1f\x7f]/g, " ").slice(0, 256)
    : undefined;
  return {
    id: input.id,
    requestId: input.requestId,
    source: "middleware",
    detectedAt: new Date().toISOString(),
    method: input.method,
    path,
    query: query || undefined,
    statusCode: input.statusCode,
    durationMs: Math.round(input.durationMs * 100) / 100,
    upstream: input.upstream,
    category: input.category,
    reason: input.reason,
    responseSample: sample || undefined,
    clientIp: input.clientIp !== undefined ? sanitizeIp(input.clientIp) : undefined,
    userAgent: cleanUa,
    error: input.error
  };
}
