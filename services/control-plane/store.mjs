// Onboarding state persistence. Secrets are encrypted at rest (AES-256-GCM)
// when a secret key is configured, written with 0600 permissions, and NEVER
// returned by the API (see redacted()).
import fs from "node:fs";
import path from "node:path";
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import { config as defaultConfig } from "./config.mjs";

const ENC_PREFIX = "enc:v1:";
const keyCache = new Map();

function deriveKey(secret) {
  if (!secret) return null;
  let k = keyCache.get(secret);
  if (!k) {
    k = scryptSync(secret, "sbwk-onboarding-at-rest-v1", 32);
    keyCache.set(secret, k);
  }
  return k;
}

export function encryptSecret(plaintext, secret) {
  if (!plaintext) return "";
  const key = deriveKey(secret);
  if (!key) return plaintext;
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${ENC_PREFIX}${iv.toString("hex")}:${tag.toString("hex")}:${encrypted.toString("hex")}`;
}

export function decryptSecret(stored, secret) {
  if (!stored || typeof stored !== "string") return "";
  if (!stored.startsWith(ENC_PREFIX)) return stored; // legacy plaintext migration support
  const key = deriveKey(secret);
  if (!key) return "";
  try {
    const [ivHex, tagHex, dataHex] = stored.slice(ENC_PREFIX.length).split(":");
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(ivHex, "hex"));
    decipher.setAuthTag(Buffer.from(tagHex, "hex"));
    return Buffer.concat([decipher.update(Buffer.from(dataHex, "hex")), decipher.final()]).toString("utf8");
  } catch {
    return "";
  }
}

function effectiveSecret(cfg) {
  if (cfg.CONTROL_PLANE_SECRET) return cfg.CONTROL_PLANE_SECRET;
  if (cfg.AGENT_CORE_TOKEN && !cfg.AGENT_CORE_TOKEN.startsWith("development-only")) return cfg.AGENT_CORE_TOKEN;
  return cfg.AGENT_CORE_TOKEN || "sbwk-local-dev-key";
}

export function createOnboardingStore(cfg = defaultConfig) {
  const initial = () => ({
    gateway: { targetUrl: cfg.DEFAULT_TARGET_URL, port: 8080, lastCheck: null },
    external: { authEndpoint: "", databaseEndpoint: "", apiKey: "", lastTest: null },
    codebase: { repoUrl: "", fullName: "", token: "", commits: [], connectedAt: null },
    safety: { dryRun: true, autoRollback: true, escalationThreshold: 0.8 },
    monitoring: { active: true, startedAt: null }
  });

  let state = initial();
  const file = () => (cfg.DATA_DIR ? path.join(cfg.DATA_DIR, "onboarding.json") : undefined);

  function load() {
    const f = file();
    if (!f) return;
    try {
      const disk = JSON.parse(fs.readFileSync(f, "utf8"));
      const secret = effectiveSecret(cfg);
      const base = initial();
      state = {
        gateway: { ...base.gateway, ...(disk.gateway || {}) },
        external: {
          ...base.external,
          ...(disk.external || {}),
          apiKey: decryptSecret(disk.external?.apiKey || "", secret)
        },
        codebase: {
          ...base.codebase,
          ...(disk.codebase || {}),
          token: decryptSecret(disk.codebase?.token || "", secret)
        },
        safety: { ...base.safety, ...(disk.safety || {}) },
        monitoring: { ...base.monitoring, ...(disk.monitoring || {}) }
      };
    } catch { /* fresh */ }
  }

  function persist() {
    const f = file();
    if (!f) return;
    const secret = effectiveSecret(cfg);
    const persistSecrets = cfg.PERSIST_SECRETS !== false;
    const toDisk = {
      ...state,
      external: {
        ...state.external,
        apiKey: persistSecrets && state.external.apiKey ? encryptSecret(state.external.apiKey, secret) : ""
      },
      codebase: {
        ...state.codebase,
        token: persistSecrets && state.codebase.token ? encryptSecret(state.codebase.token, secret) : ""
      }
    };
    const tmp = `${f}.${process.pid}.tmp`;
    try {
      fs.mkdirSync(cfg.DATA_DIR, { recursive: true });
      fs.writeFileSync(tmp, JSON.stringify(toDisk, null, 2), { mode: 0o600 });
      fs.renameSync(tmp, f);
    } catch {
      try { fs.unlinkSync(tmp); } catch { /* ignore */ }
    }
  }

  function get() { return state; }
  function update(patchObj) { state = { ...state, ...patchObj }; persist(); return state; }
  function patch(section, value) { state[section] = { ...state[section], ...value }; persist(); return state[section]; }

  function redacted() {
    return {
      gateway: state.gateway,
      external: {
        authEndpoint: state.external.authEndpoint,
        databaseEndpoint: state.external.databaseEndpoint,
        hasApiKey: Boolean(state.external.apiKey),
        lastTest: state.external.lastTest
      },
      codebase: {
        repoUrl: state.codebase.repoUrl,
        fullName: state.codebase.fullName,
        hasToken: Boolean(state.codebase.token),
        commits: state.codebase.commits,
        connectedAt: state.codebase.connectedAt
      },
      safety: state.safety,
      monitoring: state.monitoring
    };
  }

  return { load, persist, get, update, patch, redacted };
}

const defaultStore = createOnboardingStore(defaultConfig);
export const load = () => defaultStore.load();
export const persist = () => defaultStore.persist();
export const get = () => defaultStore.get();
export const update = p => defaultStore.update(p);
export const patch = (s, v) => defaultStore.patch(s, v);
export const redacted = () => defaultStore.redacted();
