// Read-only codebase inspection. Never executes or modifies code.
import fs from "node:fs/promises";
import path from "node:path";
import { config } from "./config.mjs";

const SOURCE_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go", ".rb", ".java", ".rs", ".php", ".json", ".yml", ".yaml", ".toml", ".env", ".example"]);
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "coverage", ".next", ".cache", "vendor", "__pycache__", ".venv"]);
const MAX_FILE_BYTES = 256 * 1024;
const MAX_LINE_CHARS = 800;

const DIAGNOSTIC_VOCABULARY = [
  "database", "pool", "timeout", "connection", "auth", "token",
  "econnrefused", "etimedout", "enotfound", "econnreset",
  "null", "undefined", "query", "redis", "mongo", "mongodb",
  "postgres", "postgresql", "mysql", "sql", "deadlock", "transaction",
  "kafka", "queue", "s3", "bucket", "rate", "limit", "quota", "throttle",
  "cors", "tls", "ssl", "certificate", "memory", "oom", "permission",
  "denied", "forbidden", "unauthorized", "circuit", "upstream", "gateway",
  "external", "fetch", "socket", "webhook", "validation", "schema"
];

const STOP_WORDS = new Set([
  "error", "http", "status", "message", "failed", "failure", "request",
  "response", "server", "internal", "true", "false", "from", "with", "the", "and"
]);

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function splitIdentifier(raw) {
  return raw
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^a-zA-Z0-9]+/)
    .map(s => s.toLowerCase())
    .filter(s => s.length >= 3 && !/^\d+$/.test(s) && !STOP_WORDS.has(s));
}

export function deriveKeywords(incident) {
  const keywords = new Set();

  // 1. Route segments + camelCase/kebab-case sub-tokens.
  for (const segment of (incident.path || "").split("/")) {
    const clean = segment.replace(/[^a-zA-Z0-9_-]/g, "").toLowerCase();
    if (clean.length >= 3 && !/^\d+$/.test(clean) && !/^[0-9a-f-]{16,}$/.test(clean)) {
      keywords.add(clean);
      for (const sub of splitIdentifier(segment)) keywords.add(sub);
    }
  }

  const rawEvidence = `${incident.responseSample ?? ""} ${incident.error?.message ?? ""} ${incident.error?.code ?? ""}`;
  const evidence = rawEvidence.toLowerCase();

  // 2. Expanded diagnostic vocabulary.
  for (const term of DIAGNOSTIC_VOCABULARY) {
    if (evidence.includes(term)) keywords.add(term);
  }

  // 3. Stack-trace function/method identifiers (e.g. "at getUsersFromDatabase (server.mjs:18:11)").
  for (const m of rawEvidence.matchAll(/\bat\s+([A-Za-z_$][A-Za-z0-9_$.]{2,60})/g)) {
    const fn = m[1].split(".").pop().toLowerCase();
    if (fn && fn.length >= 3 && !STOP_WORDS.has(fn)) keywords.add(fn);
  }

  return [...keywords].slice(0, 16);
}

async function walk(root, maxFiles, extraSkipDirs) {
  const files = [];
  const stack = [root];
  while (stack.length && files.length < maxFiles) {
    const dir = stack.pop();
    let entries;
    try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      if (files.length >= maxFiles) break;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name) && !extraSkipDirs.has(entry.name)) stack.push(full);
      } else if (entry.isFile()) {
        if (entry.name.endsWith(".min.js") || entry.name.endsWith(".bundle.js")) continue;
        const ext = path.extname(entry.name).toLowerCase();
        if (SOURCE_EXTENSIONS.has(ext) || entry.name === ".env.example") files.push(full);
      }
    }
  }
  return files;
}

function isCommentLine(trimmed) {
  return trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("/*") || trimmed.startsWith("*");
}

function isDefinitionOrHandlerLine(trimmed) {
  return /\b(function|async|export|class|def|func|router|route|throw|catch)\b/.test(trimmed) ||
    /["'`]\/[a-zA-Z0-9/_-]+["'`]/.test(trimmed);
}

export function scoreContent(content, keywords, relativePath = "") {
  const lower = content.toLowerCase();
  const lines = lower.split("\n");
  const wordRegexes = keywords.map(kw => ({ kw, re: new RegExp(`\\b${escapeRegex(kw)}\\b`, "i") }));

  let bestLine = -1;
  let bestLineScore = 0;
  let fileScore = 0;
  const matched = new Set();

  const lowerPath = relativePath.toLowerCase();
  for (const { kw } of wordRegexes) {
    if (lowerPath.includes(kw)) {
      matched.add(kw);
      fileScore += 2;
    }
  }

  for (const { kw, re } of wordRegexes) {
    if (re.test(lower)) {
      matched.add(kw);
      fileScore += 2;
    } else if (lower.includes(kw)) {
      matched.add(kw);
      fileScore += 1;
    }
  }

  if (matched.size === 0) return { score: 0, line: -1, matched: [] };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line || line.length > MAX_LINE_CHARS) continue;
    let lineScore = 0;
    for (const { kw, re } of wordRegexes) {
      if (re.test(line)) lineScore += 2;
      else if (line.includes(kw)) lineScore += 1;
    }
    if (lineScore <= 0) continue;
    const trimmed = line.trim();
    if (isCommentLine(trimmed)) lineScore *= 0.25;
    else if (isDefinitionOrHandlerLine(trimmed)) lineScore += 1;

    if (lineScore > bestLineScore) {
      bestLineScore = lineScore;
      bestLine = i;
    }
  }

  return { score: Math.round((fileScore + bestLineScore) * 100) / 100, line: bestLine, matched: [...matched] };
}

function snippetAround(content, lineIndex, context = 2) {
  const lines = content.split("\n");
  const start = Math.max(0, lineIndex - context);
  const end = Math.min(lines.length, lineIndex + context + 1);
  return lines.slice(start, end).map((l, i) => `${start + i + 1}: ${l}`).join("\n").slice(0, 1200);
}

export async function inspectCodebase(incident, opts = {}) {
  const root = opts.root ?? config.CODEBASE_PATH;
  const maxFiles = opts.maxFiles ?? config.CODEBASE_MAX_FILES;
  const maxFindings = opts.maxFindings ?? config.CODEBASE_MAX_FINDINGS;
  if (!root) return [];

  const resolvedRoot = path.resolve(root);
  try { if (!(await fs.stat(resolvedRoot)).isDirectory()) return []; } catch { return []; }

  const keywords = deriveKeywords(incident);
  if (!keywords.length) return [];

  const excludeRaw = opts.excludeDirs ?? config.CODEBASE_EXCLUDE_DIRS ?? "";
  const extraSkipDirs = new Set(
    String(excludeRaw).split(",").map(s => s.trim()).filter(Boolean)
  );

  const files = await walk(resolvedRoot, maxFiles, extraSkipDirs);
  const scored = [];
  for (const file of files) {
    try {
      if ((await fs.stat(file)).size > MAX_FILE_BYTES) continue;
      const content = await fs.readFile(file, "utf8");
      const relative = path.relative(resolvedRoot, file);
      const { score, line, matched } = scoreContent(content, keywords, relative);
      if (score <= 0 || line < 0) continue;
      scored.push({ score, finding: { file: relative, line: line + 1, snippet: snippetAround(content, line), reason: `Matched incident keywords: ${matched.join(", ")}` } });
    } catch { /* skip unreadable */ }
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, maxFindings).map(s => s.finding);
}
