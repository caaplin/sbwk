// Context retention: bounded in-memory history with O(1) path recurrence
// indexing and non-blocking queued atomic disk persistence.
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";

export class IncidentStore {
  constructor(max = 200, dataDir = undefined, opts = {}) {
    this.max = max;
    this.dataDir = dataDir;
    this.ttlMs = opts.ttlMs || 0;
    this.records = new Map();
    this.order = [];
    // Extended ring for recurrence counts so recurrence isn't forgotten right at `max`.
    this.maxRecurrenceHistory = Math.max(max * 5, 1000);
    this.recurrenceRing = [];
    this.pathCounts = new Map();
    this._writeChain = Promise.resolve();
    this._dirty = false;
    this._writing = false;
  }

  file() { return this.dataDir ? path.join(this.dataDir, "incidents.json") : undefined; }

  _incPath(id, p, tsMs) {
    this.recurrenceRing.push({ id, path: p, tsMs });
    this.pathCounts.set(p, (this.pathCounts.get(p) || 0) + 1);
    while (this.recurrenceRing.length > this.maxRecurrenceHistory) {
      const evicted = this.recurrenceRing.shift();
      const next = (this.pathCounts.get(evicted.path) || 1) - 1;
      if (next <= 0) this.pathCounts.delete(evicted.path);
      else this.pathCounts.set(evicted.path, next);
    }
  }

  _pruneExpired(nowMs = Date.now()) {
    if (!this.ttlMs || this.ttlMs <= 0) return;
    while (this.order.length) {
      const oldest = this.records.get(this.order[0]);
      if (!oldest) { this.order.shift(); continue; }
      const age = nowMs - (Date.parse(oldest.createdAt) || nowMs);
      if (age <= this.ttlMs) break;
      this.records.delete(this.order.shift());
    }
    while (this.recurrenceRing.length && nowMs - this.recurrenceRing[0].tsMs > this.ttlMs) {
      const evicted = this.recurrenceRing.shift();
      const next = (this.pathCounts.get(evicted.path) || 1) - 1;
      if (next <= 0) this.pathCounts.delete(evicted.path);
      else this.pathCounts.set(evicted.path, next);
    }
  }

  load() {
    const file = this.file();
    if (!file) return;
    try {
      const arr = JSON.parse(fs.readFileSync(file, "utf8"));
      if (!Array.isArray(arr)) return;
      for (const record of arr.slice(-this.max)) {
        if (!record?.incident?.id) continue;
        this.records.set(record.incident.id, record);
        this.order.push(record.incident.id);
        this._incPath(record.incident.id, record.incident.path, Date.parse(record.createdAt) || Date.now());
      }
      this._pruneExpired();
    } catch { /* no prior context */ }
  }

  _snapshotJson() {
    const items = this.order.map(id => this.records.get(id)).filter(Boolean);
    return JSON.stringify(items, null, 2);
  }

  /** Non-blocking coalesced atomic write (.tmp -> rename with 0600 permissions). */
  persist() {
    const file = this.file();
    if (!file) return;
    this._dirty = true;
    if (this._writing) return;
    this._writing = true;

    this._writeChain = this._writeChain.then(async () => {
      while (this._dirty) {
        this._dirty = false;
        const payload = this._snapshotJson();
        const tmp = `${file}.${process.pid}.tmp`;
        try {
          await fsp.mkdir(this.dataDir, { recursive: true });
          await fsp.writeFile(tmp, payload, { mode: 0o600 });
          await fsp.rename(tmp, file);
        } catch {
          try { await fsp.unlink(tmp); } catch { /* ignore */ }
        }
      }
    }).finally(() => {
      this._writing = false;
    });
  }

  /** Await pending async writes (useful in tests). */
  async flush() {
    await this._writeChain;
  }

  /** Synchronous atomic flush for SIGTERM/SIGINT shutdown hooks. */
  flushSync() {
    const file = this.file();
    if (!file || !this._dirty) return;
    const tmp = `${file}.${process.pid}.sync.tmp`;
    try {
      fs.mkdirSync(this.dataDir, { recursive: true });
      fs.writeFileSync(tmp, this._snapshotJson(), { mode: 0o600 });
      fs.renameSync(tmp, file);
      this._dirty = false;
    } catch { /* best-effort */ }
  }

  create(incident) {
    this._pruneExpired();
    const nowMs = Date.now();
    const now = new Date(nowMs).toISOString();
    const record = { incident, status: "investigating", createdAt: now, updatedAt: now };
    const isNew = !this.records.has(incident.id);
    this.records.set(incident.id, record);
    if (isNew) {
      this.order.push(incident.id);
      this._incPath(incident.id, incident.path, nowMs);
    }
    while (this.order.length > this.max) this.records.delete(this.order.shift());
    this.persist();
    return record;
  }

  attachAnalysis(id, analysis) {
    const r = this.records.get(id);
    if (!r) return undefined;
    r.analysis = analysis; r.status = "analyzed"; r.updatedAt = new Date().toISOString();
    this.persist();
    return r;
  }

  setNotification(id, notification) {
    const r = this.records.get(id);
    if (!r) return;
    r.notification = notification; r.updatedAt = new Date().toISOString();
    this.persist();
  }

  setFeedback(id, status, note) {
    const r = this.records.get(id);
    if (!r) return undefined;
    r.feedback = { status, note, at: new Date().toISOString() };
    r.status = status; r.updatedAt = new Date().toISOString();
    this.persist();
    return r;
  }

  get(id) {
    this._pruneExpired();
    return this.records.get(id);
  }

  list(limit = 50) {
    this._pruneExpired();
    return this.order.slice(-limit).reverse().map(id => this.records.get(id)).filter(Boolean);
  }

  /** O(1) lookup via maintained pathCounts map. */
  recurrenceForPath(p, excludeId) {
    this._pruneExpired();
    let total = this.pathCounts.get(p) || 0;
    if (excludeId) {
      const excluded = this.records.get(excludeId);
      if (excluded && excluded.incident.path === p) total = Math.max(0, total - 1);
    }
    return total;
  }

  contextSummary() {
    this._pruneExpired();
    const records = [...this.records.values()];
    const byStatus = {};
    for (const r of records) byStatus[r.status] = (byStatus[r.status] || 0) + 1;
    const recurring = [...this.pathCounts.entries()]
      .filter(([, n]) => n >= 3)
      .sort((a, b) => b[1] - a[1])
      .map(([p, n]) => ({ path: p, count: n }));
    return { total: records.length, byStatus, recurring, escalated: records.filter(r => r.analysis?.escalate).length };
  }
}
