// Sleepy Bot control plane console. Plain browser JS, no build step.
// Loaded with `defer`, so the DOM is ready when this runs.
(() => {
  'use strict';

  const $ = id => document.getElementById(id);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtTime = iso => { const d = new Date(iso); return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString(); };
  const TABS = ['requests', 'config', 'about'];
  const KINDS = ['auth', 'database', 'external_api', 'other'];

  class HttpError extends Error {
    constructor(message, status, body) { super(message); this.status = status; this.body = body; }
  }

  async function api(path, body) {
    const res = await fetch(path, body === undefined ? undefined : {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    });
    if (res.status === 401) { location.href = '/login'; throw new HttpError('session expired', 401); }
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.success === false) throw new HttpError(data.error || `HTTP ${res.status}`, res.status, data);
    return data;
  }

  /* ---------- tabs ---------- */
  function showTab(name) {
    if (!TABS.includes(name)) name = 'requests';
    document.querySelectorAll('.tab-btn').forEach(b => {
      const on = b.dataset.tab === name;
      b.classList.toggle('is-active', on);
      b.setAttribute('aria-selected', String(on));
    });
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('is-active', p.id === `tab-${name}`));
    if (location.hash !== `#${name}`) history.replaceState(null, '', `#${name}`);
  }
  document.querySelectorAll('.tab-btn').forEach(b => b.addEventListener('click', () => showTab(b.dataset.tab)));
  window.addEventListener('hashchange', () => showTab(location.hash.slice(1)));

  $('logout').addEventListener('click', async e => {
    e.preventDefault();
    try { await fetch('/api/logout', { method: 'POST' }); } catch { /* navigating away anyway */ }
    location.href = '/login';
  });

  /* ---------- health ---------- */
  function renderHealth(services) {
    const dot = $('health-dot'), label = $('health-label');
    const vals = Object.values(services || {});
    dot.className = 'dot';
    if (!vals.length) { label.textContent = 'no data'; return; }
    const bad = vals.filter(v => v !== 'healthy').length;
    dot.classList.add(bad === 0 ? 'ok' : bad === vals.length ? 'bad' : 'warn');
    label.textContent = bad === 0 ? 'all healthy' : `${bad}/${vals.length} not healthy`;
  }
  async function refreshHealth() {
    try { renderHealth((await api('/api/state')).services); } catch { /* shown by the feed */ }
  }

  /* ---------- requests ---------- */
  const LOG_LIMIT = 100;
  const POLL_MS = 4000;
  const POLL_MAX_MS = 60000;
  const expanded = new Set();
  let logs = [];
  let lastSig = '';
  let pollTimer = null;
  let failures = 0;
  let paused = false;
  let inFlight = false;

  function setFeed(text, cls = '') {
    const el = $('feed-state');
    el.textContent = text;
    el.className = 'feed-state' + (cls ? ' ' + cls : '');
  }

  function visibleLogs() {
    const anomalyOnly = $('filter-anomaly').checked;
    const errorsOnly = $('filter-errors').checked;
    const cls = $('filter-status').value; // '', '2xx', '4xx', '5xx'
    return logs.filter(l => {
      if (anomalyOnly && !l.anomaly) return false;
      if (errorsOnly && l.statusCode < 400) return false;
      if (cls && Math.floor(l.statusCode / 100) !== Number(cls[0])) return false;
      return true;
    });
  }

  function rowHtml(l) {
    const statusCls = l.statusCode >= 500 ? 'cell-5xx' : l.statusCode >= 400 ? 'cell-4xx' : '';
    const catCls = (l.category === 'server_error' || l.category === 'timeout') ? 'cat-bad'
                 : (!l.category || l.category === 'normal') ? '' : 'cat-warn';
    const inc = l.incidentId
      ? `<button type="button" class="link-btn" data-copy="${esc(l.incidentId)}">copy</button>`
      : '—';
    return `<tr class="log-row${l.anomaly ? ' is-anomaly' : ''}" data-log-id="${esc(l.id)}">
      <td class="col-time">${esc(fmtTime(l.timestamp))}</td>
      <td class="col-method">${esc(l.method)}</td>
      <td class="col-path">${esc(l.path)}</td>
      <td class="col-status ${statusCls}">${esc(l.statusCode)}</td>
      <td>${Math.round(l.durationMs || 0)}</td>
      <td class="${catCls}">${esc(l.category || 'normal')}</td>
      <td class="col-inc">${inc}</td>
    </tr>`;
  }

  function detailHtml(l) {
    return `<tr class="log-detail" data-detail-for="${esc(l.id)}"><td colspan="7">
      <div class="detail-grid">
        <div><span class="k">id</span><code>${esc(l.id)}</code></div>
        <div><span class="k">upstream</span><code>${esc(l.upstream)}</code></div>
        <div><span class="k">client</span><code>${esc(l.clientIp || '?')}</code></div>
        ${l.incidentId ? `<div><span class="k">incident</span><code>${esc(l.incidentId)}</code></div>` : ''}
      </div>
      ${l.responseSample ? `<pre class="sample">${esc(l.responseSample)}</pre>` : ''}
    </td></tr>`;
  }

  // Rebuild the table only when its visible content changes, so hover, scroll and
  // open details are not disturbed on every poll.
  function renderRequests(force = false) {
    $('req-count').textContent = String(logs.length);
    $('req-anomalies').textContent = String(logs.filter(l => l.anomaly).length);

    const rows = visibleLogs().sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
    const sig = JSON.stringify([
      rows.map(l => [l.id, l.statusCode, l.category, l.anomaly, l.incidentId]),
      [...expanded].sort()
    ]);
    if (!force && sig === lastSig) return;
    lastSig = sig;

    const body = $('log-body');
    if (!rows.length) {
      body.innerHTML = `<tr class="empty"><td colspan="7">// ${logs.length ? 'no requests match these filters' : 'no requests yet'}</td></tr>`;
      return;
    }
    body.innerHTML = rows.map(l => rowHtml(l) + (expanded.has(l.id) ? detailHtml(l) : '')).join('');
  }

  $('log-body').addEventListener('click', async e => {
    const copy = e.target.closest('[data-copy]');
    if (copy) {
      e.stopPropagation();
      try { await navigator.clipboard.writeText(copy.dataset.copy); copy.textContent = 'copied'; }
      catch { copy.textContent = 'failed'; }
      setTimeout(() => { copy.textContent = 'copy'; }, 1000);
      return;
    }
    const row = e.target.closest('tr.log-row');
    if (!row) return;
    const id = row.dataset.logId;
    if (expanded.has(id)) expanded.delete(id); else expanded.add(id);
    renderRequests(true);
  });

  ['filter-anomaly', 'filter-errors', 'filter-status'].forEach(id =>
    $(id).addEventListener('change', () => renderRequests(true)));

  function scheduleNextPoll() {
    clearTimeout(pollTimer);
    if (paused) return;
    const delay = failures ? Math.min(POLL_MS * 2 ** failures, POLL_MAX_MS) : POLL_MS;
    pollTimer = setTimeout(pollLogs, delay);
  }

  async function pollLogs() {
    if (inFlight) return;
    inFlight = true;
    try {
      const r = await api(`/api/logs?limit=${LOG_LIMIT}`);
      failures = 0;
      logs = r.logs || [];
      if (r.unreachable) setFeed('middleware unreachable', 'warn');
      else if (paused) setFeed('paused', 'warn');
      else setFeed('live');
      renderRequests();
    } catch {
      failures++;
      setFeed('error, retrying', 'bad');
    } finally {
      inFlight = false;
      scheduleNextPoll();
    }
  }

  $('btn-pause').addEventListener('click', () => {
    paused = !paused;
    $('btn-pause').textContent = paused ? 'Resume' : 'Pause';
    if (paused) { clearTimeout(pollTimer); setFeed('paused', 'warn'); }
    else pollLogs();
  });

  /* ---------- config ---------- */
  let services = [];   // client-side rows; `token` holds only what the user typed this session
  let dirty = false;
  let validateTimer = null;

  const isOn = id => $(id).getAttribute('aria-checked') === 'true';
  const setOn = (id, on) => $(id).setAttribute('aria-checked', String(Boolean(on)));

  function setSaveStatus(text, cls = '') {
    const el = $('save-status');
    el.textContent = text;
    el.className = 'save-status' + (cls ? ' ' + cls : '');
  }
  function markDirty() {
    dirty = true;
    setSaveStatus('unsaved changes');
  }
  function markClean() {
    dirty = false;
    setSaveStatus('');
  }

  function checkLine(s) {
    if (!s.lastCheck) return '';
    const c = s.lastCheck;
    const text = c.reachable
      ? `reachable · HTTP ${c.status ?? '—'} · ${c.latencyMs}ms${c.note ? ' · ' + c.note : ''}`
      : `unreachable · ${c.error || 'unknown error'}`;
    return `<div class="hint ${c.reachable ? 'ok' : 'warn'}">${esc(text)}</div>`;
  }

  function renderServices() {
    const list = $('services-list');
    if (!services.length) {
      list.innerHTML = '<div class="services-empty">// no services. Add one to monitor it.</div>';
      return;
    }
    list.innerHTML = services.map((s, i) => {
      const tokenPlaceholder = s.clearToken ? 'will be removed on save' : s.hasToken ? '•••• stored' : 'none';
      const tokenAction = s.clearToken
        ? '<button type="button" class="btn-micro" data-action="undo-clear">undo</button>'
        : s.hasToken
          ? '<button type="button" class="btn-micro" data-action="clear-token">clear</button>'
          : '';
      return `<div class="service-row" data-index="${i}">
        <div class="field">
          <label>NAME</label>
          <input data-field="name" value="${esc(s.name)}" placeholder="auth">
        </div>
        <div class="field">
          <label>KIND</label>
          <select data-field="kind">${KINDS.map(k => `<option value="${k}"${k === s.kind ? ' selected' : ''}>${k}</option>`).join('')}</select>
        </div>
        <div class="field">
          <label>ENDPOINT</label>
          <input data-field="endpoint" value="${esc(s.endpoint)}" placeholder="https://auth.example.com/logs">
          <div class="hint" data-hint="endpoint"></div>
          ${checkLine(s)}
        </div>
        <div class="field">
          <label>TOKEN ${tokenAction}</label>
          <input data-field="token" type="password" value="${esc(s.token)}" placeholder="${esc(tokenPlaceholder)}" ${s.clearToken ? 'disabled' : ''}>
        </div>
        <button type="button" class="btn-remove" data-action="remove" aria-label="Remove service">×</button>
      </div>`;
    }).join('');
  }

  // One listener per container, reading the row index from the DOM. No closures to go stale.
  $('services-list').addEventListener('input', e => {
    const row = e.target.closest('.service-row');
    const field = e.target.dataset.field;
    if (!row || !field) return;
    const svc = services[Number(row.dataset.index)];
    if (!svc) return;
    svc[field] = e.target.value;
    markDirty();
    scheduleValidate();
  });
  $('services-list').addEventListener('change', e => {
    if (e.target.dataset.field === 'kind') {
      const svc = services[Number(e.target.closest('.service-row').dataset.index)];
      if (svc) { svc.kind = e.target.value; markDirty(); scheduleValidate(); }
    }
  });
  $('services-list').addEventListener('click', e => {
    const action = e.target.dataset.action;
    const row = e.target.closest('.service-row');
    if (!action || !row) return;
    const i = Number(row.dataset.index);
    const svc = services[i];
    if (!svc) return;

    if (action === 'remove') {
      const label = svc.name || svc.kind;
      if (svc.hasToken && !confirm(`Remove ${label}? Its stored token will be deleted on save.`)) return;
      services.splice(i, 1);
    } else if (action === 'clear-token') {
      svc.clearToken = true; svc.token = '';
    } else if (action === 'undo-clear') {
      svc.clearToken = false;
    }
    renderServices();
    markDirty();
    scheduleValidate();
  });

  $('btn-add-service').addEventListener('click', () => {
    services.push({
      id: `svc_new_${Date.now().toString(36)}`, name: '', kind: 'other', endpoint: '',
      hasToken: false, clearToken: false, token: '', lastCheck: null
    });
    renderServices();
    markDirty();
    scheduleValidate();
  });

  function buildPayload(save = true) {
    return {
      gateway: { targetUrl: $('cfg-target').value.trim(), port: Number($('cfg-port').value) },
      external: {
        services: services.map(s => {
          const out = { id: s.id, name: s.name.trim(), kind: s.kind, endpoint: s.endpoint.trim() };
          if (s.token) out.token = s.token;
          if (s.clearToken) out.clearToken = true;
          return out;
        })
      },
      codebase: {
        repoUrl: $('cfg-repo').value.trim(),
        ...($('cfg-token').value ? { token: $('cfg-token').value } : {})
      },
      safety: {
        dryRun: isOn('cfg-dryrun'),
        autoRollback: isOn('cfg-rollback'),
        escalationThreshold: Number($('cfg-threshold').value) / 100
      },
      monitoring: { active: isOn('cfg-monitoring') },
      save
    };
  }

  // Warnings come from the server, the single source of truth for the rules.
  function showWarnings(warnings) {
    document.querySelectorAll('[data-hint]').forEach(h => { h.textContent = ''; h.className = 'hint'; });
    $('hint-target').textContent = '';
    const bar = $('warn-bar');
    if (!warnings.length) { bar.hidden = true; bar.innerHTML = ''; return; }
    bar.hidden = false;
    bar.innerHTML = warnings.map(w =>
      `<div class="warn-line ${esc(w.severity)}"><span class="warn-key">${esc(w.field)}</span>${esc(w.message)}</div>`
    ).join('');
    for (const w of warnings) {
      if (w.field === 'gateway.targetUrl') {
        const h = $('hint-target'); h.textContent = w.message; h.className = 'hint ' + w.severity;
        continue;
      }
      const m = w.field.match(/^external\.services\[(\d+)\]\.(endpoint|kind)$/);
      if (!m) continue;
      const row = document.querySelector(`.service-row[data-index="${m[1]}"]`);
      const hint = row?.querySelector('[data-hint="endpoint"]');
      if (hint && m[2] === 'endpoint') { hint.textContent = w.message; hint.className = 'hint ' + w.severity; }
    }
  }

  function scheduleValidate() {
    clearTimeout(validateTimer);
    validateTimer = setTimeout(async () => {
      try {
        const r = await api('/api/config', { ...buildPayload(false) });
        showWarnings(r.warnings || []);
      } catch (e) {
        showWarnings(e.body?.warnings || []);
      }
    }, 350);
  }

  function populate(s) {
    $('cfg-target').value = s.gateway.targetUrl || '';
    $('cfg-port').value = s.gateway.port || 8080;
    $('cfg-repo').value = s.codebase.repoUrl || '';
    $('cfg-token').value = '';
    $('hint-token').textContent = s.codebase.hasToken ? 'stored · leave blank to keep' : 'none stored';
    $('hint-repo').textContent = s.codebase.fullName
      ? `linked: ${s.codebase.fullName} · ${s.codebase.commits.length} recent commits`
      : '';
    setOn('cfg-dryrun', s.safety.dryRun);
    setOn('cfg-rollback', s.safety.autoRollback);
    $('cfg-threshold').value = Math.round(s.safety.escalationThreshold * 100);
    setOn('cfg-monitoring', s.monitoring.active);
    $('config-meta').textContent = s.monitoring.active
      ? `monitoring since ${s.monitoring.startedAt ? fmtTime(s.monitoring.startedAt) : 'unknown'}`
      : 'monitoring off';
    services = s.external.services.map(x => ({ ...x, token: '', clearToken: false }));
    renderServices();
    markClean();
  }

  async function loadState() {
    try {
      const { state, services: health } = await api('/api/state');
      populate(state);
      renderHealth(health);
      showWarnings([]);
      scheduleValidate();
    } catch (e) {
      $('config-meta').textContent = `failed to load: ${e.message}`;
    }
  }

  $('btn-reload').addEventListener('click', () => {
    if (dirty && !confirm('Discard unsaved changes?')) return;
    loadState();
  });

  $('btn-check').addEventListener('click', async () => {
    const btn = $('btn-check');
    btn.disabled = true;
    setSaveStatus('testing connections…');
    try {
      const r = await api('/api/config/check', {});
      const saved = new Map(r.state.external.services.map(s => [s.id, s]));
      // Apply results only to rows whose endpoint still matches what was tested.
      services.forEach(s => {
        const f = saved.get(s.id);
        if (f && f.endpoint === s.endpoint) s.lastCheck = f.lastCheck;
      });
      renderServices();
      setSaveStatus('connections tested', 'ok');
    } catch (e) {
      setSaveStatus(`test failed: ${e.message}`, 'bad');
    } finally {
      btn.disabled = false;
    }
  });

  $('btn-gateway-check').addEventListener('click', async () => {
    const btn = $('btn-gateway-check');
    btn.disabled = true;
    setSaveStatus('testing gateway…');
    try {
      const { lastCheck: c } = await api('/api/gateway/check', {});
      const ok = c.edge === 'healthy' && c.forwardedStatus !== null && c.forwardedStatus < 500;
      const line = $('gateway-check');
      line.textContent = `edge: ${c.edge} · request through edge: ${c.forwardedStatus ?? c.error}`;
      line.className = 'hint ' + (ok ? 'ok' : 'warn');
      setSaveStatus('gateway tested', ok ? 'ok' : 'bad');
    } catch (e) {
      setSaveStatus(`gateway test failed: ${e.message}`, 'bad');
    } finally {
      btn.disabled = false;
    }
  });

  ['cfg-target', 'cfg-port', 'cfg-repo', 'cfg-token', 'cfg-threshold'].forEach(id =>
    $(id).addEventListener('input', () => { markDirty(); scheduleValidate(); }));
  ['cfg-dryrun', 'cfg-rollback', 'cfg-monitoring'].forEach(id =>
    $(id).addEventListener('click', () => { setOn(id, !isOn(id)); markDirty(); scheduleValidate(); }));

  $('config-form').addEventListener('submit', async e => {
    e.preventDefault();
    const btn = $('btn-save');
    btn.disabled = true;
    setSaveStatus('saving…');
    try {
      const r = await api('/api/config', buildPayload(true));
      populate(r.state);
      showWarnings(r.warnings || []);
      const failed = Object.entries(r.applied || {}).filter(([, v]) => !v.ok);
      if (failed.length) {
        setSaveStatus(`saved, but not pushed: ${failed.map(([k, v]) => `${k} (${v.error || v.status})`).join(', ')}`, 'bad');
      } else {
        setSaveStatus('saved', 'ok');
      }
      refreshHealth();
    } catch (err) {
      // Validation failed or the repo could not be linked: nothing was saved, so keep the edits.
      showWarnings(err.body?.warnings || []);
      setSaveStatus(`not saved: ${err.message}`, 'bad');
    } finally {
      btn.disabled = false;
    }
  });

  window.addEventListener('beforeunload', e => {
    if (dirty) { e.preventDefault(); e.returnValue = ''; }
  });

  /* ---------- git branches tab ---------- */
  function updateGitTabVisibility(state) {
    const wrap = document.getElementById('tab-btn-git-wrap');
    if (!wrap) return;
    const hasGit = Boolean(state?.codebase?.hasToken || state?.codebase?.repoUrl);
    wrap.style.display = hasGit ? '' : 'none';
  }

  async function loadGitStatus() {
    const msgEl = document.getElementById('git-status-msg');
    const branchesEl = document.getElementById('git-branches-list');
    const diffsEl = document.getElementById('git-diffs-list');
    const metaEl = document.getElementById('git-repo-meta');
    if (!msgEl || !branchesEl || !diffsEl) return;

    msgEl.innerHTML = '<span class="muted">Loading git status from GitHub…</span>';
    try {
      const data = await api('/api/git/status');
      if (!data.configured) {
        msgEl.innerHTML = `<div style="padding:10px 12px;border:1px solid #f59e0b;background:#fffbeb;border-radius:6px;color:#92400e;">
          <strong>GitHub not configured:</strong> Set <code>GITHUB_REPO</code> and <code>GITHUB_TOKEN</code> in <code>.env</code>, or save them in the <strong>Config</strong> tab.
        </div>`;
        branchesEl.innerHTML = '';
        diffsEl.innerHTML = '';
        return;
      }
      if (!data.ok) {
        msgEl.innerHTML = `<div style="padding:10px 12px;border:1px solid #ef4444;background:#fef2f2;border-radius:6px;color:#991b1b;">
          <strong>GitHub API Error:</strong> ${esc(data.error || 'Unknown error')}
        </div>`;
        branchesEl.innerHTML = '';
        diffsEl.innerHTML = '';
        return;
      }
      if (metaEl && data.repo) {
        metaEl.textContent = `${data.repo.fullName} (default branch: ${data.repo.defaultBranch})`;
      }
      msgEl.innerHTML = `<span class="muted">Connected to <strong>${esc(data.repo?.fullName || '')}</strong> · ${data.branches?.length || 0} branch(es) · last ${data.diffs?.length || 0} commit(s)</span>`;

      branchesEl.innerHTML = `<h3 style="margin:0 0 8px;font-size:14px;">Branches</h3>
        <div style="display:flex;flex-wrap:wrap;gap:8px;">` +
        (data.branches || []).map(b =>
          `<div style="padding:6px 10px;border:1px solid var(--hair);border-radius:6px;background:var(--bg);font-size:12px;">
            <strong>${esc(b.name)}</strong> <code style="margin-left:4px;">${esc(b.sha)}</code>${b.protected ? ' <span class="badge">protected</span>' : ''}
          </div>`
        ).join('') + `</div>`;

      diffsEl.innerHTML = `<h3 style="margin:12px 0 8px;font-size:14px;">Commit History &amp; Diffs (Last ${data.diffs?.length || 0})</h3>` +
        (data.diffs || []).map((d, idx) => {
          const filesHtml = (d.files || []).map(f =>
            `<details ${idx === 0 ? 'open' : ''} style="margin:4px 0;">
              <summary style="cursor:pointer;font-size:12px;"><code>${esc(f.filename)}</code> <span class="muted">(${esc(f.status)}, +${f.additions}/-${f.deletions})</span></summary>
              <pre style="overflow:auto;max-height:220px;font-size:11px;padding:8px;background:var(--hair);border-radius:4px;margin-top:4px;">${esc(f.patch || 'No patch available')}</pre>
            </details>`
          ).join('');
          return `<div class="card" style="margin-bottom:10px;padding:12px;">
            <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">
              <div><code>${esc(d.shortSha)}</code> <strong>${esc(d.message)}</strong> <span class="muted">by ${esc(d.author)}</span></div>
              <button type="button" class="btn git-rollback-btn" data-sha="${esc(d.sha)}" data-branch="${esc(data.repo?.defaultBranch || 'main')}">Rollback to Parent</button>
            </div>
            <div style="margin-top:8px;">${filesHtml || '<span class="muted">No file diffs</span>'}</div>
          </div>`;
        }).join('');

      diffsEl.querySelectorAll('.git-rollback-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
          const sha = btn.dataset.sha;
          const branch = btn.dataset.branch;
          if (!confirm(`Roll back branch "${branch}" to parent of ${sha.slice(0, 7)}?`)) return;
          btn.disabled = true;
          try {
            const res = await api('/api/git/rollback', { method: 'POST', body: JSON.stringify({ targetSha: sha, branch }) });
            msgEl.textContent = `Rolled back ${res.branch} from ${res.rolledBackFrom} to ${res.rolledBackTo}.`;
            await loadGitStatus();
          } catch (e) {
            msgEl.textContent = `Rollback failed: ${e.message}`;
          } finally {
            btn.disabled = false;
          }
        });
      });
    } catch (e) {
      msgEl.textContent = `Error: ${e.message}`;
    }
  }

  document.getElementById('git-refresh-btn')?.addEventListener('click', loadGitStatus);
  document.getElementById('git-feed-agent-btn')?.addEventListener('click', async () => {
    const msgEl = document.getElementById('git-status-msg');
    if (msgEl) msgEl.textContent = 'Feeding last 4 diffs to agent…';
    try {
      const res = await api('/api/git/feed-agent', { method: 'POST', body: '{}' });
      if (msgEl) msgEl.textContent = `Fed ${res.fedCount} diff(s) from ${res.branch} to agent-core.`;
    } catch (e) {
      if (msgEl) msgEl.textContent = `Failed to feed agent: ${e.message}`;
    }
  });
  document.querySelector('[data-tab="git"]')?.addEventListener('click', loadGitStatus);
  api('/api/state').then(d => updateGitTabVisibility(d.state)).catch(() => {});

  /* ---------- boot ---------- */
  showTab(location.hash.slice(1) || 'requests');
  loadState();
  pollLogs();
  setInterval(refreshHealth, 30000);
})();
