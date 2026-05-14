/*
 * audr daemon dashboard — Phase 2 visual slice.
 *
 * What this does:
 *  - reads ?t=<token> from the URL
 *  - GET /api/findings — render the snapshot
 *  - groups findings into severity sections (CRIT/HIGH expanded by default,
 *    MED/LOW collapsed with a count)
 *  - filter pills, finding row expand, Copy AI Prompt
 *  - EventSource /api/events — just confirms connectivity (Phase 3+ will push
 *    live deltas)
 *
 * Intentionally framework-free. ~250 LOC of vanilla JS. SSE handler is the
 * place future-Claude wires the live update protocol.
 */
(function () {
  'use strict';

  const token = new URLSearchParams(window.location.search).get('t') || '';
  if (!token) {
    document.body.innerHTML = '<div class="empty">missing auth token in URL. Re-open via <code>audr open</code>.</div>';
    return;
  }

  const $ = (id) => document.getElementById(id);
  const el = (tag, attrs = {}, ...children) => {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') e.className = v;
      else if (k === 'text') e.textContent = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else if (k === 'dataset') Object.assign(e.dataset, v);
      else e.setAttribute(k, v);
    }
    for (const c of children) {
      if (c == null) continue;
      e.append(c.nodeType ? c : document.createTextNode(c));
    }
    return e;
  };

  // ----- API ------------------------------------------------------
  async function apiGet(path) {
    const sep = path.includes('?') ? '&' : '?';
    const r = await fetch(path + sep + 't=' + encodeURIComponent(token), {
      headers: { Accept: 'application/json' },
    });
    if (!r.ok) throw new Error('HTTP ' + r.status + ' ' + path);
    return r.json();
  }

  // ----- State ----------------------------------------------------
  const state = {
    findings: [],
    metrics: null,
    daemon: null,
    scanners: [],
    filters: { category: 'all', severity: 'all' },
    expanded: new Set(),
    sectionsCollapsed: { critical: false, high: false, medium: true, low: true },
    scanActive: false,
    firstScanCompleted: false,
    // Timestamp (ms since epoch) of the most recent scan-completed
    // event. Powers the "WATCHING — last scan X min ago" sub-label.
    lastScanCompletedAt: 0,
    dismissedBanners: new Set(),
    // Fingerprints currently animating their resolved → removed
    // transition. Excluded from render() so the JS doesn't blow them
    // away mid-animation; the timer that animates them owns deletion.
    resolving: new Set(),
  };

  const SCAN_CATEGORIES = ['ai-agent', 'secrets', 'deps', 'os-pkg'];
  const SCAN_CATEGORY_LABEL = {
    'ai-agent': 'AI-AGENT',
    'secrets':  'SECRETS',
    'deps':     'DEPS',
    'os-pkg':   'OS-PKG',
  };

  // ----- Top bar / metrics ----------------------------------------
  // The raw daemon state (RUN/SLOW/PAUSE/OFFLINE) is operationally
  // accurate but unhelpful as a label — "RUN" tells the user nothing
  // about what audr is currently doing. We surface a friendlier
  // label here that combines the raw state with the scan-active
  // signal: between scans the daemon is "WATCHING" (fsnotify +
  // periodic poll), during a scan it's "SCANNING". The full mapping
  // lives in topBarLabel below.
  function renderTop() {
    const d = state.daemon || { state: 'OFFLINE', version: 'unknown' };
    const dot = $('state-dot');
    const label = $('state-label');
    const meta = $('state-meta');
    dot.className = 'pulse-dot ' + ({ RUN: '', SLOW: 'slow', PAUSE: 'pause', OFFLINE: 'offline' }[d.state] || 'offline');
    label.textContent = topBarLabel(d);
    meta.textContent = stateNoteFor(d);

    const scan = $('scan-status');
    scan.replaceChildren();
    if (d.scan_target) {
      scan.append('SCANNING ', el('code', { text: d.scan_target }), ` · ${d.scan_done || 0} / ${d.scan_total || 0}`);
    }
    $('version').textContent = d.version || 'unknown';
  }

  function topBarLabel(d) {
    const raw = (d && d.state) || 'OFFLINE';
    switch (raw) {
      case 'RUN':
        // Between scans the daemon is watching for changes; during a
        // scan it's actively scanning. Surface both clearly.
        return state.scanActive ? 'SCANNING' : 'WATCHING';
      case 'SLOW':    return 'SLOWED';
      case 'PAUSE':   return 'PAUSED';
      case 'OFFLINE': return 'DISCONNECTED';
      default:        return raw;
    }
  }

  function stateNoteFor(d) {
    // The raw state_note (e.g., "battery", "load 5.2") is preserved
    // as a meta clause after the friendly label. Empty note → empty
    // string so we don't leave a dangling separator.
    const note = (d && d.state_note) || '';
    return note ? '· ' + note : '';
  }

  function renderMetrics() {
    const m = state.metrics || { open_total: 0, open_critical: 0, open_high: 0, resolved_today: 0 };
    $('m-open').textContent = m.open_total;
    $('m-crit').textContent = m.open_critical;
    $('m-high').textContent = m.open_high;
    $('m-resolved').textContent = '+' + (m.resolved_today || 0);
  }

  // ----- Findings list --------------------------------------------
  function filteredFindings() {
    const { category, severity } = state.filters;
    return state.findings.filter((f) => {
      if (category !== 'all' && f.category !== category) return false;
      if (severity !== 'all' && f.severity !== severity) return false;
      return true;
    });
  }

  const SEV_ORDER = ['critical', 'high', 'medium', 'low'];
  const SEV_CLASS = { critical: 'crit', high: 'high', medium: 'medium', low: 'low' };
  const SEV_LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };

  function locatorMeta(f) {
    const loc = f.locator || {};
    if (f.kind === 'os-package') {
      return el('code', { text: `${loc.manager || '?'}:${loc.name || '?'} ${loc.version || ''}` });
    }
    if (f.kind === 'dep-package') {
      return el('code', { text: `${loc.ecosystem || '?'}:${loc.name || '?'}@${loc.version || ''}` });
    }
    const line = loc.line ? `:${loc.line}` : '';
    return el('code', { text: (loc.path || '?') + line });
  }

  function renderFindingRow(f) {
    const isOpen = state.expanded.has(f.fingerprint);
    const resolving = state.resolving.has(f.fingerprint);
    const row = el(
      'article',
      {
        class: 'finding' + (resolving ? ' resolving' : ''),
        dataset: { fingerprint: f.fingerprint, severity: f.severity, category: f.category },
        'aria-expanded': isOpen ? 'true' : 'false',
        onclick: (e) => {
          if (e.target.closest('.copy-btn')) return; // copy button has its own handler
          if (isOpen) state.expanded.delete(f.fingerprint);
          else state.expanded.add(f.fingerprint);
          render();
        },
      },
      el('div', { class: 'finding-bar ' + SEV_CLASS[f.severity] }),
      el(
        'div',
        { class: 'finding-body' },
        el(
          'div',
          { class: 'finding-line1' },
          el('span', { class: 'sev-label ' + SEV_CLASS[f.severity], text: SEV_LABEL[f.severity] }),
          el('span', { class: 'cat-tag', text: f.category.toUpperCase() }),
          el('span', { class: 'finding-title', text: f.title }),
        ),
        el(
          'div',
          { class: 'finding-meta' },
          locatorMeta(f),
          el('span', { text: 'first seen ' + formatRelative(f.first_seen) }),
          el('span', { text: 'rule ' + f.rule_id }),
        ),
        isOpen ? expandedDetail(f) : null,
      ),
    );
    return row;
  }

  function expandedDetail(f) {
    const human = el('pre', { class: 'manual-steps', text: 'loading…' });
    const ai = el('div', { class: 'prompt-preview', text: 'loading…' });
    const btn = el(
      'button',
      {
        class: 'copy-btn',
        type: 'button',
        onclick: async (e) => {
          e.stopPropagation();
          await onCopy(btn, f.fingerprint);
        },
      },
      'COPY AI PROMPT',
    );

    // Lazy-fetch remediation only when the row opens.
    apiGet('/api/remediation/' + encodeURIComponent(f.fingerprint))
      .then((r) => {
        human.textContent = r.human_steps;
        ai.textContent = r.ai_prompt;
        btn.dataset.prompt = r.ai_prompt;
      })
      .catch((err) => {
        human.textContent = 'failed to load remediation: ' + err.message;
        ai.textContent = '';
      });

    return el(
      'div',
      { class: 'expanded-detail' },
      el(
        'div',
        { class: 'detail-section' },
        el('h4', { text: f.match_redacted ? 'What an attacker gets' : 'Description' }),
        el('p', { class: 'detail-desc', text: f.description }),
        f.match_redacted ? el('p', { class: 'detail-desc', text: 'Matched: ' + f.match_redacted }) : null,
        el('h4', { style: 'margin-top: 20px;', text: 'Manual fix' }),
        human,
      ),
      el(
        'div',
        { class: 'detail-section' },
        el('h4', { text: 'Or ask your coding agent' }),
        btn,
        ai,
      ),
    );
  }

  async function onCopy(btn, fingerprint) {
    let text = btn.dataset.prompt;
    if (!text) {
      try {
        const r = await apiGet('/api/remediation/' + encodeURIComponent(fingerprint));
        text = r.ai_prompt;
        btn.dataset.prompt = text;
      } catch (e) {
        btn.textContent = 'COPY FAILED';
        return;
      }
    }
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Fallback for browsers blocking clipboard on http://
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.append(ta);
      ta.select();
      try { document.execCommand('copy'); } catch (_) {}
      ta.remove();
    }
    const original = 'COPY AI PROMPT';
    btn.textContent = 'COPIED ✓';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = original;
      btn.classList.remove('copied');
    }, 2000);
  }

  function renderFindings() {
    const root = $('findings');
    root.removeAttribute('aria-busy');
    root.replaceChildren();
    const filtered = filteredFindings();
    if (filtered.length === 0) {
      root.append(el('div', { class: 'empty', text: 'no findings match the current filters' }));
      return;
    }

    // Group by severity.
    const grouped = { critical: [], high: [], medium: [], low: [] };
    for (const f of filtered) (grouped[f.severity] || []).push(f);

    for (const sev of SEV_ORDER) {
      const group = grouped[sev];
      if (group.length === 0) continue;
      const collapsed = state.sectionsCollapsed[sev];
      const section = el(
        'section',
        { class: 'sev-section', dataset: { severity: sev, collapsed: String(collapsed) } },
        el(
          'header',
          {
            class: 'sev-section-header ' + SEV_CLASS[sev],
            role: 'button',
            tabindex: '0',
            'aria-expanded': String(!collapsed),
            onclick: () => {
              state.sectionsCollapsed[sev] = !state.sectionsCollapsed[sev];
              render();
            },
            onkeydown: (e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                state.sectionsCollapsed[sev] = !state.sectionsCollapsed[sev];
                render();
              }
            },
          },
          el('span', { class: 'chev' }),
          el('span', { text: SEV_LABEL[sev] }),
          el('span', { class: 'count', text: `${group.length}` }),
        ),
        ...group.map(renderFindingRow),
      );
      root.append(section);
    }
  }

  function render() {
    renderTop();
    renderMetrics();
    renderBanners();
    renderScanProgress();
    renderFindings();
  }

  // scheduleRender coalesces multiple render() requests within a
  // single animation frame. SSE deltas land at burst rates (one event
  // per new/updated/resolved finding); with 1990+ findings during a
  // first-run scan, calling render() directly per event made the page
  // unresponsive — each render rebuilds the full finding list DOM. By
  // queuing render() onto the next rAF and dropping subsequent
  // schedule calls until that frame fires, we cap render frequency
  // at ~60Hz regardless of event burst rate.
  let renderQueued = false;
  function scheduleRender() {
    if (renderQueued) return;
    renderQueued = true;
    requestAnimationFrame(() => {
      renderQueued = false;
      render();
    });
  }

  // ----- Banner stack ---------------------------------------------
  // Stacks below the top bar. Scanner banners surface when a backend
  // is "unavailable" (sidecar not installed) or "error" (last scan
  // failed). daemon-state may also surface inotify-limit / remote-FS
  // hints; render them when present.
  function renderBanners() {
    const root = $('banners');
    root.replaceChildren();
    const banners = computeBanners();
    for (const b of banners) {
      if (state.dismissedBanners.has(b.id)) continue;
      root.append(renderBanner(b));
    }
  }

  function computeBanners() {
    const out = [];
    // Update-available banner — first in the stack so it never gets
    // hidden behind a half-screen of scanner warnings.
    const upd = (state.daemon || {}).update_available;
    if (upd && upd.version) {
      out.push({
        id: 'update:' + upd.version,
        kind: 'info',
        tag: 'UPDATE',
        text: `audr ${upd.version} is available (running ${(state.daemon && state.daemon.version) || 'unknown'}). Restart with the new binary to pick up newer rules.`,
        link: upd.url,
        linkLabel: 'View release',
      });
    }
    // Scanner banners — one per scanner that isn't ok.
    for (const sc of state.scanners) {
      const stateName = sc.state || sc.status; // wire field, defensive
      if (!stateName || stateName === 'ok') continue;
      const category = sc.name || sc.category;
      const fix = stateName === 'unavailable' || stateName === 'missing'
        ? guessInstallCommand(category)
        : '';
      out.push({
        id: `scanner:${category}:${stateName}`,
        kind: stateName === 'error' ? 'error' : 'warn',
        tag: `${(category || '?').toUpperCase()} ${stateName.toUpperCase()}`,
        text: sc.error_text || sc.errorText || defaultScannerMessage(category, stateName),
        fix,
      });
    }
    // Daemon-state hints — populated when daemon publishes them.
    const d = state.daemon || {};
    if (d.inotify_low) {
      out.push({
        id: 'inotify-low',
        kind: 'warn',
        tag: 'INOTIFY LIMIT',
        text: 'fsnotify watcher hit the kernel limit; some files won\'t trigger immediate rescans (periodic poll still covers them).',
        fix: 'echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.d/99-audr.conf && sudo sysctl -p',
      });
    }
    if (d.remote_fs_skipped) {
      out.push({
        id: 'remote-fs',
        kind: 'info',
        tag: 'REMOTE FS',
        text: `${d.remote_fs_skipped} mount(s) skipped (NFS / SMB / 9P / FUSE). Networked storage is intentionally excluded.`,
        fix: '',
      });
    }
    return out;
  }

  function renderBanner(b) {
    const node = el(
      'div',
      { class: 'banner ' + (b.kind === 'error' ? 'error' : b.kind === 'info' ? 'info' : '') },
      el('span', { class: 'banner-tag', text: b.tag }),
      el('span', { text: b.text }),
    );
    if (b.fix) {
      node.append(el('code', { class: 'fix', text: b.fix }));
    }
    if (b.link) {
      node.append(el('a', { href: b.link, target: '_blank', rel: 'noopener' }, b.linkLabel || 'open'));
    }
    node.append(el(
      'button',
      {
        class: 'dismiss',
        type: 'button',
        onclick: () => {
          state.dismissedBanners.add(b.id);
          renderBanners();
        },
      },
      'dismiss',
    ));
    return node;
  }

  function defaultScannerMessage(category, stateName) {
    if (stateName === 'unavailable' || stateName === 'missing') {
      return `${(category || 'scanner').toUpperCase()} scanner not installed — that category is being skipped.`;
    }
    if (stateName === 'error') {
      return `${(category || 'scanner').toUpperCase()} last scan errored — see daemon logs for detail.`;
    }
    if (stateName === 'outdated') {
      return `${(category || 'scanner').toUpperCase()} scanner is older than audr's minimum.`;
    }
    return `${(category || 'scanner').toUpperCase()}: ${stateName}`;
  }

  function guessInstallCommand(category) {
    if (category === 'secrets') return 'audr update-scanners --backend trufflehog --yes';
    if (category === 'deps')    return 'audr update-scanners --backend osv-scanner --yes';
    return '';
  }

  // ----- Scan-progress strip --------------------------------------
  // Always visible. Surfaces three states:
  //   1. STARTING UP    — daemon's first scan hasn't started yet
  //   2. INITIAL SCAN   — first full sweep of the machine, mid-flight
  //   3. RESCANNING     — periodic / change-triggered cycle, mid-flight
  //   4. WATCHING       — between scans, awaiting fsnotify or ticker
  //
  // Previous behavior hid the strip entirely between scans, which left
  // users wondering whether the daemon was doing anything at all.
  // Keeping it visible with a "WATCHING — last scan Xmin ago" line
  // resolves that.
  function renderScanProgress() {
    const root = $('scan-progress');
    const labelNode = $('scan-progress-text');
    const subNode = $('scan-progress-sub');

    root.removeAttribute('hidden');
    root.setAttribute('data-active', state.scanActive ? 'true' : 'false');

    let label, sub = '';
    if (state.scanActive) {
      if (state.firstScanCompleted) {
        label = 'RESCANNING';
        sub = 'change detected or periodic check';
      } else {
        label = 'INITIAL SCAN';
        sub = 'first full sweep of your machine';
      }
    } else if (state.firstScanCompleted) {
      label = 'WATCHING';
      sub = lastScanAgo();
    } else {
      label = 'STARTING UP';
      sub = 'first scan begins shortly';
    }
    labelNode.textContent = label;
    if (subNode) subNode.textContent = sub;

    const ol = $('scan-progress-categories');
    ol.replaceChildren();
    const byCategory = {};
    for (const sc of state.scanners) {
      const name = sc.name || sc.category;
      const stateName = sc.state || sc.status;
      if (name) byCategory[name] = stateName;
    }
    for (const cat of SCAN_CATEGORIES) {
      const stateName = byCategory[cat];
      let cls = 'pending';
      let stateLabel = 'PENDING';
      if (stateName === 'running') {
        cls = 'running';
        stateLabel = 'RUNNING';
      } else if (state.scanActive && !stateName) {
        // Scan is active but this category hasn't reported any
        // status yet — assume it's queued, render pending. Replaced
        // by an explicit "running" status from the orchestrator
        // once that category's backend starts.
        cls = 'pending';
        stateLabel = 'QUEUED';
      } else if (stateName === 'ok')          { cls = 'ok';          stateLabel = 'OK'; }
      else if (stateName === 'error')         { cls = 'error';       stateLabel = 'ERROR'; }
      else if (stateName === 'unavailable' || stateName === 'missing') {
        cls = 'unavailable'; stateLabel = 'OFF';
      } else if (stateName === 'outdated')    { cls = 'unavailable'; stateLabel = 'OUTDATED'; }
      ol.append(el(
        'li',
        { class: cls },
        el('span', { class: 'dot' }),
        el('span', { text: SCAN_CATEGORY_LABEL[cat] }),
        el('span', { style: 'margin-left:auto;color:var(--text-muted);', text: stateLabel }),
      ));
    }
  }

  // ----- Filter pills ---------------------------------------------
  function wireFilters() {
    document.querySelectorAll('.filter-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        const group = btn.dataset.filter; // "category" | "severity"
        const value = btn.dataset.value;
        state.filters[group] = value;
        for (const sib of document.querySelectorAll(`.filter-btn[data-filter="${group}"]`)) {
          sib.classList.toggle('active', sib === btn);
        }
        render();
      });
    });
  }

  // ----- SSE event stream -----------------------------------------
  // Subscribe to the store's event bus. Server forwards:
  //   - scan-started / scan-completed: scan-cycle bookends
  //   - finding-opened: new finding (or reopened after resolution)
  //   - finding-updated: re-detected, fields may have changed
  //   - finding-resolved: scanner no longer detects it, transitioned to resolved
  //   - scanner-status: per-category status changed (ok/error/unavailable)
  //   - daemon-state: RUN/SLOW/PAUSE transitions (Phase 3+)
  function connectEvents() {
    const url = '/api/events?t=' + encodeURIComponent(token);
    const src = new EventSource(url);

    src.addEventListener('hello', () => { /* connected */ });
    src.addEventListener('heartbeat', () => { /* keep-alive */ });

    src.addEventListener('finding-opened', (e) => {
      const f = parseEvent(e);
      if (!f) return;
      upsertFinding(f);
      recomputeMetrics();
      scheduleRender();
    });

    src.addEventListener('finding-updated', (e) => {
      const f = parseEvent(e);
      if (!f) return;
      upsertFinding(f);
      recomputeMetrics();
      scheduleRender();
    });

    src.addEventListener('finding-resolved', (e) => {
      const f = parseEvent(e);
      if (!f) return;
      animateResolution(f.fingerprint);
      if (state.metrics) {
        state.metrics.resolved_today = (state.metrics.resolved_today || 0) + 1;
        renderMetrics();
      }
    });

    src.addEventListener('scanner-status', (e) => {
      const s = parseEvent(e);
      if (!s) return;
      const key = s.name || s.category;
      const idx = state.scanners.findIndex((x) => (x.name || x.category) === key);
      if (idx >= 0) state.scanners[idx] = s;
      else state.scanners.push(s);
      renderScanProgress();
      renderBanners();
    });

    src.addEventListener('scan-started', () => {
      state.scanActive = true;
      // Don't reset state.scanners — old per-category statuses are
      // still relevant context until the new run overwrites them.
      renderScanProgress();
    });
    src.addEventListener('scan-completed', () => {
      state.scanActive = false;
      state.firstScanCompleted = true;
      state.lastScanCompletedAt = Date.now();
      renderScanProgress();
    });
    src.addEventListener('daemon-state', (e) => {
      const d = parseEvent(e);
      if (!d || !state.daemon) return;
      state.daemon.state = d.state || state.daemon.state;
      state.daemon.state_note = d.state_note || '';
      renderTop();
    });

    src.onerror = () => {
      // EventSource auto-reconnects respecting the server's retry: hint.
      // Phase 5 polish can add a "reconnecting..." state-indicator badge.
    };
  }

  // upsertFinding inserts or replaces by fingerprint. Safe to call
  // when an SSE event arrives for a finding that's already in the
  // snapshot — we just replace with the freshest payload.
  function upsertFinding(f) {
    const idx = state.findings.findIndex((x) => x.fingerprint === f.fingerprint);
    if (idx >= 0) state.findings[idx] = f;
    else state.findings.push(f);
  }

  // animateResolution drives the 5-second "fix it and watch it go
  // green" feedback loop:
  //   t=0      strikethrough + fade   (700ms transition via .resolving)
  //   t=800ms  start collapse         (500ms transition via .resolved-collapsing)
  //   t=5000ms remove from state + DOM
  // We keep the finding in state.findings during the animation so
  // re-renders (e.g., filter changes) don't drop it mid-animation;
  // state.resolving guards inclusion when those re-renders happen.
  function animateResolution(fingerprint) {
    if (state.resolving.has(fingerprint)) return;
    state.resolving.add(fingerprint);
    const row = document.querySelector(
      `.finding[data-fingerprint="${cssEscape(fingerprint)}"]`,
    );
    if (!row) {
      // Filtered out or scrolled off — drop it without animating.
      finalizeResolution(fingerprint);
      return;
    }
    row.classList.add('resolving');
    setTimeout(() => {
      const stillThere = document.querySelector(
        `.finding[data-fingerprint="${cssEscape(fingerprint)}"]`,
      );
      if (stillThere) stillThere.classList.add('resolved-collapsing');
    }, 800);
    setTimeout(() => finalizeResolution(fingerprint), 5000);
  }

  function finalizeResolution(fingerprint) {
    state.findings = state.findings.filter((x) => x.fingerprint !== fingerprint);
    state.expanded.delete(fingerprint);
    state.resolving.delete(fingerprint);
    recomputeMetrics();
    scheduleRender();
  }

  // cssEscape escapes a fingerprint for use in a querySelector
  // attribute value. Fingerprints are sha256 hex, but CSS.escape is
  // the durable choice for any future ID scheme.
  function cssEscape(s) {
    if (typeof CSS !== 'undefined' && CSS.escape) return CSS.escape(s);
    return String(s).replace(/[^a-zA-Z0-9_-]/g, (c) => `\\${c}`);
  }

  // recomputeMetrics rebuilds the metric strip totals from state.findings.
  // The initial snapshot's metrics.resolved_today is preserved since
  // SSE deltas don't include that count; finding-resolved handlers
  // bump it directly.
  function recomputeMetrics() {
    const m = {
      open_total: 0, open_critical: 0, open_high: 0, open_medium: 0, open_low: 0,
      resolved_today: (state.metrics && state.metrics.resolved_today) || 0,
    };
    for (const f of state.findings) {
      m.open_total++;
      const k = 'open_' + f.severity;
      if (k in m) m[k]++;
    }
    state.metrics = m;
  }

  function parseEvent(e) {
    try { return JSON.parse(e.data); } catch { return null; }
  }

  // ----- Helpers --------------------------------------------------
  function formatRelative(iso) {
    if (!iso) return '?';
    const t = new Date(iso).getTime();
    if (isNaN(t)) return iso;
    const delta = (Date.now() - t) / 1000;
    if (delta < 60) return 'just now';
    if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
    if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
    return `${Math.floor(delta / 86400)}d ago`;
  }

  // lastScanAgo formats state.lastScanCompletedAt as a human relative
  // phrase for the WATCHING sub-label. Empty string when no scan has
  // completed yet in this session (the dashboard JS doesn't yet read
  // the most-recent completed timestamp from the snapshot — that's
  // tracked as a v0.4.x followup).
  function lastScanAgo() {
    // If the dashboard loaded between scans we don't yet know when
    // the last one finished — surface a neutral phrase rather than
    // overclaim. After the next scan-completed SSE event the
    // timestamp populates and we switch to "last scan X min ago".
    // Plumbing the most-recent completed_at through the snapshot is
    // tracked as a v0.4.x followup.
    if (!state.lastScanCompletedAt) return 'fsnotify + 5min poll';
    const delta = (Date.now() - state.lastScanCompletedAt) / 1000;
    if (delta < 60)    return 'last scan just now';
    if (delta < 3600)  return `last scan ${Math.floor(delta / 60)} min ago`;
    if (delta < 86400) return `last scan ${Math.floor(delta / 3600)} hr ago`;
    return `last scan ${Math.floor(delta / 86400)} d ago`;
  }

  // ----- Boot -----------------------------------------------------
  async function load() {
    try {
      const snap = await apiGet('/api/findings');
      state.findings = snap.findings || [];
      state.metrics = snap.metrics;
      state.daemon = snap.daemon;
      state.scanners = snap.scanners || [];
      // A scanner row in the snapshot means at least one scan cycle
      // has completed (or the daemon recorded sidecar statuses
      // pre-cycle). Either way, treat first-run as past so the
      // progress strip doesn't surface unless an SSE scan-started
      // event flips scanActive.
      if (state.scanners.length > 0) {
        state.firstScanCompleted = true;
      }
      // If a scan is in flight when the dashboard loads, set
      // scanActive directly from the snapshot — we'd otherwise miss
      // the scan-started SSE event of an already-running scan and
      // wrongly show "WAITING FOR FIRST SCAN" until the scan
      // completed.
      if (state.daemon && state.daemon.scan_in_progress) {
        state.scanActive = true;
      }
      render();
    } catch (e) {
      document.getElementById('findings').replaceChildren(
        el('div', { class: 'empty', text: 'failed to load findings: ' + e.message }),
      );
    }
  }

  document.getElementById('reload').addEventListener('click', (e) => {
    e.preventDefault();
    load();
  });

  wireFilters();
  load();
  connectEvents();
})();
