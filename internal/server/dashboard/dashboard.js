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
  };

  // ----- Top bar / metrics ----------------------------------------
  function renderTop() {
    const d = state.daemon || { state: 'OFFLINE', version: 'unknown' };
    const dot = $('state-dot');
    const label = $('state-label');
    const meta = $('state-meta');
    dot.className = 'pulse-dot ' + ({ RUN: '', SLOW: 'slow', PAUSE: 'pause', OFFLINE: 'offline' }[d.state] || 'offline');
    label.textContent = d.state || 'OFFLINE';
    meta.textContent = d.state_note ? '· ' + d.state_note : '';

    const scan = $('scan-status');
    scan.replaceChildren();
    if (d.scan_target) {
      scan.append('SCANNING ', el('code', { text: d.scan_target }), ` · ${d.scan_done || 0} / ${d.scan_total || 0}`);
    }
    $('version').textContent = d.version || 'unknown';
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
    const row = el(
      'article',
      {
        class: 'finding',
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
    renderFindings();
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

  // ----- SSE event stream (Phase 2: connectivity only) -----------
  function connectEvents() {
    const url = '/api/events?t=' + encodeURIComponent(token);
    const src = new EventSource(url);
    src.addEventListener('hello', () => {
      // Connected. Phase 3+ subscribes to finding-* events here.
    });
    src.addEventListener('heartbeat', () => { /* keep-alive */ });
    src.onerror = () => {
      // EventSource auto-reconnects respecting the server's retry: hint.
      // Phase 2 just lets it ride; no UI feedback yet.
    };
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

  // ----- Boot -----------------------------------------------------
  async function load() {
    try {
      const snap = await apiGet('/api/findings');
      state.findings = snap.findings || [];
      state.metrics = snap.metrics;
      state.daemon = snap.daemon;
      state.scanners = snap.scanners || [];
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
