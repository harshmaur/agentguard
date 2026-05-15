// audr policy editor — vanilla JS, no build step.
//
// Renders the Form + YAML tabs over the /api/policy + /api/rules
// endpoints. Save flow: POST /api/policy with the JSON form; the
// server canonicalizes and returns the on-disk YAML which the
// editor swaps back in.
//
// Visual contract pinned by the mockup at
// ~/.gstack/projects/harshmaur-audr/designs/policy-editor-20260515/mockup.html.
//
// Anti-slop:
//   - No drop shadows, no gradients, no emoji.
//   - Severity is conveyed by both color AND uppercase text.
//   - Honors prefers-reduced-motion (CSS handles the animation case).

(() => {
  "use strict";

  const params = new URLSearchParams(location.search);
  const token = params.get("t") || "";
  if (!token) {
    document.body.innerHTML =
      '<p style="padding:24px;font-family:monospace;color:#f5f5f0;background:#0e0e0c">' +
      "Missing token. Open the dashboard via <code>audr open</code> instead of pasting the URL directly." +
      "</p>";
    return;
  }

  // ----- State ---------------------------------------------------

  // The Policy we'd save right now. Starts as a deep copy of the
  // server's view and gets mutated by form interactions.
  let draft = null;
  // The Policy as it was last persisted server-side. Used to compute
  // "is there anything to save?".
  let persisted = null;
  // The rule catalog (id, title, default severity, category) from
  // the server.
  let rules = [];
  // The current category selection in the left rail. "all" shows
  // every rule.
  let activeCategory = "all";
  // Free-text filter from the search input.
  let filterText = "";

  // ----- API helpers --------------------------------------------

  async function apiGet(path) {
    const url = new URL(path, location.origin);
    url.searchParams.set("t", token);
    const res = await fetch(url.toString(), {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    if (!res.ok) throw new Error(`${path}: ${res.status} ${res.statusText}`);
    return res.json();
  }

  async function apiPost(path, body) {
    const url = new URL(path, location.origin);
    url.searchParams.set("t", token);
    const res = await fetch(url.toString(), {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`${path}: ${res.status} — ${text.slice(0, 200)}`);
    }
    return res.json();
  }

  // ----- Initial load -------------------------------------------

  async function load() {
    try {
      const data = await apiGet("/api/policy");
      rules = data.rules || [];
      persisted = clone(data.policy);
      draft = clone(data.policy);
      document.getElementById("yaml-textarea").value = data.yaml || "";
      document.getElementById("path-label").textContent = data.path;
      document.getElementById("version-label").textContent =
        "v" + (data.policy.version || 1);
      renderBanners(data.warnings);
      renderCategoryList();
      renderRules();
      updateUnsavedIndicator();
    } catch (err) {
      renderBanner("error", "Failed to load policy: " + err.message);
    }
  }

  function clone(o) { return JSON.parse(JSON.stringify(o)); }

  // ----- Rendering: banners --------------------------------------

  function renderBanners(warnings) {
    const stack = document.getElementById("banners");
    stack.innerHTML = "";
    if (warnings && warnings.length) {
      for (const w of warnings) renderBanner("warn", w, stack);
    }
  }

  function renderBanner(kind, message, stack) {
    stack = stack || document.getElementById("banners");
    const el = document.createElement("div");
    el.className = "banner banner-" + kind;
    el.setAttribute("role", "status");
    el.textContent = message;
    const close = document.createElement("button");
    close.className = "banner-close";
    close.textContent = "×";
    close.setAttribute("aria-label", "Dismiss");
    close.onclick = () => el.remove();
    el.appendChild(close);
    stack.appendChild(el);
  }

  // ----- Rendering: category nav --------------------------------

  function renderCategoryList() {
    const counts = new Map();
    for (const r of rules) {
      const c = r.category || "Other";
      counts.set(c, (counts.get(c) || 0) + 1);
    }
    const ul = document.getElementById("category-list");
    ul.innerHTML = "";
    const renderItem = (label, count, value) => {
      const li = document.createElement("li");
      li.className = "category-item" + (activeCategory === value ? " active" : "");
      li.onclick = () => {
        activeCategory = value;
        renderCategoryList();
        renderRules();
      };
      li.setAttribute("role", "button");
      li.tabIndex = 0;
      li.innerHTML =
        '<span>' + escapeHTML(label) + '</span>' +
        '<span class="count">' + count + '</span>';
      ul.appendChild(li);
    };
    renderItem("All", rules.length, "all");
    const cats = [...counts.keys()].sort();
    for (const c of cats) renderItem(c, counts.get(c), c);
  }

  // ----- Rendering: rule list -----------------------------------

  function renderRules() {
    const list = document.getElementById("rule-list");
    const title = document.getElementById("rule-pane-title");
    const meta = document.getElementById("rule-pane-meta");

    const filtered = rules.filter((r) => {
      if (activeCategory !== "all" && (r.category || "Other") !== activeCategory) return false;
      if (filterText) {
        const f = filterText.toLowerCase();
        return r.id.toLowerCase().includes(f) ||
          (r.title || "").toLowerCase().includes(f);
      }
      return true;
    });

    title.textContent = activeCategory === "all" ? "All rules" : activeCategory + " rules";
    const enabledCount = filtered.filter((r) => effectiveEnabled(r.id)).length;
    meta.textContent = filtered.length + " rules · " + enabledCount + " enabled";

    list.innerHTML = "";
    if (!filtered.length) {
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = filterText
        ? 'No rules match "' + filterText + '". Clear filter.'
        : "No rules in this category.";
      list.appendChild(empty);
      return;
    }
    for (const r of filtered) list.appendChild(ruleRow(r));
  }

  function effectiveEnabled(ruleID) {
    const ov = draft.rules && draft.rules[ruleID];
    if (!ov || ov.enabled === undefined || ov.enabled === null) return true;
    return ov.enabled !== false;
  }
  function effectiveSeverity(rule) {
    const ov = draft.rules && draft.rules[rule.id];
    if (ov && ov.severity) return ov.severity;
    return rule.default_severity;
  }

  function ruleRow(rule) {
    const enabled = effectiveEnabled(rule.id);
    const severity = effectiveSeverity(rule);

    const row = document.createElement("article");
    row.className = "rule-row" + (enabled ? "" : " disabled");

    // Toggle.
    const toggle = document.createElement("button");
    toggle.className = "rule-toggle" + (enabled ? " on" : "");
    toggle.setAttribute("aria-pressed", String(enabled));
    toggle.setAttribute("aria-label",
      (enabled ? "Disable " : "Enable ") + "rule " + rule.id);
    toggle.onclick = () => {
      const cur = effectiveEnabled(rule.id);
      ensureOverride(rule.id).enabled = !cur;
      cleanOverride(rule.id);
      markDirty();
      renderRules();
    };
    row.appendChild(toggle);

    // Meta column.
    const meta = document.createElement("div");
    meta.className = "rule-meta";
    const id = document.createElement("div");
    id.className = "rule-id";
    id.textContent = rule.id;
    const desc = document.createElement("div");
    desc.className = "rule-desc";
    desc.textContent = rule.title || "(no description)";
    meta.appendChild(id);
    meta.appendChild(desc);

    const scopeOv = (draft.rules && draft.rules[rule.id] && draft.rules[rule.id].scope) || null;
    if (scopeOv && (scopeOv.include || scopeOv.exclude)) {
      const scope = document.createElement("div");
      scope.className = "rule-scope-meta";
      const parts = [];
      if (scopeOv.include && scopeOv.include.length) {
        parts.push("include: " + scopeOv.include.join(" "));
      }
      if (scopeOv.exclude && scopeOv.exclude.length) {
        parts.push("exclude: " + scopeOv.exclude.join(" "));
      }
      scope.textContent = parts.join(" · ");
      meta.appendChild(scope);
    }
    row.appendChild(meta);

    // Severity dropdown (a real <select> styled like the pill).
    const sev = document.createElement("select");
    sev.className = "severity-pill " + severity;
    sev.setAttribute("aria-label", "Severity for " + rule.id);
    for (const s of ["critical", "high", "medium", "low"]) {
      const opt = document.createElement("option");
      opt.value = s;
      opt.textContent = s.toUpperCase();
      if (s === severity) opt.selected = true;
      sev.appendChild(opt);
    }
    sev.onchange = () => {
      if (sev.value === rule.default_severity) {
        // Reverting to natural — drop the override.
        if (draft.rules && draft.rules[rule.id]) {
          delete draft.rules[rule.id].severity;
          cleanOverride(rule.id);
        }
      } else {
        ensureOverride(rule.id).severity = sev.value;
      }
      markDirty();
      renderRules();
    };
    if (!enabled) sev.disabled = true;
    row.appendChild(sev);

    return row;
  }

  function ensureOverride(ruleID) {
    draft.rules = draft.rules || {};
    if (!draft.rules[ruleID]) draft.rules[ruleID] = {};
    return draft.rules[ruleID];
  }
  function cleanOverride(ruleID) {
    // Drop overrides that are now empty so the file stays terse.
    const ov = draft.rules && draft.rules[ruleID];
    if (!ov) return;
    const empty =
      (ov.enabled === undefined || ov.enabled === null) &&
      !ov.severity &&
      (!ov.scope || (
        (!ov.scope.include || !ov.scope.include.length) &&
        (!ov.scope.exclude || !ov.scope.exclude.length)
      )) &&
      (!ov.allowlists || !ov.allowlists.length) &&
      !ov.notes;
    if (empty) delete draft.rules[ruleID];
  }

  // ----- Save flow ----------------------------------------------

  async function save() {
    const btn = document.getElementById("save-btn");
    btn.disabled = true;
    btn.textContent = "Saving…";
    try {
      const resp = await apiPost("/api/policy", draft);
      persisted = clone(resp.policy);
      draft = clone(resp.policy);
      document.getElementById("yaml-textarea").value = resp.yaml || "";
      document.getElementById("version-label").textContent =
        "v" + (resp.policy.version || 1);
      btn.classList.add("pulse");
      btn.textContent = "Saved";
      setTimeout(() => {
        btn.classList.remove("pulse");
        updateUnsavedIndicator();
      }, 600);
      renderRules();
    } catch (err) {
      btn.disabled = false;
      btn.textContent = "Save";
      renderBanner("error", "Save failed: " + err.message);
    }
  }

  function updateUnsavedIndicator() {
    const btn = document.getElementById("save-btn");
    const ind = document.getElementById("unsaved-indicator");
    const dirty = JSON.stringify(draft) !== JSON.stringify(persisted);
    if (dirty) {
      btn.disabled = false;
      btn.textContent = "Save";
      ind.hidden = false;
      document.getElementById("unsaved-count").textContent = "Unsaved";
    } else {
      btn.disabled = true;
      btn.textContent = "Save";
      ind.hidden = true;
    }
  }

  function markDirty() {
    updateUnsavedIndicator();
  }

  // ----- YAML tab -----------------------------------------------

  let yamlValidateTimer = null;
  function onYAMLChange() {
    if (yamlValidateTimer) clearTimeout(yamlValidateTimer);
    yamlValidateTimer = setTimeout(() => {
      // For v1.2 we skip server-side YAML parsing (would require a
      // YAML→JSON adapter on the server). The user can still save
      // via Form view. Document the limitation in the status line
      // so users know to use the form for live edits in v1.2.0.
      document.getElementById("yaml-status").textContent =
        "YAML view is read-only in v1.2 — edit via Form tab or hand-edit policy.yaml on disk.";
      document.getElementById("yaml-status").className = "rule-pane-meta";
    }, 200);
  }

  // ----- Tab switching ------------------------------------------

  function showForm() {
    document.getElementById("tab-form").classList.add("active");
    document.getElementById("tab-yaml").classList.remove("active");
    document.getElementById("tab-form").setAttribute("aria-selected", "true");
    document.getElementById("tab-yaml").setAttribute("aria-selected", "false");
    document.getElementById("form-view").hidden = false;
    document.getElementById("yaml-view").hidden = true;
  }
  function showYAML() {
    document.getElementById("tab-form").classList.remove("active");
    document.getElementById("tab-yaml").classList.add("active");
    document.getElementById("tab-form").setAttribute("aria-selected", "false");
    document.getElementById("tab-yaml").setAttribute("aria-selected", "true");
    document.getElementById("form-view").hidden = true;
    document.getElementById("yaml-view").hidden = false;
  }

  // ----- Cancel + reload + tab-close guard ----------------------

  function dirty() {
    return JSON.stringify(draft) !== JSON.stringify(persisted);
  }

  function attachCancelGuards() {
    const guard = (e) => {
      if (!dirty()) return;
      if (!confirm("You have unsaved changes. Discard and leave?")) {
        e.preventDefault();
        return false;
      }
    };
    for (const id of ["back-link", "cancel-link", "footer-back"]) {
      const el = document.getElementById(id);
      if (el) el.addEventListener("click", (e) => {
        if (!dirty()) return;
        if (!confirm("You have unsaved changes. Discard and leave?")) {
          e.preventDefault();
        }
      });
    }
    window.addEventListener("beforeunload", (e) => {
      if (dirty()) {
        e.preventDefault();
        e.returnValue = "";
        return "";
      }
    });
  }

  // ----- Wiring -------------------------------------------------

  function wire() {
    document.getElementById("tab-form").addEventListener("click", showForm);
    document.getElementById("tab-yaml").addEventListener("click", showYAML);
    document.getElementById("save-btn").addEventListener("click", save);
    document.getElementById("filter-input").addEventListener("input", (e) => {
      filterText = e.target.value;
      renderRules();
    });
    document.getElementById("reload-link").addEventListener("click", (e) => {
      e.preventDefault();
      if (dirty() && !confirm("Discard unsaved changes and reload from disk?")) return;
      load();
    });
    document.getElementById("yaml-textarea").addEventListener("input", onYAMLChange);

    // Append token to all in-app navigation so we don't lose auth.
    for (const id of ["back-link", "cancel-link", "footer-back"]) {
      const el = document.getElementById(id);
      if (el) el.href = "/?t=" + encodeURIComponent(token);
    }
    attachCancelGuards();
  }

  function escapeHTML(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // ----- Init ---------------------------------------------------

  wire();
  load();
})();
