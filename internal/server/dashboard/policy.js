// audr policy editor — Alpine.js `x-data` factory backing the
// declarative bindings in policy.html. htmx loaded separately for
// any future server-fragment integration; today the editor stays on
// fetch() for the policy save/validate calls because the JSON
// round-trip is easier to reason about than HTML-fragment swaps for
// a structured form.
//
// Visual contract pinned by the mockup at
// ~/.gstack/projects/harshmaur-audr/designs/policy-editor-20260515/mockup.html
//
// Why Alpine: the entire policy editor is one reactive form bound to
// an in-memory draft Policy. Without Alpine we'd be re-rendering the
// rule list manually on every toggle; with Alpine the bindings are
// declarative and the re-render is automatic.

/* global Alpine */

(function () {
  "use strict";

  function getTokenFromURL() {
    return new URLSearchParams(location.search).get("t") || "";
  }

  // Expose for the htmx hx-headers binding in policy.html.
  window.getToken = getTokenFromURL;

  // Alpine x-data factory. Bound on <body>. Every reactive field
  // (draft, persisted, rules, banners, etc.) is declared in the
  // returned object; Alpine sees them and re-renders bindings when
  // any are mutated.
  window.policyEditor = function policyEditor() {
    return {
      // --- Identity / nav ---
      token: getTokenFromURL(),
      path: "",
      tab: "form",
      activeCategory: "all",
      filterText: "",

      // --- Data ---
      persisted: { version: 1 }, // server-last-known
      policy: { version: 1 },    // mirror for top-bar version label
      rules: [],
      yamlText: "",
      banners: [],

      // --- UI state ---
      saving: false,
      justSaved: false,
      modal: null,         // null | "diff" | "destructive"
      confirmInput: "",
      diffLines: [],
      staleOnDisk: false,

      // YAML view status — reflects last validation result.
      get yamlStatus() {
        if (!this.yamlText.trim()) return "";
        if (this.yamlValid) return "✓ valid";
        return "✗ " + (this.yamlError || "invalid");
      },
      get yamlStatusClass() {
        if (!this.yamlText.trim()) return "rule-pane-meta";
        return this.yamlValid ? "rule-pane-meta valid" : "rule-pane-meta invalid";
      },

      // ---------- Initial load ----------

      async init() {
        if (!this.token) {
          document.body.innerHTML =
            '<p style="padding:24px;font-family:monospace;color:#f5f5f0;background:#0e0e0c">' +
            "Missing token. Open the dashboard via <code>audr open</code> instead of pasting the URL directly." +
            "</p>";
          return;
        }
        await this.load();
        this.attachCancelGuards();
        this.openServerSentEvents();
      },

      async load() {
        try {
          const data = await this.apiGet("/api/policy");
          this.rules = data.rules || [];
          this.persisted = JSON.parse(JSON.stringify(data.policy));
          this.draft = JSON.parse(JSON.stringify(data.policy));
          this.policy = this.draft;
          this.path = data.path || "~/.audr/policy.yaml";
          this.yamlText = data.yaml || "";
          this._lastYamlFromServer = this.yamlText;
          this.yamlValid = true;
          this.yamlError = "";
          this.staleOnDisk = false;
          if (data.warnings && data.warnings.length) {
            for (const w of data.warnings) {
              this.banners.push({ kind: "warn", message: w });
            }
          }
        } catch (err) {
          this.banners.push({
            kind: "error",
            message: "Failed to load policy: " + err.message,
          });
        }
      },

      async reload() {
        if (this.dirty && !confirm("Discard unsaved changes and reload from disk?")) {
          return;
        }
        await this.load();
      },

      openServerSentEvents() {
        // Subscribe to the daemon's SSE channel; the watcher pushes
        // "policy-changed" events when the file is hand-edited on
        // disk. Reuses the main dashboard's /api/events endpoint;
        // we filter to the policy-relevant event.
        try {
          const url = new URL("/api/events", location.origin);
          url.searchParams.set("t", this.token);
          const es = new EventSource(url.toString());
          es.addEventListener("policy-changed", () => {
            // If the user has no unsaved edits, auto-reload silently.
            // Otherwise mark the on-disk-stale banner so they can
            // choose between their edits and the new on-disk state.
            if (!this.dirty) {
              this.load();
            } else {
              this.staleOnDisk = true;
            }
          });
          // Best-effort — if /api/events isn't reachable yet (daemon
          // booting) the dashboard still works, just without the
          // file-change pulse.
          es.onerror = () => {
            // Silent — main dashboard handles connection state UI.
          };
        } catch (e) {
          // SSE not available — proceed without live reload.
        }
      },

      // ---------- Computed ----------

      get dirty() {
        if (!this.draft) return false;
        // YAML tab dirty counts too — the user may have only edited
        // there. Either side being out of sync with persisted means
        // "user has unsaved work."
        if (this.yamlTabDirty()) return true;
        return JSON.stringify(this.draft) !== JSON.stringify(this.persisted);
      },

      get draftSafe() {
        if (!this.draft) {
          this.draft = JSON.parse(JSON.stringify(this.persisted));
          this.policy = this.draft;
        }
        return this.draft;
      },

      isEnabled(ruleID) {
        const ov = this.draftSafe.rules && this.draftSafe.rules[ruleID];
        if (!ov || ov.enabled === undefined || ov.enabled === null) return true;
        return ov.enabled !== false;
      },

      effectiveSeverity(rule) {
        const ov = this.draftSafe.rules && this.draftSafe.rules[rule.id];
        if (ov && ov.severity) return ov.severity;
        return rule.default_severity;
      },

      hasScope(ruleID) {
        const ov = this.draftSafe.rules && this.draftSafe.rules[ruleID];
        if (!ov || !ov.scope) return false;
        return (
          (ov.scope.include && ov.scope.include.length) ||
          (ov.scope.exclude && ov.scope.exclude.length)
        );
      },

      scopeMetaText(ruleID) {
        const ov = this.draftSafe.rules[ruleID];
        const parts = [];
        if (ov.scope.include && ov.scope.include.length) {
          parts.push("include: " + ov.scope.include.join(" "));
        }
        if (ov.scope.exclude && ov.scope.exclude.length) {
          parts.push("exclude: " + ov.scope.exclude.join(" "));
        }
        return parts.join(" · ");
      },

      categoryList() {
        const counts = new Map();
        for (const r of this.rules) {
          const c = r.category || "Other";
          counts.set(c, (counts.get(c) || 0) + 1);
        }
        const out = [{ label: "All", count: this.rules.length, value: "all" }];
        const cats = [...counts.keys()].sort();
        for (const c of cats) out.push({ label: c, count: counts.get(c), value: c });
        return out;
      },

      filteredRules() {
        const f = this.filterText.toLowerCase();
        return this.rules.filter((r) => {
          if (this.activeCategory !== "all" && (r.category || "Other") !== this.activeCategory) {
            return false;
          }
          if (f) {
            return (
              r.id.toLowerCase().includes(f) ||
              (r.title || "").toLowerCase().includes(f)
            );
          }
          return true;
        });
      },

      paneTitle() {
        return this.activeCategory === "all" ? "All rules" : this.activeCategory + " rules";
      },

      paneMeta() {
        const filtered = this.filteredRules();
        const enabled = filtered.filter((r) => this.isEnabled(r.id)).length;
        return filtered.length + " rules · " + enabled + " enabled";
      },

      unsavedLabel() {
        const overrides = this.draftSafe.rules || {};
        const persistedRules = this.persisted.rules || {};
        let changes = 0;
        const ids = new Set([
          ...Object.keys(overrides),
          ...Object.keys(persistedRules),
        ]);
        for (const id of ids) {
          if (JSON.stringify(overrides[id]) !== JSON.stringify(persistedRules[id])) {
            changes++;
          }
        }
        return changes > 0 ? "Unsaved (" + changes + ")" : "Unsaved";
      },

      // ---------- Mutations ----------

      ensureOverride(ruleID) {
        this.draftSafe.rules = this.draftSafe.rules || {};
        if (!this.draftSafe.rules[ruleID]) this.draftSafe.rules[ruleID] = {};
        return this.draftSafe.rules[ruleID];
      },

      cleanOverride(ruleID) {
        const ov = this.draftSafe.rules && this.draftSafe.rules[ruleID];
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
        if (empty) delete this.draftSafe.rules[ruleID];
      },

      toggleRule(rule) {
        const cur = this.isEnabled(rule.id);
        this.ensureOverride(rule.id).enabled = !cur;
        this.cleanOverride(rule.id);
      },

      setSeverity(rule, value) {
        if (value === rule.default_severity) {
          if (this.draftSafe.rules && this.draftSafe.rules[rule.id]) {
            delete this.draftSafe.rules[rule.id].severity;
            this.cleanOverride(rule.id);
          }
        } else {
          this.ensureOverride(rule.id).severity = value;
        }
      },

      // ---------- Allowlist CRUD ----------

      addAllowlist() {
        if (!this.draftSafe.allowlists) this.draftSafe.allowlists = {};
        // Pick a unique placeholder name. The user renames it to
        // something meaningful via the inline rename input.
        let i = 1;
        let name = "new-allowlist";
        while (this.draftSafe.allowlists[name]) {
          name = "new-allowlist-" + ++i;
        }
        this.draftSafe.allowlists[name] = { entries: [], notes: "" };
      },

      renameAllowlist(oldName, newName) {
        newName = (newName || "").trim();
        if (!newName || oldName === newName) return;
        if (this.draftSafe.allowlists[newName]) {
          this.banners.push({
            kind: "warn",
            message: 'Allowlist "' + newName + '" already exists; rename ignored',
          });
          return;
        }
        this.draftSafe.allowlists[newName] = this.draftSafe.allowlists[oldName];
        delete this.draftSafe.allowlists[oldName];
        // Update any rule.allowlists references to the new name.
        const rules = this.draftSafe.rules || {};
        for (const id of Object.keys(rules)) {
          const al = rules[id].allowlists;
          if (al && Array.isArray(al)) {
            rules[id].allowlists = al.map((x) => (x === oldName ? newName : x));
          }
        }
      },

      removeAllowlist(name) {
        if (!confirm('Delete allowlist "' + name + '"?')) return;
        delete this.draftSafe.allowlists[name];
        // Strip references from rules.
        const rules = this.draftSafe.rules || {};
        for (const id of Object.keys(rules)) {
          if (Array.isArray(rules[id].allowlists)) {
            rules[id].allowlists = rules[id].allowlists.filter((x) => x !== name);
            if (rules[id].allowlists.length === 0) delete rules[id].allowlists;
            this.cleanOverride(id);
          }
        }
      },

      addAllowlistEntry(name) {
        if (!this.draftSafe.allowlists[name]) return;
        if (!this.draftSafe.allowlists[name].entries) {
          this.draftSafe.allowlists[name].entries = [];
        }
        this.draftSafe.allowlists[name].entries.push("");
      },

      updateAllowlistEntry(name, index, value) {
        if (!this.draftSafe.allowlists[name]) return;
        const entries = this.draftSafe.allowlists[name].entries;
        if (!entries || index < 0 || index >= entries.length) return;
        entries[index] = value;
      },

      removeAllowlistEntry(name, index) {
        if (!this.draftSafe.allowlists[name]) return;
        const entries = this.draftSafe.allowlists[name].entries;
        if (!entries || index < 0 || index >= entries.length) return;
        entries.splice(index, 1);
      },

      updateAllowlistNotes(name, notes) {
        if (!this.draftSafe.allowlists[name]) return;
        this.draftSafe.allowlists[name].notes = notes;
      },

      // ---------- Suppression CRUD ----------

      addSuppression() {
        if (!this.draftSafe.suppressions) this.draftSafe.suppressions = [];
        this.draftSafe.suppressions.push({
          rule: "",
          path: "",
          reason: "",
        });
      },

      updateSuppression(index, field, value) {
        if (!this.draftSafe.suppressions) return;
        const s = this.draftSafe.suppressions[index];
        if (!s) return;
        if (field === "expires" && !value) {
          delete s.expires;
        } else {
          s[field] = value;
        }
      },

      removeSuppression(index) {
        if (!this.draftSafe.suppressions) return;
        if (!confirm("Delete this suppression?")) return;
        this.draftSafe.suppressions.splice(index, 1);
      },

      // ---------- YAML tab editing ----------
      //
      // The textarea is the source-of-truth in YAML view. On change:
      //   1. Debounced validate via POST /api/policy/yaml/validate.
      //   2. UI shows valid/invalid status inline.
      //   3. Save (via SAVE button) POSTs YAML to /api/policy/yaml
      //      which parses, validates, persists, and returns the
      //      canonical re-marshal that swaps back into the textarea.

      yamlValid: true,
      yamlError: "",

      async onYAMLChange() {
        // Don't validate empty edits — let the user clear and
        // re-type. The save flow still validates on actual save.
        if (!this.yamlText.trim()) {
          this.yamlValid = true;
          this.yamlError = "";
          return;
        }
        try {
          const res = await fetch(
            "/api/policy/yaml/validate?t=" + this.token,
            {
              method: "POST",
              headers: { "Content-Type": "application/yaml" },
              body: this.yamlText,
            }
          );
          const json = await res.json();
          this.yamlValid = !!json.valid;
          this.yamlError = json.errors ? (json.errors[0] || "") : "";
        } catch (err) {
          this.yamlValid = false;
          this.yamlError = err.message;
        }
      },

      // ---------- Save flow ----------

      openDiffModal() {
        this.computeDiff();
        this.confirmInput = "";
        this.modal = this.isDestructive() ? "destructive" : "diff";
      },

      closeModal() {
        this.modal = null;
      },

      computeDiff() {
        const lines = [];
        const persistedRules = this.persisted.rules || {};
        const draftRules = this.draftSafe.rules || {};

        // Rule deltas.
        const ruleIDs = new Set([
          ...Object.keys(persistedRules),
          ...Object.keys(draftRules),
        ]);
        for (const id of [...ruleIDs].sort()) {
          const a = persistedRules[id];
          const b = draftRules[id];
          if (JSON.stringify(a) === JSON.stringify(b)) continue;
          // Enabled flip.
          const aEnabled = !a || a.enabled === undefined || a.enabled === null ? true : a.enabled !== false;
          const bEnabled = !b || b.enabled === undefined || b.enabled === null ? true : b.enabled !== false;
          if (aEnabled !== bEnabled) {
            lines.push({
              kind: bEnabled ? "added" : "removed",
              text: "rules." + id + ".enabled: " + aEnabled + " → " + bEnabled,
            });
          }
          // Severity.
          const aSev = a && a.severity ? a.severity : null;
          const bSev = b && b.severity ? b.severity : null;
          if (aSev !== bSev) {
            lines.push({
              kind: bSev ? "added" : "removed",
              text: "rules." + id + ".severity: " +
                (aSev || "(default)") + " → " + (bSev || "(default)"),
            });
          }
          // Scope.
          if (JSON.stringify((a && a.scope) || {}) !== JSON.stringify((b && b.scope) || {})) {
            lines.push({
              kind: "added",
              text: "rules." + id + ".scope: changed",
            });
          }
        }

        // Allowlists.
        const persistedAls = this.persisted.allowlists || {};
        const draftAls = this.draftSafe.allowlists || {};
        const alNames = new Set([
          ...Object.keys(persistedAls),
          ...Object.keys(draftAls),
        ]);
        for (const name of [...alNames].sort()) {
          if (JSON.stringify(persistedAls[name]) !== JSON.stringify(draftAls[name])) {
            lines.push({
              kind: draftAls[name] ? "added" : "removed",
              text: "allowlists." + name + ": " +
                (draftAls[name] ? "set" : "removed"),
            });
          }
        }

        // Suppressions.
        const persistedSupps = this.persisted.suppressions || [];
        const draftSupps = this.draftSafe.suppressions || [];
        if (JSON.stringify(persistedSupps) !== JSON.stringify(draftSupps)) {
          lines.push({
            kind: "added",
            text: "suppressions: " + persistedSupps.length + " → " + draftSupps.length,
          });
        }

        this.diffLines = lines;
      },

      diffCountLabel() {
        const n = this.diffLines.length;
        return n + " change" + (n === 1 ? "" : "s") + " to " + (this.path || "~/.audr/policy.yaml");
      },

      // Destructive heuristic per plan B4.2. Fires on ANY of:
      //   - ≥5 rule disables
      //   - severity downgrade on a critical-default rule
      //   - any allowlist deletion
      //   - any non-expired suppression deletion
      // We compute this from the diff plus the rule catalog (which
      // carries each rule's default severity).
      isDestructive() {
        const persistedRules = this.persisted.rules || {};
        const draftRules = this.draftSafe.rules || {};
        let disables = 0;
        let criticalDowngrade = false;
        const ruleCatalog = new Map(this.rules.map((r) => [r.id, r]));
        for (const id of Object.keys({ ...persistedRules, ...draftRules })) {
          const a = persistedRules[id];
          const b = draftRules[id];
          const aEnabled = !a || a.enabled === undefined || a.enabled === null ? true : a.enabled !== false;
          const bEnabled = !b || b.enabled === undefined || b.enabled === null ? true : b.enabled !== false;
          if (aEnabled && !bEnabled) disables++;

          // Severity downgrade on critical-default rules.
          const catalog = ruleCatalog.get(id);
          if (catalog && catalog.default_severity === "critical") {
            const bSev = b && b.severity ? b.severity : catalog.default_severity;
            if (bSev !== "critical") criticalDowngrade = true;
          }
        }
        if (disables >= 5) return true;
        if (criticalDowngrade) return true;

        // Allowlist deletions.
        const persistedAls = this.persisted.allowlists || {};
        const draftAls = this.draftSafe.allowlists || {};
        for (const name of Object.keys(persistedAls)) {
          if (!draftAls[name]) return true;
        }

        // Suppression deletions (non-expired only).
        const persistedSupps = this.persisted.suppressions || [];
        const draftSupps = this.draftSafe.suppressions || [];
        const draftKey = new Set(draftSupps.map((s) => s.rule + "::" + s.path));
        const now = new Date();
        for (const s of persistedSupps) {
          if (s.expires) {
            const exp = new Date(s.expires);
            if (!Number.isNaN(exp.getTime()) && exp < now) continue;
          }
          if (!draftKey.has(s.rule + "::" + s.path)) return true;
        }
        return false;
      },

      destructiveSummary() {
        const persistedRules = this.persisted.rules || {};
        const draftRules = this.draftSafe.rules || {};
        const ruleCatalog = new Map(this.rules.map((r) => [r.id, r]));
        let disables = 0;
        const criticalDowngrades = [];
        for (const id of Object.keys({ ...persistedRules, ...draftRules })) {
          const a = persistedRules[id];
          const b = draftRules[id];
          const aEnabled = !a || a.enabled === undefined || a.enabled === null ? true : a.enabled !== false;
          const bEnabled = !b || b.enabled === undefined || b.enabled === null ? true : b.enabled !== false;
          if (aEnabled && !bEnabled) disables++;
          const catalog = ruleCatalog.get(id);
          if (catalog && catalog.default_severity === "critical") {
            const bSev = b && b.severity ? b.severity : catalog.default_severity;
            if (bSev !== "critical") criticalDowngrades.push(id + " → " + bSev);
          }
        }
        const out = [];
        if (disables > 0) out.push(disables + " rule" + (disables === 1 ? "" : "s") + " will be disabled");
        for (const x of criticalDowngrades) {
          out.push("Critical-default rule " + x);
        }
        const persistedAls = this.persisted.allowlists || {};
        const draftAls = this.draftSafe.allowlists || {};
        for (const name of Object.keys(persistedAls)) {
          if (!draftAls[name]) {
            const count = (persistedAls[name].entries || []).length;
            out.push("Allowlist " + name + " deleted (" + count + " entries)");
          }
        }
        return out;
      },

      // Effective scope after save: rule-count summary used in the
      // diff modal's "you'll have N rules at Critical" stat strip.
      scopeAfter() {
        const before = this.countBy(this.persisted);
        const after = this.countBy(this.draftSafe);
        return {
          enabled: after.enabled,
          enabledDelta: after.enabled - before.enabled,
          critical: after.critical,
          criticalDelta: after.critical - before.critical,
          high: after.high,
          highDelta: after.high - before.high,
        };
      },

      countBy(pol) {
        const ov = pol.rules || {};
        let enabled = 0, critical = 0, high = 0;
        for (const r of this.rules) {
          const o = ov[r.id];
          const isOn = !o || o.enabled === undefined || o.enabled === null ? true : o.enabled !== false;
          if (isOn) enabled++;
          const sev = o && o.severity ? o.severity : r.default_severity;
          if (isOn && sev === "critical") critical++;
          if (isOn && sev === "high") high++;
        }
        return { enabled, critical, high };
      },

      async save() {
        if (this.modal === "destructive" && this.confirmInput.trim() !== "I understand") {
          return;
        }
        this.saving = true;
        try {
          let resp;
          // YAML tab dirty: POST raw YAML so the server's parser is
          // authoritative + the user keeps the file shape they typed
          // (modulo canonicalization on next save).
          if (this.tab === "yaml" && this.yamlTabDirty()) {
            resp = await this.apiPostYAML(this.yamlText);
          } else {
            resp = await this.apiPost("/api/policy", this.draftSafe);
          }
          this.persisted = JSON.parse(JSON.stringify(resp.policy));
          this.draft = JSON.parse(JSON.stringify(resp.policy));
          this.policy = this.draft;
          this.yamlText = resp.yaml || "";
          this._lastYamlFromServer = this.yamlText;
          this.yamlValid = true;
          this.yamlError = "";
          this.staleOnDisk = false;
          this.justSaved = true;
          this.modal = null;
          this.confirmInput = "";
          setTimeout(() => { this.justSaved = false; }, 600);
        } catch (err) {
          this.banners.push({
            kind: "error",
            message: "Save failed: " + err.message,
          });
        } finally {
          this.saving = false;
        }
      },

      // yamlTabDirty: are we on the YAML tab AND the user has typed
      // something different than what the server returned? If so the
      // YAML save path runs; otherwise the JSON-form save path runs.
      // Catches the case where the user opens the YAML tab to look,
      // then switches back to Form — we shouldn't POST YAML the user
      // never edited.
      yamlTabDirty() {
        if (!this._lastYamlFromServer) return false;
        return this.yamlText.trim() !== this._lastYamlFromServer.trim();
      },
      _lastYamlFromServer: "",

      async apiPostYAML(yamlBody) {
        const url = new URL("/api/policy/yaml", location.origin);
        url.searchParams.set("t", this.token);
        const res = await fetch(url.toString(), {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/yaml",
            Accept: "application/json",
          },
          body: yamlBody,
        });
        if (!res.ok) {
          const text = await res.text();
          throw new Error("/api/policy/yaml: " + res.status + " — " + text.slice(0, 200));
        }
        return res.json();
      },

      // ---------- YAML highlighter ----------
      //
      // Tiny inline highlighter that runs against the canonical
      // YAML the server returned. Goals: visually distinguish keys
      // vs strings vs numbers vs booleans vs comments. Not a full
      // YAML parser; the underlying file is canonical so we know
      // the shape stays predictable.
      //
      // Replaces CodeMirror 6 (which would need an npm-built bundle).
      // ~60 lines instead of ~150KB; covers the visual contract.

      highlightYAML(src) {
        if (!src) return "";
        // Escape HTML first.
        const escaped = src
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;");
        // Process line-by-line so multi-line patterns don't bleed.
        const lines = escaped.split("\n");
        const out = lines.map((line) => {
          // Comment lines.
          if (/^\s*#/.test(line)) {
            return '<span class="yaml-comment">' + line + "</span>";
          }
          // Mid-line comment (after a space + #).
          let highlighted = line.replace(
            /( +#.*)$/,
            '<span class="yaml-comment">$1</span>'
          );
          // Key: value pattern at start of line (after any indent).
          highlighted = highlighted.replace(
            /^(\s*)([\w.-]+)(:)( *)(.*)$/,
            (m, indent, key, colon, sp, val) => {
              const valOut = this.highlightYAMLValue(val);
              return indent +
                '<span class="yaml-key">' + key + "</span>" +
                colon + sp + valOut;
            }
          );
          // List items.
          highlighted = highlighted.replace(
            /^(\s*)(-)( +)(.*)$/,
            (m, indent, dash, sp, val) => {
              const valOut = this.highlightYAMLValue(val);
              return indent + '<span class="yaml-dash">' + dash + "</span>" + sp + valOut;
            }
          );
          return highlighted;
        });
        return out.join("\n");
      },

      highlightYAMLValue(val) {
        if (!val) return "";
        // Strings.
        if (/^['"].*['"]\s*$/.test(val)) {
          return '<span class="yaml-str">' + val + "</span>";
        }
        // Booleans.
        if (/^(true|false)\s*$/.test(val)) {
          return '<span class="yaml-bool">' + val + "</span>";
        }
        // Numbers.
        if (/^-?\d+(\.\d+)?\s*$/.test(val)) {
          return '<span class="yaml-num">' + val + "</span>";
        }
        // Bracketed inline arrays.
        if (/^\[.*\]\s*$/.test(val)) {
          return '<span class="yaml-array">' + val + "</span>";
        }
        // ISO 8601 dates (suppression expires).
        if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\s*$/.test(val)) {
          return '<span class="yaml-num">' + val + "</span>";
        }
        // Plain scalar.
        return val;
      },

      yamlReadOnlyNotice() {
        return "Read-only in v1.2.x — edit via Form tab or hand-edit policy.yaml on disk.";
      },

      // ---------- Cancel / unload guards ----------

      cancelGuard(e) {
        if (!this.dirty) return;
        if (!confirm("You have unsaved changes. Discard and leave?")) {
          if (e && e.preventDefault) e.preventDefault();
          return false;
        }
      },

      attachCancelGuards() {
        window.addEventListener("beforeunload", (e) => {
          if (this.dirty) {
            e.preventDefault();
            e.returnValue = "";
            return "";
          }
        });
      },

      // ---------- Fetch helpers ----------

      async apiGet(path) {
        const url = new URL(path, location.origin);
        url.searchParams.set("t", this.token);
        const res = await fetch(url.toString(), {
          credentials: "same-origin",
          headers: { Accept: "application/json" },
        });
        if (!res.ok) throw new Error(path + ": " + res.status + " " + res.statusText);
        return res.json();
      },

      async apiPost(path, body) {
        const url = new URL(path, location.origin);
        url.searchParams.set("t", this.token);
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
          throw new Error(path + ": " + res.status + " — " + text.slice(0, 200));
        }
        return res.json();
      },
    };
  };
})();
