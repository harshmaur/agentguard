# Changelog

All notable changes to Audr.
Format follows [Keep a Changelog](https://keepachangelog.com/), versioning is `MAJOR.MINOR.PATCH`.

## [0.10.1] - 2026-05-16 — Dashboard nav: POLICY link in the topbar

Small UX fix on top of v1.3. The audit dashboard now has a `POLICY` link in
the top-right of the topbar, so the policy editor at `/policy/edit` is one
click away instead of a URL you had to memorise.

### Added

- **POLICY link in the topbar.** Renders in the existing IBM Plex Mono
  monospace voice, muted by default, underlined on hover. Sits at the
  right edge of the topbar, next to the scan-status strip.
- **Auth token preserved across in-app navigation.** `annotateNavTokens()`
  rewrites every `.nav-link`'s href on page load to append the same
  `?t=<token>` query the dashboard was opened with. No re-auth required
  when clicking through. Same-origin only — absolute URLs are skipped
  so a future template author can't accidentally leak the token offsite.
- **`aria-current="page"`** on the active route gets a colored bottom
  border, so when you're on the policy editor the POLICY link in its
  own topbar (already wired in v0.7.0) shows as active.

### Changed

- **Topbar grid** widens from `200px 1fr 1fr` to `200px 1fr 1fr auto` to
  accommodate the new nav block. The < 1280px responsive breakpoint
  was extended so the nav block stacks left-aligned with the rest of
  the topbar contents in narrow viewports.

## [0.10.0] - 2026-05-15 — v1.3 Loveable Daily Driver: dedup engine + rolled-up dashboard

The founder ran `audr scan ~` on their own machine and got 1700+ findings.
Could see the right observations. Could see the suggested fixes. Could not
bring themselves to start. v1.3 is the response: dedup by vulnerability,
group affected paths by who can fix them, render override snippets the
user can paste into their own package manifest, render pre-filled GitHub
issue URLs the user can fire at plugin maintainers. One row per CVE, three
fix-authority buckets per row, no wall of text.

The "AV-feel default-green dashboard with streaks and a threat-banner card"
(Approach B in the design doc) ships in v1.4 once the dedup pass earns
five voluntary dashboard opens in a row. Active quarantine (Approach C)
follows in v1.5.

### Added

- **Roll-up by dedup_group_key.** New `internal/triage/` package owns
  classification: every finding now carries a `DedupGroupKey` (collapsing
  the same vulnerability across paths) and a `FixAuthority` enum
  (`you` / `maintainer` / `upstream`). Path-class table in
  `triage/authority.go` resolves authority from the affected path — user
  projects fall through to `you`, plugin cache paths resolve to
  `maintainer` with a vendor hint, marketplace external_plugins resolve
  to `upstream`. Secret findings always force `you` (rotation is your
  job no matter where the leak appeared) but keep the maintainer hint
  in `SecondaryNotify` so the dashboard can render "also notify <vendor>".

- **Per-package OSV dedup.** OSV findings used to dedup per (package, CVE)
  → a package with 8 CVEs showed as 8 rows. Now they dedup per package
  with `max(fixed_version)` carried in the dedup key. The override snippet
  pins to the max fixed version, which resolves all known CVEs for that
  package in one upgrade.

- **Override-snippet rendering.** New `internal/remediate/lockfile.go`
  renders package-manager-specific override blocks for npm
  (`overrides`), yarn (`resolutions`), pnpm (`pnpm.overrides`),
  bun (`overrides`), go (`replace`), and cargo (`[patch.crates-io]`).
  Driven by `internal/remediate/osv.go` which parses the OSV dedup key
  back into `(ecosystem, package, fixed_version)` and cross-checks the
  ecosystem against the detected lockfile format (F6 guard — refuses to
  emit a go-replace snippet against a yarn.lock).

- **Pre-filled GitHub issue URLs.** New `internal/remediate/maintainers.go`
  maps known plugin vendors (Vercel claude-plugins-official, Anthropic
  marketplace, Cursor) to canonical `/issues/new` endpoints with
  title/body pre-filled from the finding. Unknown vendors fall back to
  a clipboard-copy of the Markdown body so the user can paste into
  whichever tracker the maintainer publishes. URLs are capped at 8KB to
  stay within GitHub's pre-fill limit.

- **Override-snippet F3 disclaimer.** Every snippet ships with a one-line
  banner adjacent to the code: *"This override pins the transitive dep.
  Verify your build + tests pass before committing — semver compatibility
  isn't guaranteed when bypassing a maintainer's resolution."* Honest
  about the tradeoff so audr doesn't get blamed when an override breaks
  a build.

- **Three new server endpoints.** `GET /api/findings/rollup` returns
  rolled-up rows + path-authority sub-groups. `GET /api/remediate/snippet/{fp}`
  renders the override snippet for a specific finding.
  `GET /api/remediate/maintainer/{fp}` returns the issue URL + body for
  the "File issue with <vendor>" button.

- **Schema v3 migration.** Three nullable columns added to the `findings`
  table (`dedup_group_key`, `fix_authority`, `secondary_notify`) plus
  two indexes (`findings_dedup_group`, `findings_fix_authority`).
  Existing findings are wiped on migrate; next scan repopulates with
  triage metadata. The daemon prints a one-shot
  *"audr v1.3 dedup engine: finding history reset; this scan is the
  baseline."* notice on the first post-v3 startup.

### Changed

- **Dashboard renders rolled-up rows by default.** No new route; the
  existing `/` dashboard's `renderFindingRow` now displays one
  vulnerability per row with a `<n> paths` badge. Expanded detail shows
  three fix-authority sub-cards inside the existing `.expanded-detail`
  panel — same visual language as v1.2 (severity bar, sev-label,
  cat-tag, dark theme, IBM Plex Mono/Sans). Filters, severity sections,
  banner stack, metric strip, scan progress strip: unchanged.

- **SSE-driven refresh.** Incremental finding-* upsert handlers
  replaced with a debounced re-fetch of `/api/findings/rollup` — fewer
  moving parts, server-aggregated truth, no in-JS aggregation race
  conditions. Resolution animations were removed for v1.3; metric
  counts stay live via the same SSE channel.

### Manual QA (the parts that don't fit a Go integration test)

After upgrading, walk through these flows on your own machine:

1. **Copy-snippet → fix → rescan clears.** Pick a YOU-bucket dep finding.
   Copy the override snippet. Paste into your project's `package.json`
   (or equivalent). Run `npm install` (or `pnpm install`, `yarn`, etc.).
   Wait for the next daemon scan (or trigger one). The finding should
   resolve. The row should disappear from the rolled-up view.

2. **File-issue button opens a pre-filled GitHub issue.** Pick a
   MAINTAINER-bucket finding (one whose path lives in
   `~/.claude/plugins/cache/<vendor>/...`). Click the "File issue with
   <vendor>" button. A new browser tab opens to
   `github.com/<vendor>/.../issues/new` with the title and body
   (CVE id, affected versions, paths) pre-filled.

3. **Track-upstream is a hint, not a button (v1.3).** UPSTREAM-bucket
   findings show a static "only the original maintainer can fix this"
   note. The 30-day snooze action ships in v1.4 alongside the streak
   and health-score primitives.

### Notes for v1.4 / v1.5

- v1.4 (TODO 8 in `TODOS.md`) adds the default-green dashboard, streak
  primitive, health score, and threat-banner card — the actual "AV-feel"
  overlay. Gated on the v1.3 dogfood signal: 5 voluntary dashboard
  opens in a row earns the next investment.
- v1.5 (TODO 9 in `TODOS.md`) adds active quarantine for critical chains
  with one-click undo. Trust bar is much higher than v1.3; gets its
  own office-hours session before scoping.
- v1.3's hardcoded path-class table (~20 entries in
  `internal/triage/authority.go`) is forward-compatible with TODO 10
  (user-extensible entries via policy.yaml).

## [0.9.0] - 2026-05-16 — Resolved-counter accuracy, parallel sidecars, 1-core daemon trufflehog

Multiple fixes to the daemon scan loop. The dashboard's "Resolved Today"
metric no longer inflates with phantom resolutions, the secret scanner
no longer pegs every core in the background, and the OSV scanners now
run alongside trufflehog instead of waiting for it to finish.

### Fixed

- **Resolved-counter inflation from browser-cache churn.** Brave,
  Chrome, Chromium, Edge, and Firefox user-data directories on Linux,
  macOS, and Windows are now in `scanignore.Defaults()`. Browsers
  auto-update component-filter extensions every few hours and ship
  hundreds of URLs in each new version dir; trufflehog's URI detector
  fired on every one of those URLs and the orchestrator resolved the
  old version dir's findings the moment the browser deleted it. On a
  typical developer machine, this single source produced 95%+ of the
  daemon's "resolved today" entries. The browser caches contain no
  audit signal for audr's purposes — there's no reason to scan them.

- **Resolved-counter inflation from binary-blob noise.** APK / IPA /
  AAB / DEX, native libraries (`.so`/`.dll`/`.dylib`), JVM archives
  (`.jar`/`.war`/`.class`), executables, archives (`.zip`/`.tar.gz`/
  etc.), images, audio, video, fonts, and compiled Python now all
  match a new `BinaryFileExtensions()` allowlist written into
  trufflehog's `--exclude-paths`. The trufflehog URI detector hits
  random byte sequences in binary blobs that look like
  `http://x:y@host`, producing different "matches" each scan and an
  endless churn of fingerprint-resolve-reopen for a single 8MB Android
  APK build artifact.

- **Resolved-counter inflation from scanner-status conflation.** When
  a scanner errored, was disabled, or was unavailable, every
  previously-open finding in its category got mass-resolved on the
  next cycle because it wasn't in the cycle's `seen` set. Next scan,
  those findings re-opened — often under different fingerprints,
  leaving phantom "resolved today" rows that never aged out.
  `orchestrator.runOnce` now tracks each previously-open finding's
  category and only resolves findings whose scanner reported `status:
  ok` this cycle. If trufflehog times out, secret findings stay open
  until the next successful scan instead of flashing green.

- **Resolved-counter inflation from verification flapping.**
  TruffleHog's verification API (rate limits, transient network
  failures, briefly-revoked keys) caused the same secret to flip
  between `secret-trufflehog-verified` and `secret-trufflehog-unverified`
  scan to scan. Because rule_id is part of the fingerprint hash, each
  flip resolved the old row and opened a new one — even though the
  secret never moved. `convert.go`'s new `fingerprintRuleID()` helper
  collapses both rule-id variants to a stable `secret-trufflehog` for
  fingerprint hashing; the row's actual rule_id and severity still
  update on re-detection via the updated `UpsertFinding`, so dashboards,
  severity, and remediation templates stay accurate.

### Changed

- **Daemon TruffleHog concurrency dropped from `NumCPU/2` to 1.** The
  daemon runs continuously in the background while you're doing actual
  work — peak CPU matters more than scan latency. Even with `nice 19`
  (via the lowprio wrapper), `--concurrency=4` on an 8-core developer
  laptop kept ~450% CPU pinned during the secret scan because nice
  only yields under contention. New `secretscan.DefaultDaemonJobs()`
  returns 1 unconditionally; `secretscan.DefaultJobs()` (used by
  one-shot `audr scan`, where you're sitting there waiting) stays at
  `NumCPU/2`. Daemon scans now hold to roughly one core.

- **Sidecar scanners run in parallel.** Native rules still run first
  (they walk the filesystem and would contend with trufflehog for the
  page cache), then secrets + deps + os-pkg launch concurrently as
  goroutines synced by a `WaitGroup`. trufflehog is CPU+disk and
  capped at one worker; osv-scanner for deps and os-pkg is dominated
  by network IO against `api.osv.dev`. Running them serially burned
  ~30s per cycle waiting on the OSV API while trufflehog wasn't using
  the network anyway. Each scanner gets its own private `seen` map
  (no mutex needed; the state store is already single-writer-safe via
  its writer goroutine), and the orchestrator unions them before
  resolution detection.

### Removed

Nothing.

## [0.8.1] - 2026-05-16 — `audr open` diagnostic fix

Hotfix for a pre-v0.4 message that survived the daemon refactor and
shipped through v0.8.0.

### Fixed

- **`audr open` no longer prints "the dashboard HTTP server lands in
  phase 2 of the v1 build".** The "running but state file missing"
  diagnostic in `cmd/audr/open.go` carried copy from the Phase 1
  scaffold (pre-v0.4 — before the dashboard HTTP server shipped).
  In every release since v0.4, the daemon's service status returning
  "running" with no state file actually means one of:
  1. Daemon just started; the state file is written AFTER the HTTP
     server's Bind() succeeds — usually 50–500ms later but can drift
     to several seconds on cold-start with sidecar reprobing.
  2. HTTP server failed to bind (port in use, permission, etc.) and
     the daemon is alive but useless.

  `audr open` now polls the state file for up to 3 seconds when the
  service reports running. If it appears, opens the browser. If
  not, surfaces the daemon log path (`Paths.LogFile()`) so the user
  can read the actual bind error. Also handles the intermediate
  case where the state file appears but the port still isn't
  answering yet — prints the URL and the log path with "wait and
  retry" guidance.
- **`audr open` "stopped" branch** also dropped its stale Phase 1
  reference ("the dashboard HTTP server lands in phase 2; for now
  `audr daemon start` runs the scaffolded daemon only"). Replaced
  with the concrete `Run: audr daemon start` next step.

## [0.8.0] - 2026-05-16 — Notification subsystem removed; trust story simplified

Major surface reduction. v0.4.2–v0.7.x carried OS-native toast notifications across Linux (dbus + ActionInvoked click routing), macOS (terminal-notifier-or-osascript with the brew-install dance), and Windows (beeep + the WinRT/AppUserModelID work that was still planned for v1.1.x). The polish was real, the complexity was a tax — three OSes worth of preflight registry probes, permission prompts, focus-mode detection, debouncing, batching, cooldown, dedup, pending-fallback files, dashboard banners surfacing dropped toasts. The dashboard already serves the live finding stream via SSE — toasts were a nice-to-have that was actively expensive to maintain.

Removed. The dashboard is the product. `audr open` is one command. Users who want a "something fired" signal can keep the dashboard tab open; the SSE stream is already live. v0.8.0 trades the toast UI for ~2120 deleted lines, kills the v1.1.x WinRT work entirely before it was ever built, and lets the trust story stop apologizing for unsigned Windows binaries.

### Removed

- **`internal/notify/`** package (5 .go files, ~1240 lines): the cross-platform Toaster + ClickableToaster + LifecycleToaster interfaces, Linux godbus toaster with ActionInvoked listener, macOS terminal-notifier-or-osascript toaster, Windows beeep fallback, the entire cooldown/dedup/rate-cap/first-scan-suppression policy machinery, and the pending-notify.json fallback file.
- **`cmd/audr/notify_preflight_{linux,darwin,windows,other}.go`** (4 files, ~480 lines): Linux libnotify probe, macOS Script Editor permission detection + focus-mode detection, Windows registry probes (ToastEnabled, NoToastApplicationNotification, NOC_GLOBAL_SETTING_TOASTS_ENABLED, AppUserModelID Start Menu shortcut), BSD no-op.
- **`audr daemon notify`** CLI subcommand and its `--off / --on / --status / --test` flags. The on-demand verification toast UX, the disabled-vs-enabled state file at `${state_dir}/notify.config.json`, all gone.
- **macOS osascript notification-permission probe** at `audr daemon install` time.
- **Notifier daemon subsystem** from the lifecycle chain in `cmd/audr/daemon.go`.
- **`DELETE /api/notify/pending`** server endpoint + `handleNotifyPendingDismiss` handler.
- **`DaemonInfo.PendingNotifications`** field + the snapshot path that populated it.
- **`NOTIFICATIONS DROPPED`** dashboard banner in `dashboard.js`.
- **Dependencies:** `github.com/gen2brain/beeep` and `github.com/godbus/dbus/v5` dropped from `go.mod` (transitively, also their child deps from `go.sum`).
- **Planned-but-never-built:** v1.1.x WinRT toaster + AppUserModelID Start Menu shortcut registration. Codex outside-voice review flagged this as the single highest schedule risk in the audr roadmap; it never had to ship and never will.

### Changed

- **`audr daemon install` on macOS** no longer fires the osascript permission-prompt probe. Install is silent on every OS now.
- **TODO 5 (Windows Authenticode signing)** marked closed in `TODOS.md`. audr is open-source; the EV-cert recurring spend isn't worth removing a first-run SmartScreen warning that a SHA-256-verifying installer already mitigates. The cosign-signed `SHA256SUMS` is the trust anchor; users verify it, click "Run anyway" once, and `Unblock-File` clears the Zone.Identifier for subsequent runs. Re-open the TODO if a paying customer demands Authenticode and underwrites the cert.

### Migration note for users on v0.7.x

If you were using `audr daemon notify --off / --on / --status / --test`, the subcommand is gone. Notifications themselves are gone. Keep the dashboard tab open in your browser for the live stream; `audr open` opens it. Existing `${state_dir}/notify.config.json` and `${state_dir}/pending-notify.json` files on disk are harmless — the daemon no longer reads or writes them. You can `rm` them at your leisure.

## [0.7.2] - 2026-05-16 — v1.3 Policy Editor UI completeness

Closes the two surfaces v1.2.x explicitly named as v1.3 deferrals: full
allowlist + suppression editing UI in the dashboard, and a server-side
YAML round-trip parser that makes the YAML tab editable. The policy
editor is now complete end-to-end — every field in the on-disk
`policy.yaml` schema is reachable through both the Form view (curated)
and the YAML view (raw).

### Added — Allowlist + suppression editing UI

Two new categories in the policy editor's left rail under a "Lists"
section heading: **Allowlists** and **Suppressions**.

**Allowlists pane** — CRUD over named string-sets that rules consult
via `ctx.AllowlistContains(name, item)`. Each allowlist card surfaces:
inline rename input (renaming auto-updates references in
`rules.*.allowlists`), one-row-per-entry editing with per-entry
remove buttons, an "+ Add entry" affordance with dashed border, a
free-text `notes:` field that round-trips through canonical YAML,
and a delete-allowlist button with confirmation.

**Suppressions pane** — CRUD over `(rule, path, reason)` triples.
Each card uses a 2x2 grid of label-over-input controls:
  - **Rule** — `<select>` populated from the live rule catalog. No
    free-typing — every suppression references a rule audr actually
    knows about.
  - **Path glob** — free-text matching the file's path. Tooltip
    hint about glob semantics.
  - **Expires** — optional RFC3339 timestamp. Empty clears the
    field.
  - **Reason** — required free text. Validation rejects whitespace-
    only on save; the explainer above the list states why.

Both surfaces participate in the dirty/save flow already established
in v0.7.1: changes mark the SAVE button live, the diff preview modal
shows allowlist + suppression deltas, and the destructive-action
confirm gate fires when an allowlist or non-expired suppression is
deleted.

### Added — Server-side YAML round-trip

- **`POST /api/policy/yaml`** — accepts raw YAML body (`Content-Type:
  application/yaml`), parses through `policy.Parse`, validates,
  persists via the same `policy.Save` path as the JSON endpoint, and
  returns the canonical YAML the server actually wrote. The
  canonical-generated contract still applies — comments and field
  order are rewritten on save, the header comment explains this.
- **`POST /api/policy/yaml/validate`** — same parse + validate flow
  without persisting. Used by the dashboard's debounced-as-you-type
  lint loop.

The dashboard's YAML tab is now editable. As-you-type:
- 300ms debounced validate hits `/api/policy/yaml/validate`.
- Inline status indicator next to the editor header shows `✓ valid`
  (green) or `✗ <error>` (red).
- Save (via the SAVE button) routes through `/api/policy/yaml` when
  the YAML tab has unsaved edits; Form-view edits still route
  through the existing `/api/policy` JSON path. The save flow
  picks the right endpoint automatically — `yamlTabDirty()`
  compares the textarea content against the last server response.

### Tests

8 new server-side tests: PUT YAML valid round-trip, PUT YAML rejects
invalid (422), validate-yaml with 4 cases (valid / bad severity /
missing reason / malformed YAML), every YAML endpoint requires the
token, and the editor page renders all 4 new UI surface markers
(`__allowlists__`, `__suppressions__`, "+ Add allowlist", "+ Add
suppression").

### Changed

- **Policy editor `dirty` getter** now considers YAML-tab edits — a
  user who only touched the YAML tab still sees the SAVE button
  enabled and the unsaved-changes indicator.
- **`category-section-label`** class added to the dashboard for the
  "Lists" sub-heading in the left rail.
- **`readAllBody` test helper** swapped from a 16KB-capped manual
  read to `io.ReadAll` — the policy.html grew past 16KB with the
  new UI elements and the test was silently truncating.

## [0.7.1] - 2026-05-16 — v1.2.x Policy Editor UI (htmx + Alpine, diff modal, fsnotify)

Lands the four pieces v1.2.0 deferred — the planned dashboard stack, the diff-preview modal, the destructive-action confirm gate, and the fsnotify-driven live reload. The policy editor now matches the design-reviewed mockup end-to-end.

### Added

- **htmx + Alpine.js vendored** under `internal/server/dashboard/vendor/` as single-file `//go:embed` blobs. No Node toolchain in the audr repo's build; no `package.json`, no `npm ci`. Provenance, SHA-256 hashes, and upgrade procedure documented in `VENDORED.md` so the audit story stays intact. Single-file libs were picked specifically because they don't drag in build-time complexity: htmx is ~50KB unminified-and-uncompressed (~14KB gzipped over the wire), Alpine is ~45KB unminified (~15KB gzipped).
- **Policy editor refactored to use the planned stack.** `policy.html` is now an Alpine `x-data="policyEditor()"`-rooted page with declarative bindings throughout — `:class`, `x-show`, `x-text`, `x-for`, `@click`, `x-model`. The 350-line vanilla-JS `policy.js` becomes a clean factory function returning a single reactive object; bindings re-render automatically when its fields mutate. htmx attributes are wired in for future server-fragment integration (`hx-headers='js:{"X-Audr-Token": getToken()}'`); v1.2.x uses fetch+JSON for the structured form round-trip because policy state is genuinely tabular, but the seam is in place.
- **Diff preview modal (plan B4.1).** Clicking SAVE opens a modal showing the unified diff against the persisted policy plus an "Effective scope after save" stat strip (rules enabled / at Critical / at High, with deltas). Color + glyph signal kind: `+` green for additions, `−` red for removals. Anti-slop: no drop shadows, no gradients, no emoji, no decorative chrome. Backdrop is `rgba(14,14,12,0.85)`; modal is a centered 720px surface with hairline border.
- **Destructive-action confirm gate (plan B4.2).** Fires when the diff includes ANY of: ≥5 rule disables, severity downgrade on a critical-default rule, allowlist deletion, non-expired suppression deletion. The same modal shell becomes the destructive-confirm view: header gains a `⚠ Destructive change` tag (amber `--high` foreground, mono uppercase), summary bullets list the destructive deltas, the diff collapses behind a "Show full diff" toggle, and the confirm button stays disabled until the user types `I understand` into the inline input. Pressing Enter in the input submits when the phrase matches exactly.
- **Tiny inline YAML highlighter** for the YAML tab. ~60 lines of regex-based highlighting inside `policy.js` covers keys, strings, numbers, booleans, comments, list dashes, inline arrays, and ISO 8601 dates. Renders into a `<pre class="yaml-overlay">` positioned behind a transparent `<textarea>` so the user sees highlighted text while editing into a real textarea (no `contenteditable` footguns). Replaces the deferred CodeMirror 6 plan: ~60 lines instead of a 150KB ESM bundle that would need a Node build step. The YAML tab remains read-only in v1.2.x — primary editing happens in the Form view.
- **fsnotify policy watcher** (`internal/policy/watcher.go`). New `Watcher` and `Subsystem` types. Watches the parent directory of `~/.audr/policy.yaml` (not the inode — atomic-rename saves invalidate file-inode watches), filters for the specific file basename, debounces bursts within 150ms (a single save typically fires write+chmod+rename in <10ms), and invokes its onChange callback at most once per logical save. Wired as a daemon subsystem after the orchestrator + server in registration order (closes before them on shutdown). On fire, publishes a new `state.EventPolicyChanged` event; the dashboard's SSE stream forwards it as `event: policy-changed`. The policy editor listens for that event:
  - **No unsaved edits:** silently reloads the policy from disk.
  - **Unsaved edits present:** shows a "policy.yaml changed on disk" banner in the eyebrow with an inline reload button. User decides between their in-flight edits and the new on-disk state.

### Changed

- **`internal/state.Publish(Event)` is now exported.** Daemon subsystems outside `state/` (the policy watcher today; future hot-reload signals tomorrow) push events through this entry point. The lowercase `publish` helper is unchanged for internal Store callers.
- **`policy.css` doubled in size.** Added the modal styling (backdrop, hairline-bordered modal, unified diff colors, scope-summary stat strip, destructive-warning tag, confirm input section), the YAML textarea-overlay positioning math, and an `[x-cloak]` rule so pre-hydration HTML doesn't flash unstyled Alpine bindings.

### Tests

- 8 watcher tests covering fire-on-write, debounce, sibling-file filtering, dir auto-creation, idempotent Close, nil-callback rejection, parallel-write stress (80 writes from 8 goroutines must coalesce to ≤10 callbacks).
- 7 server-side policy-endpoint tests: GET returns the catalog + canonical YAML, POST persists and returns canonical YAML, POST rejects malformed severity with 422, POST `/validate` works without writing, GET `/rules` returns the catalog standalone, every endpoint rejects missing tokens, the editor page references both vendor scripts.

### What's still deferred

- **Allowlist + suppression editing UI.** v1.2.x covers rule overrides (toggle, severity, scope). Adding/editing allowlists and suppressions through the dashboard form view lands in v1.3 — the file format already supports both surfaces, and `audr policy edit` opens the YAML directly for users who need them now.
- **Server-side YAML round-trip parser.** The YAML tab is read-only in v1.2.x because round-tripping a hand-edited YAML through the `Policy` struct requires a YAML-aware diff that preserves the user's text. Plumbing exists for v1.3 to make the YAML tab fully editable.

## [0.7.0] - 2026-05-16 — v1.2 Policy Lake

User-editable rule-behavior overlay. Built-in detection logic stays Go-coded; v1.2 ships the surface that lets users adjust HOW those rules behave: disable per-rule, override severity, narrow scope, manage named allowlists, and suppress findings with required reasons. The whole spec from the v1.2 policy lake plan, end-to-end.

This is a **policy overlay system**, not a rules-as-data refactor. Custom rule definitions (Semgrep-style YAML detection logic) stay deferred to v1.3 per TODO 7 — the distinction matters: this release changes how existing rules behave, it does not add new detection logic.

### Added — Policy overlay

- **`internal/policy/` package** — full `Policy` type with `Load` / `Save` / `Validate` / `MarshalCanonical` / `Hash`. The on-disk file at `~/.audr/policy.yaml` is canonical-generated: every save fully rewrites it with deterministic sort order (rules by ID, allowlists by name, entries within each allowlist, suppressions by rule+path), deterministic indent + LF line endings, file mode forced to 0600, and atomic write via `.tmp` + rename. The canonical file header documents the regeneration contract so hand-editors aren't surprised when their comments disappear. Comment-preservation escape hatch: every entry ships a `notes:` field that DOES round-trip.
- **`internal/policy/merge.go`** — `Effective` view implements the precedence model from plan section B3.4:
  1. Rule not registered → never fires.
  2. `rules.X.enabled = false` → skip globally.
  3. `rules.X.scope.exclude` matches path → skip.
  4. `rules.X.scope.include` set but path not included → skip.
  5. Rule runs; allowlists pass through as context.
  6. Suppressions (union of policy.yaml + `.audrignore`) — ANY match silences.
  7. Severity override rewrites surviving findings.
  8. Emit.
  Expired suppressions are ignored at scan time but kept on disk until the next save (the dashboard surfaces them so users can prune).
- **Rule registry wrap (CQ2)** — `rules.ApplyWithPolicy(doc, filter)` is the new policy-aware entry point. `rules.Apply(doc)` keeps the v1.1 signature and is now equivalent to passing a nil filter, so existing callers (CLI scan, self-audit, rule tests) need no code change. **Regression contract:** an empty policy produces byte-identical scan results to v1.1. Anchored by `TestEmptyPolicy_BehavesIdenticallyToNoPolicy` in `internal/rules/registry_policy_test.go`.
- **Daemon orchestrator hot-reload** — `runNative` re-loads `~/.audr/policy.yaml` at the top of every scan cycle. Same pattern as v0.5.0's `scanner.config.json`. No daemon restart needed; dashboard saves take effect within one scan interval.
- **`audr policy` CLI subcommand** — `show` / `path` / `edit` / `validate` / `init`. `audr policy edit` opens the file in `$VISUAL` / `$EDITOR` / `code` / `vi` (Windows: `notepad`) and re-validates on exit. `audr policy validate ~/.audr/policy.yaml` returns exit code 1 on a malformed file — usable as a CI gate.

### Added — Dashboard policy editor

- **`/policy/edit` page** — separate route reached via `audr open` or via a top-bar link from the main dashboard. Form view with category nav on the left (counts per category: MCP / Claude / Codex / Cursor / PowerShell / Shell / GitHub Actions / Skill / Shai-Hulud / OpenClaw / Other), rule rows on the right showing toggle + rule-id + description + severity dropdown. Each toggle / severity change updates an in-memory draft; the SAVE button stays disabled until the draft differs from what's persisted. Tab-close protection via `beforeunload` keeps unsaved changes safe.
- **`/api/policy`** — GET returns the current policy + rule catalog + canonical YAML + load warnings. POST validates and saves; returns the canonical YAML the server actually persisted so the editor stays in sync.
- **`/api/policy/validate`** — POST validates without writing. For future client-side as-you-type linting.
- **`/api/rules`** — GET returns the rule catalog (id, title, default severity, category). Standalone for clients that only need the catalog.
- **`policy.html` + `policy.css` + `policy.js`** — vanilla JS, no build step, no node_modules. Uses audr's existing dashboard tokens (Plex Mono/Sans, dark-only palette). The visual contract matches the design-reviewed mockup at `~/.gstack/projects/harshmaur-audr/designs/policy-editor-20260515/mockup.html`.

### Deferred from v1.2 (documented as v1.2.x slices)

- **CodeMirror 6 YAML editor.** Plan B2 called for a vendored ESM bundle. Building it requires the Node toolchain we deliberately keep out of the audr repo per the trust thesis. v1.2.0 ships the YAML view as a `<textarea>` in read-only mode (status line explains: "edit via Form tab or hand-edit policy.yaml on disk"). v1.2.x will ship a vetted prebuilt bundle vendored as a single binary blob.
- **htmx-based main-dashboard refactor.** Plan B2 called for the whole dashboard to migrate to htmx + Alpine fragments. The policy editor is the only piece v1.2 needs htmx-style behavior from, and it works fine as vanilla JS — a wholesale dashboard rewrite would have shipped weeks of risk for no functional gain. The main dashboard's existing 895-line `dashboard.js` keeps working unchanged.
- **fsnotify watcher for dashboard live-reload of the policy editor.** Per-scan-cycle re-read is the primary hot-reload path and ships in v1.2.0; the editor itself can refresh on user "reload from disk" click. The fsnotify integration for instant editor refresh when the user hand-edits the file via `$EDITOR` lands in v1.2.x.
- **Diff preview modal + destructive-action confirm modal.** Plan B4.1 and B4.2 designed these. v1.2.0 ships a simpler "SAVE" button without the diff preview interstitial. v1.2.x will add the modal flow when the destructive-action heuristic per Codex review #11 (coverage-delta math instead of raw counts) is settled.

### Changed

- **`scan.Options` gains a `Policy rules.PolicyFilter` field.** Nil = no overlay (CLI default, v1.1 behavior). The daemon orchestrator populates this from the live `~/.audr/policy.yaml` on every scan cycle.

### Tests

- `internal/policy/policy_test.go` — 11 tests covering round-trip, deterministic sort, validation, atomic save, backup rotation, restrictive file mode, future-schema rejection, notes preservation, header presence, expiry round-trip, hash stability.
- `internal/policy/merge_test.go` — 9 tests covering each precedence step + path glob semantics including the Windows-path normalization regression.
- `internal/rules/registry_policy_test.go` — 5 integration tests: empty policy equals v1.1 behavior, disable-by-policy, severity override, suppression silences, scope exclude.

## [0.6.0] - 2026-05-15 — v1.1 Platform Completeness Lake

First release shipping audr as a first-class Windows tool plus click-to-open notifications on macOS. The v1.1 milestone per `/plan-eng-review` of 2026-05-15. Two outside-voice review passes (Codex + Claude subagent) ran against the plan before implementation; their feedback shaped the deferred-vs-shipped split below.

### Added — macOS click-to-open

- **`internal/notify/toaster_darwin.go`** — new macOS toaster that prefers `terminal-notifier` on PATH for click-to-open routing (`-execute "audr open"` opens the dashboard via the CLI's state-file-read path, same restart-survival as Linux dbus). Absent terminal-notifier: degrades to `osascript display notification` without click action. The Notifier's body-composition logic auto-appends the `run "audr open" to investigate` hint to the toast body only when click won't route — users always have a working manual path.
- **`internal/notify` — new `ClickableToaster` interface.** `SupportsClickAction() bool` tells the Notifier whether to include the manual-fallback hint. Linux toaster implements it (true when dbus connected + onClick non-nil). The Windows beeep fallback omits the interface so the hint always appears there.
- **`audr daemon notify --test` on macOS** now skips the Script Editor diagnostic when terminal-notifier is in use (only relevant on the osascript fallback path) and upgrades the terminal-notifier suggestion from a "future" hint to a real install recommendation with concrete consequences.

### Added — Windows

- **`internal/daemon/service_windows.go`** — new Windows install backend that registers a per-user **Scheduled Task at user logon** instead of a Windows Service Manager entry. Windows Services run in Session 0, which is desktop-isolated since Vista — a Session 0 process can't deliver toast notifications, which would break audr's notification contract. The Scheduled Task runs in the user's interactive logon session with normal desktop access, mirroring the macOS LaunchAgent / systemd `--user` model already in use.
  - Task XML composed in-process with `LogonTrigger` (fires at user login), `InteractiveToken` logon type (no stored credentials), `LeastPrivilege` run level (no UAC prompt), `DisallowStartIfOnBatteries=false` + `StopIfGoingOnBatteries=false` (daemon keeps running unplugged), `MultipleInstancesPolicy=IgnoreNew` (defense vs trigger races), `Hidden=true` (keeps Task Scheduler UI list short).
  - `schtasks /Create /F` force-overwrites an existing task — re-installing after an upgrade rewrites the binary path naturally; no stale entries left behind. Codex outside-voice review flagged install-path drift as a real concern (#8); the `/F` semantics resolve it.
  - `Status()` parses `schtasks /Query /FO LIST` output and normalizes to audr's vocabulary (running / stopped / not-installed / unknown).
  - `Run()` skips the kardianos service-manager protocol entirely (there is none — Task Scheduler just spawns the binary as a normal user process) and wires `signal.NotifyContext` directly so a `schtasks /End` (CTRL_BREAK_EVENT) or interactive Ctrl-C both cancel the run-context cleanly.
- **`internal/lowprio` — Windows IoPriorityHintLow.** v0.5.5 shipped `BELOW_NORMAL_PRIORITY_CLASS` at process creation (CPU drop only). v0.6.0 adds the IO-class analogue: `NtSetInformationProcess(ProcessIoPriority, IoPriorityHintLow)` via ntdll.dll. Same shape as Linux's `ioprio_set(IOPRIO_CLASS_IDLE)` — both axes matter for the "never hog the laptop" promise. Graceful no-op when ntdll lacks the proc (Server Core) or older Windows returns `STATUS_INVALID_PARAMETER`.
- **`internal/parse/powershell.go`** — new PowerShell profile parser handling `$env:KEY = ...` assignments, bare `$var = ...` (scope prefix stripped), dot-source (`. ./other.ps1`), `Import-Module` / `Add-PSSnapin` / `using module`, `Set-Alias` / `New-Alias` (positional + named forms), pipeline detection (splits on `|` outside paired quotes; leaves `||` logical-or + quoted pipes alone), trailing-backtick line continuation, conservative trailing-`#`-comment trimming. Mirrors `parseShellRC`'s shape so rules port cleanly.
- **`internal/parse/document.go` — `FormatPowerShellProfile`** detection. Catches `Microsoft.PowerShell_profile.ps1`, `Microsoft.VSCode_profile.ps1`, `profile.ps1` (PS7+ canonical name), and `ConsoleHost_history.txt` (PSReadLine command-history, a known secret-leak surface for users who paste tokens at the prompt). `DetectFormat` now normalizes backslashes to forward slashes before basename extraction so Windows-native paths classify correctly on any host audr runs on.
- **PowerShell rule pack (3 new rules)**:
  - `powershell-iwr-iex` — **Critical** — pipeline pattern that fetches from the network and pipes into `Invoke-Expression` / `iex` / `Add-Type`. The Windows analogue of `curl | bash`. Order-aware: fetch must precede exec in pipeline order. Intermediate stages between them (ForEach-Object, ConvertFrom-Json) don't break detection.
  - `powershell-secret-env` — **High** — `$env:KEY = "value"` assignments where the value matches a credential pattern. Reuses the existing `matchesCredential` helper so AWS / GitHub / GitLab / Stripe / Anthropic / Google / Slack / HF / npm prefix recognition applies identically to `.ps1` sources.
  - `powershell-execution-policy-bypass` — **Medium** — `Set-ExecutionPolicy Bypass` / `Unrestricted` in a profile silently disables the signature gate every session. RemoteSigned / AllSigned / Restricted (safer values) do not flag.
- **Windows scan-root coverage.** `os.UserHomeDir()` returns `C:\Users\X` on Windows; the default scan walker now covers `%USERPROFILE%`, `%APPDATA%`, PowerShell profile + history paths, and VS Code / Cursor / Claude desktop / Windsurf settings dirs. Default `SkipDirs` extended with Windows cache basenames so a $HOME scan doesn't tank on browser caches: `INetCache`, `WindowsApps`, `NuGet`, `.nuget`, `npm-cache`, `go-build`. `pkg` is deliberately NOT skipped — it collides with the Go layout convention.
- **`cmd/audr/notify_preflight_windows.go`** — diagnostic probes via `golang.org/x/sys/windows/registry`: master `ToastEnabled` switch, group-policy `NoToastApplicationNotification` (corporate-managed laptops), Focus Assist / Quiet Hours state (`NOC_GLOBAL_SETTING_TOASTS_ENABLED`), and AppUserModelID Start Menu shortcut presence. `audr daemon notify --test` surfaces concrete fixes when toasts are silently suppressed.
- **`install.ps1`** — Windows PowerShell installer. Downloads the matching release ZIP from GitHub Releases, verifies SHA-256 against the published `SHA256SUMS`, extracts to `%LOCALAPPDATA%\audr\audr.exe`, `Unblock-File`s to clear the Zone.Identifier ADS so SmartScreen doesn't re-prompt on subsequent runs, adds the install dir to user PATH (user-scope; no admin required). Prominently documents the SmartScreen warning users will hit on first run and the cosign-signed SHA-256 as the trust anchor for unsigned Windows builds.
- **CI / release pipeline.** `release.yml` now cross-compiles `windows-amd64` + `windows-arm64` artifacts, packages them as `.zip` (alongside the existing `.tar.gz` for macOS/Linux), cosign-signs every Windows artifact, includes them in SLSA L2 provenance attestations, and attaches them to the GitHub Release. New `test-windows` + `test-macos` jobs in `ci.yml` run the full unit-test suite on real Windows + macOS hosts so platform-tagged code (toaster_darwin.go, lowprio_windows.go, service_windows.go) gets actually-executed coverage rather than only cross-compile validation.

### Deferred from v1.1 (documented in TODOS.md)

The plan's `/codex review` outside-voice pass surfaced 12 findings, three of which were applied as plan-text patches before implementation started. The remaining six are conscious deferrals visible to users:

- **Windows click-to-open notifications via WinRT** — Codex review flagged the WinRT activation surface as the single highest schedule risk in v1.1 (`COM activator plumbing for unpackaged Win32 toast click handling`, not just the `x/sys/windows` syscalls). v1.1 ships Windows toasts via beeep's PowerShell backend without click action; the Notifier appends the manual-fallback hint to the body so users have a working path. v1.1.x will land the WinRT + AppUserModelID slice.
- **Windows Authenticode signing** — `TODOS.md` TODO 5. Triggers EV cert spend ($300–500/year). v1.1 ships unsigned Windows binaries with the SmartScreen workaround prominently documented; the cosign-signed SHA-256 is the trust anchor.

### Fixed

- **`internal/parse/DetectFormat` was OS-aware via `filepath.Base`** — on Linux it returned the whole string for backslash-separated paths, silently classifying Windows-native paths as `FormatUnknown`. Now normalizes backslashes to forward slashes before basename extraction. Side effect: Windows path classification works on any host audr runs on, useful for the future cross-machine fleet aggregation in Phase 3.
- **`cmd/audr/notify_preflight_other.go`** build tag tightened to `!linux && !darwin && !windows` so each mainline platform has its own preflight file rather than silently no-op'ing on Windows.

## [0.5.8] - 2026-05-14

### Added
- **Linux click-to-open notifications.** Clicking an audr toast now opens the dashboard. New `internal/notify/toaster_linux.go` talks to `org.freedesktop.Notifications` over godbus directly (replacing beeep on Linux only), sends each notification with a "default" action and "resident" hint so critical toasts stay in the tray until clicked, and listens for `ActionInvoked` signals. The daemon's click handler reads the live state file each time so token rotation across restarts doesn't leave stale URLs. macOS + Windows click-to-open are queued: macOS needs either `.app` bundling or `terminal-notifier` detection; Windows needs `AppUserModelID` registration.
- **`audr daemon notify --test` runs OS-specific preflight diagnostics** before firing the toast. Catches the silent-failure modes you'd otherwise hit:
  - Linux: missing `notify-send` / libnotify-bin, empty `DBUS_SESSION_BUS_ADDRESS`, GNOME `show-banners=false` (the case the user actually hit — banners suppressed system-wide).
  - macOS: Focus / Do Not Disturb on, Script Editor missing from `ncprefs.plist` (no permission prompt has been seen), `terminal-notifier` not installed (suggested as the cleaner long-term path).

## [0.5.7] - 2026-05-14

### Added
- **`audr daemon notify --test`** — fires an on-demand test toast that bypasses all batching, cooldown, and first-scan-suppression so users can verify their OS notification pipeline (libnotify / osascript / Windows toast) in one command without waiting for a critical finding to appear. When the toast fails, prints the underlying OS error plus per-platform hints.
- **`audr daemon notify --status` now reports pending drops** — surfaces the count of toasts the OS suppressed (pending-notify.json) with a pointer to `--test` for diagnosis. Mirrors the dashboard's NOTIFICATIONS DROPPED banner on the CLI.

## [0.5.6] - 2026-05-14

Incorporates two open PRs from Alex Umrysh ([@AUmrysh](https://github.com/AUmrysh)) that complement the v0.5.5 sidecar work.

### Added
- **`audr scan --scanner-jobs N`** (originally PR #9) — user-controllable cap on TruffleHog's internal worker pool via its `--concurrency` flag. Default is `max(1, NumCPU/2)` so the scan doesn't peg the machine. `--scanner-jobs 0` opts into TruffleHog's own default (NumCPU) for CI / batch runs where pegging is fine. Pairs with v0.5.5's lowprio wrapper as defense-in-depth: lowprio limits OS-level scheduling pressure, `--scanner-jobs` limits how many goroutines TruffleHog spawns in the first place.
- **`audr scan --runtime-info`** (originally PR #10) — opt-in detection of whether the scan is running on bare-metal, in a container (docker/podman/kubernetes), in a VM (kvm/vmware/hyperv), or under WSL, plus classification of each scan root as host-bound (bind-mounted from outside the container) vs container-local. New `internal/runtimeenv` package with `Detect()` + `ClassifyRoots()`. Surfaces in text output as `runtime: linux/amd64 · container (docker)` and in the HTML report as a Runtime row in the meta-grid + a collapsible "Runtime evidence" disclosure showing which signals fired (`/.dockerenv`, `KUBERNETES_SERVICE_HOST`, `/proc/1/cgroup` contents, etc.). Opt-in for now so existing CI fixtures stay byte-stable; default-on lands when the staleness-gate normalizer accounts for the new fields.
- **`internal/updater.LatestReleaseTag`** is reused — no new dep beyond `gopsutil/v4/host` (added for runtimeenv).
- **`secretscan.DefaultJobs()`** — exported helper for callers that want to apply the same half-cores cap audr's CLI uses (orchestrator already does).

## [0.5.5] - 2026-05-14

Sidecar scanners now run at low CPU + IO priority so the daemon doesn't hog the laptop. Closes one of the spec's day-one promises.

### Fixed
- **TruffleHog + OSV-Scanner no longer compete with the user's interactive work for CPU.** Observed in the wild 2026-05-14: TruffleHog at 80% CPU, OSV-Scanner at 56% during a first-run $HOME scan made the machine unusable. New `internal/lowprio` package wraps sidecar `exec.Command` invocations with cross-OS priority drops:
  - Linux: `nice 19` (via `setpriority`) + `ionice IDLE` (via raw `ioprio_set` syscall) — the scanner only gets CPU/IO time when nothing else needs it.
  - macOS: `nice 19` (`setpriority`). Darwin doesn't expose ioprio_set through Go's syscall package, but the CPU drop alone is enough for the observed pain.
  - Windows: `BELOW_NORMAL_PRIORITY_CLASS` via creation flags. Matches the spec.
  - BSDs / other Unix: `nice 19`; ionice is a no-op.

  Applied to the daemon's secretscan / depscan / ospkg child processes. The one-shot `audr scan` CLI is unchanged — explicit user invocations stay at normal priority so they finish fast.

  Scans take longer in absolute terms (the trade the spec accepts: "Hours acceptable; resource hogging is not"), but the user's editor / browser stay responsive throughout.

## [0.5.4] - 2026-05-14

Hotfix: the daemon now finds sidecars installed via Homebrew, Linuxbrew, Cargo, and `go install` even when started by systemd-user with a stripped PATH.

### Fixed
- **`trufflehog installed via Linuxbrew, daemon says secrets unavailable`** — the daemon's PATH inherited from systemd-user / launchd lacks `/home/linuxbrew/.linuxbrew/bin`, `/opt/homebrew/bin`, `~/.cargo/bin`, `~/go/bin`, `~/.local/bin`. `exec.LookPath("trufflehog")` returned not-found despite the binary being present. New `daemon.AugmentPATH()` prepends these locations at startup (if they exist on disk and aren't already on PATH). Idempotent. Same fix applies to osv-scanner installed in any of those locations. Windows is currently a no-op; chocolatey/scoop paths can be added if needed.

## [0.5.3] - 2026-05-14

Hotfix for a PID-lock safety bug observed in the wild.

### Fixed
- **Stale daemon's shutdown no longer deletes the live daemon's PID lock file.** When two audr daemons ran simultaneously (a known but rare path-vs-inode flock race), shutting down the stale one would unlink the active one's PID file. The live daemon's `flock` survived, but `audr daemon status`, the "another daemon is running" contention check, and CLI invocations that rely on the PID file all broke until a manual restart. The user-visible symptom: scanner toggles via `audr daemon scanners --off` or the dashboard click-to-toggle were ineffective because two daemons were writing conflicting `scanner_statuses` rows to the same SQLite DB (one wrote DISABLED, the other wrote UNAVAILABLE — dashboard rendered both). `PIDLock.Release` now reads the file and only `os.Remove`'s when the contained PID matches our own.

## [0.5.2] - 2026-05-14

Smarter `audr update-scanners` and a OSV-Scanner Linux fix.

### Added
- **`audr update-scanners` skips already-up-to-date scanners.** Before running an installer, queries GitHub Releases for the latest tag of osv-scanner / trufflehog, probes the installed binary via `--version`, and skips the entire install plan when installed >= latest. No more re-downloading or rebuilding when nothing changed. Network failures fall through to the install path (no silent stale-stranding). New `--force` flag bypasses the check for reinstalling corrupted binaries or when the version probe can't reach GitHub.
- **`internal/updater.LatestReleaseTag(ctx, owner, repo)`** — generic GitHub Releases query helper that the update-scanners flow uses. Filters draft + prerelease tags.

### Fixed
- **OSV-Scanner on Linux: prefer brew over go install.** The Linux update plan only listed `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`. brew-installed users still hit go install, which can fail with `/tmp/go-build` disk exhaustion (the user reported this) or with replace-directive errors. Added `brew upgrade osv-scanner || brew install osv-scanner` as the first option; go install becomes the fallback for no-brew systems.
- **depscan's `RunUpdatePlan` now treats `BinaryCommands` as fallbacks**, matching the secretscan fix from v0.5.1. First success wins; remaining commands are skipped. `DatabaseCommands` still iterate as a sequential chain (DB-refresh steps that all must complete).

## [0.5.1] - 2026-05-14

Two hotfixes for v0.5.0 bugs surfaced by first use.

### Fixed
- **Dashboard scanner toggle was a no-op.** v0.5.0 shipped click-to-toggle scanner pills, but a variable-naming inversion made every click POST the current state instead of the toggle. Renamed the local `isOff` to `userEnabled` so the parameter passed to `toggleScanner(category, currentlyEnabled)` matches its semantics. Clicking pills now actually toggles them.
- **`audr update-scanners --backend trufflehog --yes` failed after a successful brew upgrade.** TruffleHog's go.mod uses `replace` directives so `go install` refuses to build it. The Linux update plan lists brew and go-install as alternatives, but `RunUpdatePlan` was iterating them as sequential steps — brew step succeeded, then go install ran anyway and failed. Changed the semantic to fallback-style: first command that succeeds wins; remaining commands skip; full failure only when every command fails.

## [0.5.0] - 2026-05-14

User-controllable scanner toggles + SQLite migration framework with auto-rebuild fallback.

### Added
- **Per-category scanner enable/disable.** New `audr daemon scanners --off=secrets,deps / --on=secrets / --status` CLI plus click-to-toggle pills in the dashboard's scan-progress strip. Persists at `${state_dir}/scanner.config.json` (mode 0600). The running orchestrator re-reads on every scan cycle so toggles take effect within ~10 minutes without a daemon restart. A user-disabled category is distinct from a sidecar-missing one: dashboard shows DISABLED (neutral muted colour) vs OFF (amber, "install sidecar" signal). Banner stack ignores Status="disabled" so deliberately turning a category off doesn't add noise.
- **POST /api/scanners endpoint.** Token-required. Body `{"category": "secrets", "enabled": false}`. Returns the full new config so optimistic-UI clients can re-sync.
- **`DaemonInfo.ScannerEnabled`** map on the snapshot so the dashboard knows which categories are user-disabled vs unavailable on initial load (not just on the next SSE event).

### Fixed
- **Migration v2: widen `scanner_statuses.status` CHECK.** The v1 schema only accepted `'ok','error','unavailable','outdated'`. Since v0.4.1 the orchestrator has been writing `'running'` (mid-scan indicator) and v0.5 now writes `'disabled'` (user kill-switch). Both were silently rejected by the CHECK constraint, suppressed at the orchestrator's log warning, and never reached the dashboard. Migration v2 rebuilds the table with a wider CHECK (`'ok','error','unavailable','outdated','running','disabled'`) inside a single transaction. The running indicator and disabled state now actually propagate.
- **`state.Open` self-heals on migration failure.** When the SQLite DB is corrupt, version-drifted, or partially-written from a crash, `state.Open` now deletes the DB file plus its `-wal` / `-shm` / `-journal` sidecars and retries once. Second failure is genuinely fatal. Daemon state is reproducible from the filesystem; losing the DB means the next scan re-detects everything as new findings. Logs the rebuild to stderr.

## [0.4.3] - 2026-05-14

Hotfix slice. Sidecar re-probe (the bug behind "I installed trufflehog and audr still says secrets OFF"), plus the three deferred notification followups from v0.4.2.

### Fixed
- **Sidecar re-probe per scan cycle (D15).** `RunSecrets` / `RunDeps` / `RunOSPkg` were evaluated once at orchestrator construction and never re-checked. Installing trufflehog or osv-scanner after the daemon started had no effect until a daemon restart. The orchestrator now tracks an auto-mode flag per scanner and re-probes the sidecar at the top of every scan cycle when the scanner was at its auto-default. Installing a sidecar externally now takes effect within one scan interval (typically 10 minutes).

### Added
- **NOTIFICATIONS DROPPED banner.** When the OS drops a toast (permission denied, missing notify-send, Focus mode), the notifier writes to `${state_dir}/pending-notify.json` — already true in v0.4.2 but not consumed. v0.4.3 surfaces the count on the snapshot, renders a dashboard banner with the `audr daemon notify --status` fix command, and adds a `DELETE /api/notify/pending` endpoint the banner-dismiss button calls to truncate the file (so dismissals persist across reloads).
- **macOS install-time osascript permission probe.** `audr daemon install` on darwin now fires an osascript notification so the system permission prompt appears under audr's identity before any real CRITICAL toast. The daemon falls back to pending-notify.json regardless if denied; this just front-loads the prompt to install time.
- **WATCHING state shows accurate "last scan X min ago" on initial load.** `DaemonInfo.LastScanCompleted` surfaces the most recent completed scan's timestamp via snapshot. Dashboard reads it on load so the WATCHING sub-label is specific immediately, rather than waiting for the next `scan-completed` SSE event.

## [0.4.2] - 2026-05-14

OS-native toast notifications for new CRITICAL findings, with batching so a first-run scan on a compromised machine doesn't bombard the user.

### Added
- **OS-native toast notifications for new CRITICAL findings.** New `internal/notify` package emits toasts via `gen2brain/beeep` (cross-OS: macOS osascript, Linux notify-send, Windows toast). Wired as a daemon subsystem subscribing to the store's event bus. The body is `CRITICAL: <title> · run "audr open" to investigate`; the title is just `audr`.
- **Smart batching so 1000 critical findings don't produce 1000 toasts.** Three layers:
  - **First-scan suppression**: every CRITICAL detected during the daemon's very first scan after install is suppressed. On scan-completed, one aggregate toast fires: `audr · First scan complete · N critical · audr open`.
  - **Per-fingerprint 24h cooldown**: a CRITICAL re-detected on every subsequent cycle won't re-fire its toast for 24h.
  - **5-minute rolling cap of 3 toasts**: during steady-state, anything past the cap is suppressed and counted. On scan-completed, one aggregate fires: `audr · N more critical findings since last alert · audr open`. So even a sudden burst tops out at 3 + 1 = 4 toasts per scan cycle.
- **`audr daemon notify --off / --on / --status`** CLI to toggle notifications without restarting the daemon. Writes `${state_dir}/notify.config.json` (mode 0600); the running notifier re-reads on every event. Disabling does NOT halt scanning — findings still appear on the dashboard.
- **Pending-notify fallback** at `${state_dir}/pending-notify.json`. When a toast fails (permission denied / missing notify-send / OS suppressed), the notifier records the dropped notification so `audr open` can surface a dashboard banner. Wiring `audr open` to actually read this file lands in v0.4.x.

## [0.4.1] - 2026-05-14

Hotfix slice for v0.4.0 dashboard UX issues surfaced by first real-world use.

### Performance
- **Dashboard render coalescing.** A first-run scan against $HOME on a dev machine produced ~1990 findings, and each finding-opened / finding-updated SSE event triggered a full DOM rebuild. The page became unresponsive during the event burst. `scheduleRender()` now queues `render()` onto the next animation frame and drops subsequent schedule calls until that frame fires, capping render frequency at ~60Hz regardless of incoming event rate. Click handlers keep direct `render()` calls for instant single-event feedback.

### Changed
- **Friendlier dashboard verbiage.** The top-bar label now reads `WATCHING` (between scans) / `SCANNING` (during a scan) / `SLOWED` / `PAUSED` / `DISCONNECTED` instead of the raw `RUN` / `SLOW` / `PAUSE` / `OFFLINE` state tokens. The scan-progress strip stays visible at all times with four states: `STARTING UP` (daemon boot), `INITIAL SCAN` (first full sweep), `RESCANNING` (subsequent cycles), and `WATCHING` (between scans, with a relative-time sub-label once a scan-completed timestamp is known).
- **Installer post-install message.** `install.sh` now points fresh users at daemon mode (`audr daemon install` + `audr open`) and `audr update-scanners --yes` for sidecar coverage, in addition to the existing `audr scan ~` one-shot path.

### Fixed
- **Scan-progress strip showed "INITIALIZING" while a scan was clearly running.** The dashboard's `scanActive` flag was only set from the `scan-started` SSE event. Opening the dashboard mid-cycle missed that event entirely, so the strip claimed the daemon was still booting for the full duration of the in-flight scan. The snapshot now carries `DaemonInfo.ScanInProgress` set from the store's `scans` table, and the dashboard reads it on initial load.
- **Per-category running state.** The scan-progress strip showed all four categories as "pending" until each scanner backend completed — users couldn't tell what was currently being scanned. The orchestrator now records a `Status="running"` ScannerStatus before each backend starts (overwritten by the terminal `ok`/`error`/`unavailable` when it finishes via the existing UPSERT), and the dashboard pill maps `running` to the RUNNING visual state. The "scanning but no status yet" fallback is now labelled QUEUED (accurate) instead of RUNNING (overclaiming).

## [0.4.0] - 2026-05-14

Always-on dev-machine vulnerability dashboard. Pivot from one-shot CLI to a long-running daemon that watches your machine continuously, surfaces findings on a live local dashboard, and gives you AI-agent remediation prompts alongside the manual steps. v1 lands the full bundle: AI-agent risks, language-dep CVEs, OS-package CVEs, and secrets (including AI chat transcripts). The dashboard auto-updates as the daemon finds things; resolved findings strikethrough, fade, and disappear without celebration.

### Added
- **Always-on daemon.** `audr daemon install / uninstall / start / stop / status` — per-OS user-level service via `kardianos/service` (launchd LaunchAgent on macOS, systemd `--user` on Linux, Windows Service Manager). PID-lock with `flock` / `LockFileEx`. State + logs under per-OS conventional dirs. `audr open` does liveness probe → auto-start → browser open in one step.
- **Live local dashboard.** Plain HTTP on `127.0.0.1:<dynamic-port>` with a 256-bit token in the URL. Severity-grouped finding stream (Critical/High expanded, Medium/Low collapsed), category × severity filter pills, expand-to-detail with manual steps + paste-ready AI prompt, Copy AI Prompt with inline button feedback, SSE live updates. Banner stack below the top bar for scanner-unavailable / scanner-error / update-available / inotify-limit / remote-FS conditions, each with a per-session dismiss. Scan-progress strip during scan cycles. Resolved findings strikethrough, fade, then collapse over 5 seconds. `prefers-reduced-motion` honored throughout.
- **SQLite state store.** WAL mode + single-writer goroutine pattern with prepared statements. Findings keyed on `sha256(rule_id || kind || canonicalized_locator || normalized_match)` so file rename / move doesn't re-introduce; mid-scan crashes get reconciled at next start. 90-day scan retention, 30-day resolved-finding retention.
- **Hybrid watch + poll engine.** `fsnotify` on scoped tight-watch paths (git repos under $HOME, `~/.claude`, `~/.codex`, `~/.cursor`, AI chat transcript dirs, dotfiles). Periodic full-tree poll for the rest. Adaptive backoff state machine: RUN → SLOW (battery or load 2-4) → PAUSE (load >4). Linux inotify budget detection with graceful demote-to-poll + dashboard banner. Remote-FS detection (NFS / SMB / 9P / FUSE / WSL host mount) excludes those roots from tight-watch and surfaces a banner.
- **OS-package CVE detection** for Linux distros OSV-Scanner covers (Debian, Ubuntu, RHEL, Rocky, Alma, CentOS, Fedora, Alpine) via dpkg / rpm / apk enumeration → CycloneDX 1.5 SBOM → `osv-scanner scan source -L`. macOS and Windows render fix commands (`brew upgrade`, `winget upgrade`) without CVE detection per OSV ecosystem coverage.
- **AI chat transcript secret scanning.** TruffleHog wired to also walk `~/.claude/projects/*/sessions/*.jsonl` and `~/.codex/sessions/`. Catches the secrets developers paste into Claude Code or Codex while debugging.
- **Native rule remediation templates.** Hand-authored handlers for all 20 v0.2 rules, the 11 OSV language ecosystems, the 3 OS-pkg managers, the top 10 TruffleHog detectors, 6 Mini-Shai-Hulud indicator-of-attack rules, and the 15 OpenClaw CVE-shaped rules. Each emits both manual steps and a paste-ready AI prompt scoped to a single well-defined change. Ecosystem flows teach diagnose-first — `npm why` / `pnpm why` / `cargo tree --invert` before any manifest edit — and the override-the-transitive fallback when the parent dep has no patched release.
- **Auto-update foundation.** Daemon polls GitHub Releases once per 24h, caches the result, and surfaces a dashboard banner when a newer release is available with a link to the release page. No telemetry; the only outbound call is the public Releases API. Cache survives daemon restarts.
- **Sidecar binary health checks.** Startup probe of `osv-scanner --version` and `trufflehog --version` against pinned minimums. Missing or outdated → category status = unavailable + dashboard banner pointing at `audr update-scanners`.
- **HTML report restructure.** `audr scan -f html` output now groups by severity (matching the dashboard's information architecture) with a row-level kind badge (PACKAGE / SECRET / OTHER). The path-grouped view stays as a secondary "Browse by file" disclosure at the bottom. Verdict block and attack chain narratives preserved as report-unique editorial features.
- **`DESIGN.md`.** Single source of truth for tokens, type, severity language, and component vocabulary across audr's three rendering surfaces (marketing site, dashboard, HTML report). Documents intentional drift, not aspirational unification.

### Fixed
- **CI test gate (`internal/server/dashboard/index.html` was gitignored).** The broad `*.html` ignore matched the dashboard's embedded HTML, so `//go:embed dashboard` silently produced an `embed.FS` without `index.html`. `TestIndexServesEmbeddedDashboard` has been failing on every CI run since the dashboard was introduced. Added the `!internal/server/dashboard/*.html` exception and tracked the file. CI tests now have a path to green.

## [0.3.2] - 2026-05-13

### Fixed
- **`docs/sample-report.html` regenerated** to clear the CI staleness gate after a coverage-warning rendering tweak.

## [0.3.1] - 2026-04-29

Hotfix for the v0.3.0 install path.

### Fixed
- **`install.sh` was installing a directory at `~/.local/bin/audr` instead of the binary.** The release tarball wraps the `audr` binary inside `audr-vX.Y.Z-os-arch/`; install.sh's `binary=` pointed at that directory rather than at the file inside, so `mv "$binary" "$INSTALL_DIR/audr"` moved the whole directory. Latent since v0.2.x — surfaced by the v0.3.0 release smoke test. Pinned by a new regression test in `internal/installscript/` that asserts the binary path includes the `/audr` suffix.

## [0.3.0]

First public release of Audr — a static-analysis scanner for AI-agent configurations.

### Added
- **20 rules across 4 format families.** Claude Code (5), Codex CLI (2), Cursor (2), generalized MCP across Cursor/Codex/Windsurf (3), MCP supplemental (3), skill / instruction-doc (2), GitHub Actions (2), shell rc (1).
- **5 attack-chain correlations.** Critical: hook RCE in repo-shipped `.claude/settings.json`; permission-loose agent + reachable secret = exfil chain; Codex trusted `$HOME` + plaintext key = no-friction takeover. High: third-party plugin ships an unauthenticated MCP server; same credential reused across N harnesses.
- **Forensic-document HTML report.** Per-finding "what an attacker gets" callout, severity-tinted left borders, file-by-file forensic narrative. Reads like a court exhibit, not a scanner dump. Embedded fonts as base64 data URIs — zero external requests.
- **`audr scan` subcommand.** Default scans `$HOME`, opens HTML in browser. Output formats: HTML, SARIF (GitHub Code Scanning compatible), JSON (pipe to `jq`). Exit code 1 on any high or critical finding.
- **`audr verify <tarball>` subcommand.** Verify a downloaded release tarball against `SHA256SUMS`. If `cosign` is on PATH and `.sig` + `.crt` files are alongside, also runs `cosign verify-blob` against the sigstore transparency log. Flags: `--sums`, `--cert-identity-regexp`, `--cert-oidc-issuer`.
- **`audr self-audit` subcommand.** Prints the SHA-256 of the running binary plus its full rule + chain manifest. `--json` for diffing between machines or feeding a CMDB. Diff the JSON output between two installs to confirm they're identical.
- **`.audrignore` suppression file.** Per-rule and per-path-glob suppression syntax. Loaded automatically from the scan root if present.
- **Signed releases.** Every release artifact ships with cosign-signed `.sig` and `.crt`, SHA256SUMS, SBOMs (SPDX + CycloneDX), and SLSA L2 build provenance via `actions/attest-build-provenance`.
- **License: FSL-1.1-MIT.** Functional Source License with MIT future grant. Source is fully readable, internal use OK, redistribution OK; the only restriction is reselling Audr as a competing commercial service. Two years after each release, that release reverts to plain MIT. Same model used by Sentry, Convex, GitButler, Keygen.
- **`AGENTS.md`.** Cross-tool instructions for Claude Code, Cursor, Codex, OpenCode, Aider. Headline rule: never commit real credentials to test fixtures — use repeated-character placeholders that match the format's prefix and length so the regex still fires.
- **CI self-scan gate.** `.github/workflows/ci.yml` runs `./audr scan .` on every PR and fails the build on any finding. The scanner now gates its own source.
- **`internal/suppress` test coverage.** Full table-driven coverage of `LoadFile`, rule parsing, and path-glob matching (previously zero coverage).
- **`install.sh` cosign cert-identity-regexp regression test.** Shell-only logic in `install.sh` is now exercised by a Go test that runs the script with a stub `cosign` and asserts the exact regexp argument. Prevents silent verification bypass from a future typo.
- **`docs/sample-report.html` staleness gate.** CI regenerates the sample report from the current template + fixture and diffs it against the committed copy. PR fails if the committed sample is stale.
