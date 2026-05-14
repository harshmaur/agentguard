# Changelog

All notable changes to Audr.
Format follows [Keep a Changelog](https://keepachangelog.com/), versioning is `MAJOR.MINOR.PATCH`.

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
