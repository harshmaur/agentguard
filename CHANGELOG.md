# Changelog

All notable changes to Audr.
Format follows [Keep a Changelog](https://keepachangelog.com/), versioning is `MAJOR.MINOR.PATCH`.

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
