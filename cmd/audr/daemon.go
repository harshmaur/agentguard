package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/harshmaur/audr/internal/daemon"
	"github.com/harshmaur/audr/internal/lowprio"
	"github.com/harshmaur/audr/internal/orchestrator"
	"github.com/harshmaur/audr/internal/ospkg"
	"github.com/harshmaur/audr/internal/parse"
	"github.com/harshmaur/audr/internal/policy"
	"github.com/harshmaur/audr/internal/server"
	"github.com/harshmaur/audr/internal/state"
	"github.com/harshmaur/audr/internal/templates"
	"github.com/harshmaur/audr/internal/updater"
	"github.com/harshmaur/audr/internal/watch"
	"github.com/spf13/cobra"
)

// newDaemonCmd builds the `audr daemon` subcommand group: install /
// uninstall / start / stop / status, plus the hidden `run-internal`
// the OS service manager invokes.
func newDaemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Manage the audr background daemon",
		Long: `Manage the audr background daemon — a long-running per-user service that
continuously monitors your developer-machine security posture.

Typical first-time setup:

  audr daemon install    # registers the per-OS user-level service
  audr daemon start      # asks the service manager to start it
  audr open              # opens the dashboard in your browser

Tear down:

  audr daemon stop
  audr daemon uninstall`,
	}
	cmd.AddCommand(newDaemonInstallCmd())
	cmd.AddCommand(newDaemonUninstallCmd())
	cmd.AddCommand(newDaemonStartCmd())
	cmd.AddCommand(newDaemonStopCmd())
	cmd.AddCommand(newDaemonStatusCmd())
	cmd.AddCommand(newDaemonScannersCmd())
	cmd.AddCommand(newDaemonRunInternalCmd())
	return cmd
}

// newDaemonScannersCmd toggles per-category scanner enable/disable
// without restarting the daemon. Writes scanner.config.json; the
// running orchestrator re-reads it at the top of every scan cycle.
//
// Categories: ai-agent, deps, secrets, os-pkg. Disabling a category
// is distinct from "scanner sidecar not installed" — a disabled
// category is reported on the dashboard as DISABLED, not OFF.
func newDaemonScannersCmd() *cobra.Command {
	var off, on string
	var showStatus bool
	cmd := &cobra.Command{
		Use:   "scanners",
		Short: "Enable / disable specific scanner categories",
		Long: `Toggle individual scanner categories on or off without restarting the daemon.

Categories: ai-agent, deps, secrets, os-pkg

Examples:
  audr daemon scanners --off=secrets,deps    # disable two categories
  audr daemon scanners --on=secrets          # re-enable one
  audr daemon scanners                       # print current state

Disabling a category is permanent (persists across daemon restarts).
The orchestrator re-reads the config at the start of each scan
cycle, so toggles take effect within one interval (~1 hour by
default, overridable via AUDR_SCAN_INTERVAL).

A disabled scanner is distinct from a missing-sidecar scanner.
Missing sidecars show 'unavailable' and point to audr update-scanners.
User-disabled scanners show 'disabled' and point back to this command.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			actions := 0
			if off != "" {
				actions++
			}
			if on != "" {
				actions++
			}
			if showStatus {
				actions++
			}
			if actions == 0 {
				showStatus = true
			}
			paths, err := daemon.Resolve()
			if err != nil {
				return fmt.Errorf("resolve daemon paths: %w", err)
			}
			if err := paths.Ensure(); err != nil {
				return fmt.Errorf("ensure daemon paths: %w", err)
			}
			cfg, err := orchestrator.ReadScannerConfig(paths.State)
			if err != nil {
				return fmt.Errorf("read scanner config: %w", err)
			}

			apply := func(csv string, enabled bool) error {
				for _, cat := range strings.Split(csv, ",") {
					cat = strings.TrimSpace(cat)
					if cat == "" {
						continue
					}
					updated, err := cfg.SetEnabled(cat, enabled)
					if err != nil {
						return err
					}
					cfg = updated
				}
				return nil
			}
			if off != "" {
				if err := apply(off, false); err != nil {
					return err
				}
			}
			if on != "" {
				if err := apply(on, true); err != nil {
					return err
				}
			}
			if off != "" || on != "" {
				if err := orchestrator.WriteScannerConfig(paths.State, cfg); err != nil {
					return fmt.Errorf("write scanner config: %w", err)
				}
			}
			// Print status table.
			w := cmd.OutOrStdout()
			fmt.Fprintln(w, "audr daemon scanners:")
			for _, cat := range orchestrator.ScannerCategories() {
				marker := "enabled"
				if !cfg.Enabled(cat) {
					marker = "disabled"
				}
				fmt.Fprintf(w, "  %-10s %s\n", cat, marker)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&off, "off", "", "comma-separated category names to disable (ai-agent, deps, secrets, os-pkg)")
	cmd.Flags().StringVar(&on, "on", "", "comma-separated category names to enable")
	cmd.Flags().BoolVar(&showStatus, "status", false, "print current scanner state (default when no flag passed)")
	return cmd
}

func newDaemonInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Register the audr daemon with the OS service manager",
		Long: `Register the audr daemon as a per-user service:

  - macOS:   LaunchAgent under ~/Library/LaunchAgents/com.harshmaur.audr.plist
  - Linux:   systemd --user unit at ~/.config/systemd/user/audr-daemon.service
  - Windows: a per-user entry in the Windows Service Manager

This only registers the service. Use 'audr daemon start' to actually run it.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, err := newDaemonService()
			if err != nil {
				return err
			}
			if err := svc.Install(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "audr daemon: installed")
			fmt.Fprintln(cmd.OutOrStdout(), "next: audr daemon start")
			return nil
		},
	}
}

func newDaemonUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the audr daemon from the OS service manager",
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, err := newDaemonService()
			if err != nil {
				return err
			}
			if err := svc.Uninstall(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "audr daemon: uninstalled")
			return nil
		},
	}
}

func newDaemonStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Ask the OS service manager to start the audr daemon",
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, err := newDaemonService()
			if err != nil {
				return err
			}
			if err := svc.Start(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "audr daemon: started")
			fmt.Fprintln(cmd.OutOrStdout(), "next: audr open")
			return nil
		},
	}
}

func newDaemonStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Ask the OS service manager to stop the audr daemon",
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, err := newDaemonService()
			if err != nil {
				return err
			}
			if err := svc.Stop(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "audr daemon: stopped")
			return nil
		},
	}
}

func newDaemonStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report whether the audr daemon is installed and/or running",
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, err := newDaemonService()
			if err != nil {
				return err
			}
			status, err := svc.Status()
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "audr daemon: %s\n", status)
			return nil
		},
	}
}

// newDaemonRunInternalCmd is the hidden subcommand the OS service
// manager invokes (or a developer runs in the foreground for testing).
// It hands control to kardianos/service.Run(), which calls our service
// program's Start callback to boot the Lifecycle.
//
// Flags:
//   --demo:  also seed demo findings on startup (Phase 2 visual
//            slice behavior). Useful for a clean machine where the
//            real scanner cycle hasn't surfaced anything yet — gives
//            the user something to look at on first open.
func newDaemonRunInternalCmd() *cobra.Command {
	var demo bool
	cmd := &cobra.Command{
		Use:    "run-internal",
		Short:  "Run the daemon (invoked by the OS service manager)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, err := daemon.NewService(daemon.DefaultServiceConfig(), func(ctx context.Context) error {
				// Resolve paths up front so all subsystems share the
				// same view. Ensure is idempotent (daemon.Run calls
				// it again; that's fine).
				paths, err := daemon.Resolve()
				if err != nil {
					return fmt.Errorf("resolve paths: %w", err)
				}
				if err := paths.Ensure(); err != nil {
					return fmt.Errorf("ensure paths: %w", err)
				}

				// Route ospkg's package-level runner through the
				// low-priority wrapper so background dpkg-query / rpm /
				// apk shells run at nice 19 (+ ionice idle on Linux).
				// Secretscan + depscan get the same treatment via
				// per-call Options.Runner; ospkg uses a package-level
				// default so a setter is the simplest plumb. Idempotent
				// — daemon only opens once.
				ospkg.SetRunner(lowprio.Runner{})

				// State store: SQLite-backed persistent findings, scans,
				// scanner statuses, file_cache. Open() applies
				// migrations, reconciles crashed scans, and starts the
				// writer goroutine — so the store is immediately
				// usable for writes before Lifecycle.Run begins.
				store, err := state.Open(state.Options{Path: filepath.Join(paths.State, "audr.db")})
				if err != nil {
					return fmt.Errorf("open state store: %w", err)
				}

				// v1.3: print the dedup-engine baseline-reset notice once
				// after the v3 migration runs (wipes pre-existing findings).
				// The migration trades first_seen_at continuity for the
				// simplest correct dedup-key backfill path; saying so out
				// loud is honest. AppliedMigrationsOnOpen is empty on
				// already-current DBs, so this is a one-shot per upgrade.
				for _, v := range store.AppliedMigrationsOnOpen() {
					if v == 3 {
						fmt.Fprintln(os.Stderr, "audr v1.3 dedup engine: finding history reset; this scan is the baseline.")
					}
				}

				// Phase 4: the orchestrator subsystem replaces the
				// Phase 2 demo seeder. It runs an initial scan
				// immediately and then on a configurable cadence
				// (default 1 hour; AUDR_SCAN_INTERVAL overrides),
				// producing real findings + scanner statuses for the
				// dashboard. The watcher fires reactive scans on top
				// of this for any filesystem change in scope.
				//
				// --demo additionally seeds the 8 hand-crafted demo
				// findings so the dashboard isn't empty on first
				// open if the real scan turns up nothing. Useful for
				// development + screenshotting.
				if demo {
					if err := server.SeedDemoFindings(ctx, store); err != nil {
						_ = store.Close()
						return fmt.Errorf("seed demo findings: %w", err)
					}
				}

				// Build the scan orchestrator. Default roots = $HOME.
				// Wire a JSON logger writing to the daemon log file so
				// orchestrator activity (scan starts, finding counts,
				// scanner statuses) shows up alongside daemon.Info logs.
				logFile, err := os.OpenFile(paths.LogFile(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
				if err != nil {
					_ = store.Close()
					return fmt.Errorf("open daemon log: %w", err)
				}
				// Note: the file handle is intentionally leaked to the
				// orchestrator goroutine — Close on the daemon brings
				// the orchestrator down which stops writing.
				orchLogger := slog.New(slog.NewJSONHandler(logFile, &slog.HandlerOptions{Level: slog.LevelInfo}))

				// Phase 3 watcher: fsnotify on scoped paths + adaptive
				// backoff. Its Triggers() channel feeds the
				// orchestrator alongside the periodic ticker.
				watcher, err := watch.NewWatcher(watch.Options{
					Logger: orchLogger,
				})
				if err != nil {
					_ = store.Close()
					return fmt.Errorf("build watcher: %w", err)
				}

				// Allow the user to override the scan cadence via
				// AUDR_SCAN_INTERVAL (Go duration string — "30m",
				// "2h", "6h"). Unset / unparseable → 1-hour default
				// applied by orchestrator.New. Logged either way so
				// the daemon log makes the effective cadence
				// explicit.
				interval := resolveScanInterval(orchLogger)

				orch, err := orchestrator.New(orchestrator.Options{
					Store:            store,
					Logger:           orchLogger,
					Interval:         interval,
					AudrVersion:      Version,
					ExternalTriggers: watcher.Triggers(),
					StateDir:         paths.State,
					// Gate the periodic ticker behind the watcher's
					// backoff state machine. The watcher's trigger
					// forwarder already drops/throttles triggers under
					// SLOW/PAUSE, but the ticker bypassed that gate —
					// a thrashing machine kept scanning regardless.
					// AV/EDR products yield the machine under load;
					// we should too.
					SkipTickerWhen: func() bool {
						return watcher.CurrentState() == watch.StatePause
					},
					// Drop watcher triggers where every changed path is
					// scanner-irrelevant (Claude Code's own transcript
					// churn under ~/.claude/projects/X/transcripts/*.jsonl,
					// log rotation, sqlite WAL/SHM ticks, etc). Without
					// this filter the watcher fires every 2-3 minutes on
					// an "idle" dev machine just because background tools
					// keep writing to disk — none of those writes change
					// anything any rule cares about. The hourly ticker
					// catches edge cases the filter rejects.
					RelevantPath: isScannerRelevantPath,
				})
				if err != nil {
					_ = watcher.Close()
					_ = store.Close()
					return fmt.Errorf("build orchestrator: %w", err)
				}

				// Remediation: the real templates library (per-rule +
				// per-ecosystem + per-OS-pkg-manager + secret-rotation
				// + generic fallback) is the canonical lookup. The
				// demo registry is only consulted when --demo seeded
				// the canned 8 findings AND the templates library
				// returns "no match" — i.e., DemoRemediation acts as
				// a fallback for the canned fingerprints.
				rem, err := buildRemediation(demo)
				if err != nil {
					_ = store.Close()
					return fmt.Errorf("build remediation: %w", err)
				}

				// Update checker subsystem. Polls GitHub Releases once
				// per 24h and surfaces "update available" hints on the
				// dashboard banner. No telemetry — only outbound call
				// is the public Releases API. Build before the server
				// so the server can read its Latest() result on every
				// snapshot.
				upd, err := updater.New(updater.Options{
					CurrentVersion: Version,
					CacheDir:       paths.State,
				})
				if err != nil {
					_ = store.Close()
					return fmt.Errorf("build updater: %w", err)
				}

				// HTTP server subsystem. ListenPort=0 lets the kernel
				// assign a free port; the daemon publishes the chosen
				// port via the daemon.state file.
				srv, err := server.NewServer(server.Options{
					Paths:        paths,
					Store:        store,
					Remediation:  rem,
					Version:      Version,
					UpdateProbe:  updaterProbe{upd},
					WatcherProbe: watcher,
				})
				if err != nil {
					_ = store.Close()
					return fmt.Errorf("build server: %w", err)
				}

				// Policy file watcher (v1.2.x). When the user
				// hand-edits ~/.audr/policy.yaml via $EDITOR the
				// dashboard receives a "policy-changed" SSE event
				// and refreshes. The per-scan-cycle reload in
				// orchestrator.runNative remains the primary
				// hot-reload path; this subsystem is the UI
				// polish layer.
				policyPath, err := policy.Path()
				if err != nil {
					return fmt.Errorf("resolve policy path: %w", err)
				}
				policyWatcher := policy.NewSubsystem(store, policyPath, orchLogger.With("subsystem", "policy-watcher"))

				// Register subsystems in dependency order. Lifecycle
				// closes in REVERSE registration order:
				//   1. fs watcher stops first (no new triggers fire)
				//   2. policy watcher stops (no more policy-changed events)
				//   3. orchestrator drains in-flight scan + sees the
				//      watcher channel close, falls back to ticker-only
				//   4. server drains in-flight HTTP requests
				//   5. updater stops (just halts the poll loop)
				//   6. store closes the DB last
				return daemon.Run(ctx, daemon.Options{
					Paths:      paths,
					Subsystems: []daemon.Subsystem{store, upd, srv, orch, policyWatcher, watcher},
				})
			})
			if err != nil {
				return err
			}
			// RunAsService blocks until the OS service manager (or, in
			// interactive mode, Ctrl-C) stops us. It returns nil on
			// graceful shutdown.
			if err := svc.RunAsService(); err != nil {
				// Distinguish "another daemon already running" from
				// generic errors so the user sees a friendly message.
				var already *daemon.AlreadyRunningError
				if errors.As(err, &already) {
					return fmt.Errorf("%s", already.Error())
				}
				return err
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&demo, "demo", false, "additionally seed 8 hand-crafted demo findings on startup (visual testing)")
	return cmd
}

// buildRemediation composes the production remediation lookup: the
// per-rule template library is the primary, with the demo registry
// layered behind it so --demo's canned findings still resolve when
// the templates library doesn't claim them. The fallback in the
// templates registry always claims, so in practice the demo layer
// only matters for the few demo fingerprints whose canned text we
// want to preserve.
// isScannerRelevantPath reports whether a path the watcher saw change
// is something any scanner cares about. Used by the orchestrator to
// drop trigger pulses where every changed path is just background
// churn that no rule will ever match on.
//
// Three classes of "relevant":
//
//   - Files parse.DetectFormat recognizes (.mcp.json, settings.json,
//     shell rcs, .env, GHA workflows, AGENTS.md, etc).
//   - Dependency manifests / lockfiles by basename (package.json,
//     go.mod, Cargo.lock, etc).
//   - Files matching shellrc / mcp / claude / codex / cursor scope
//     by directory prefix (catches new file creation events where
//     the basename isn't yet parseable).
//
// Everything else is ignored: jsonl transcripts, sqlite WAL/SHM
// rotation, .log files, OS-level cache writes. The watcher already
// excludes scanignore-listed directories before paths reach this
// classifier — the work here is finer-grained per-file.
func isScannerRelevantPath(path string) bool {
	if parse.DetectFormat(path) != parse.FormatUnknown {
		return true
	}
	switch filepath.Base(path) {
	case "package.json", "package-lock.json", "pnpm-lock.yaml",
		"yarn.lock", "bun.lock", "bun.lockb",
		"requirements.txt", "pyproject.toml", "poetry.lock",
		"uv.lock", "Pipfile.lock",
		"go.mod", "go.sum",
		"Cargo.lock", "Cargo.toml",
		"Gemfile.lock", "Gemfile",
		"composer.lock", "composer.json":
		return true
	}
	return false
}

// resolveScanInterval reads AUDR_SCAN_INTERVAL and returns the parsed
// duration. Returns 0 on unset / parse failure / non-positive so the
// orchestrator's own default kicks in. The env-var path is the only
// user-facing knob today — a policy.yaml field is the v1.5 plan once
// the dashboard grows a daemon settings panel.
//
// Logged both on success ("using interval X from AUDR_SCAN_INTERVAL")
// and failure ("AUDR_SCAN_INTERVAL=X invalid, falling back to
// default") so the effective cadence is auditable in daemon.log.
func resolveScanInterval(logger *slog.Logger) time.Duration {
	raw := strings.TrimSpace(os.Getenv("AUDR_SCAN_INTERVAL"))
	if raw == "" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		logger.Warn("AUDR_SCAN_INTERVAL parse failed; using default", "value", raw, "err", err)
		return 0
	}
	if d <= 0 {
		logger.Warn("AUDR_SCAN_INTERVAL non-positive; using default", "value", raw)
		return 0
	}
	logger.Info("scan interval overridden via AUDR_SCAN_INTERVAL", "interval", d)
	return d
}

func buildRemediation(includeDemo bool) (server.RemediationLookup, error) {
	tmpl := templates.New()
	if !includeDemo {
		return tmpl, nil
	}
	demo, err := server.NewDemoRemediation()
	if err != nil {
		return nil, err
	}
	return chainedRemediation{first: tmpl, second: demo}, nil
}

// chainedRemediation tries the first lookup; if it returns ok=false
// (which the production templates registry never does — fallback
// always claims), falls through to the second. Used to keep the demo
// findings' hand-authored text when --demo seeded them.
type chainedRemediation struct {
	first, second server.RemediationLookup
}

func (c chainedRemediation) Lookup(f state.Finding) (string, string, bool) {
	if h, ai, ok := c.first.Lookup(f); ok {
		return h, ai, true
	}
	return c.second.Lookup(f)
}

// newDaemonService constructs a daemon.Service the install/uninstall/
// start/stop/status commands share. The run callback is intentionally
// nil here — those operations don't need to invoke the service body;
// they just talk to the OS service manager. run-internal is the only
// flow that needs the callback wired up.
func newDaemonService() (*daemon.Service, error) {
	return daemon.NewService(daemon.DefaultServiceConfig(), nil)
}

// updaterProbe adapts updater.Checker (which returns its own
// *updater.Available shape) to server.UpdateProbe (which expects
// *server.UpdateAvailable). The two types carry identical fields;
// keeping them separate avoids server→updater import coupling.
type updaterProbe struct{ c *updater.Checker }

func (p updaterProbe) Latest() *server.UpdateAvailable {
	a := p.c.Latest()
	if a == nil {
		return nil
	}
	return &server.UpdateAvailable{
		Version:     a.Version,
		URL:         a.URL,
		PublishedAt: a.PublishedAt,
	}
}
