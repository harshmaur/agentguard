package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/harshmaur/audr/internal/daemon"
	"github.com/harshmaur/audr/internal/lowprio"
	"github.com/harshmaur/audr/internal/notify"
	"github.com/harshmaur/audr/internal/orchestrator"
	"github.com/harshmaur/audr/internal/ospkg"
	"github.com/harshmaur/audr/internal/policy"
	"github.com/harshmaur/audr/internal/server"
	"github.com/harshmaur/audr/internal/state"
	"github.com/harshmaur/audr/internal/templates"
	"github.com/harshmaur/audr/internal/updater"
	"github.com/harshmaur/audr/internal/watch"
	"github.com/gen2brain/beeep"
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
	cmd.AddCommand(newDaemonNotifyCmd())
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
cycle, so toggles take effect within one interval (~10 minutes).

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

// newDaemonNotifyCmd toggles OS notification delivery without
// restarting the daemon. Writes the config file the running notifier
// re-reads on every event. No subcommand: --off / --on / --status as
// flags so the muscle memory is `audr daemon notify --off`.
func newDaemonNotifyCmd() *cobra.Command {
	var off, on, showStatus, runTest bool
	cmd := &cobra.Command{
		Use:   "notify",
		Short: "Manage OS notifications (toasts on new CRITICAL findings)",
		Long: `Manage OS-native toast notifications for new CRITICAL findings.

Notifications are on by default. v0.4.2 batching:
  - Per-fingerprint 24h cooldown — a re-detected CRITICAL won't re-fire
  - 5-minute rolling cap of 3 toasts — overflow rolls into a single
    "audr · N more critical findings since last alert" aggregate
    emitted on scan-completed
  - First scan after install emits one aggregate
    "audr first scan complete · N critical · audr open" toast, never
    per-finding toasts

Disabling does NOT halt the daemon — findings still appear on the
dashboard. It only suppresses the OS-level toast surface.

Use --test to fire an on-demand verification toast that bypasses
the cooldown + rate-cap + first-scan-suppression logic. If you see
the toast, the OS-level pipeline (Linux notify-send / macOS
osascript / Windows toast) works. If you don't, the command will
print the underlying error (permission denied, missing notify-send
binary, Focus mode, etc.) — which is what gets written to
pending-notify.json in normal operation.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			set := 0
			for _, b := range []bool{off, on, showStatus, runTest} {
				if b {
					set++
				}
			}
			if set == 0 {
				showStatus = true
			}
			if set > 1 {
				return fmt.Errorf("specify exactly one of --off / --on / --status / --test")
			}
			paths, err := daemon.Resolve()
			if err != nil {
				return fmt.Errorf("resolve daemon paths: %w", err)
			}
			if runTest {
				// Preflight diagnostics that detect common silent-
				// failure modes BEFORE we send the toast — saves the
				// user the "beeep said success but I saw nothing"
				// confusion.
				w := cmd.OutOrStdout()
				if warnings := preflightNotifications(); len(warnings) > 0 {
					fmt.Fprintln(w, "audr: notification preflight detected potential issues:")
					for _, msg := range warnings {
						fmt.Fprintf(w, "  - %s\n", msg)
					}
					fmt.Fprintln(w, "audr: continuing with test toast anyway. If you don't see it,")
					fmt.Fprintln(w, "      address the items above and re-run `audr daemon notify --test`.")
					fmt.Fprintln(w)
				}
				// Fire an on-demand toast via beeep directly. Skips the
				// notifier's Subsystem / event-bus / batching paths so
				// this works whether the daemon is running or not — and
				// surfaces the underlying OS error cleanly when toasts
				// are blocked.
				err := beeep.Notify(
					"audr",
					"Test notification · if you see this, OS notifications work. Run \"audr daemon notify --off\" to suppress real alerts.",
					"",
				)
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(),
						"audr: test toast failed: %v\n"+
							"Hints:\n"+
							"  Linux: ensure libnotify is installed (apt install libnotify-bin) and a notification daemon is running.\n"+
							"  macOS: check System Settings → Notifications → audr is allowed.\n"+
							"  Windows: ensure Focus Assist isn't suppressing notifications for audr.\n",
						err)
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "audr: test toast dispatched. Check your notification area.")
				return nil
			}
			if off {
				if err := notify.WriteConfig(paths.State, notify.Config{Enabled: false}); err != nil {
					return fmt.Errorf("write notify config: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), "audr: OS notifications disabled.")
				return nil
			}
			if on {
				if err := notify.WriteConfig(paths.State, notify.Config{Enabled: true}); err != nil {
					return fmt.Errorf("write notify config: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), "audr: OS notifications enabled.")
				return nil
			}
			// --status (default when nothing passed).
			cfg, err := notify.ReadConfig(paths.State)
			if err != nil {
				return fmt.Errorf("read notify config: %w", err)
			}
			state := "enabled"
			if !cfg.Enabled {
				state = "disabled"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "audr: OS notifications %s.\n", state)
			// Also surface any drops from pending-notify.json. The
			// dashboard banner reads from the same file; printing here
			// gives CLI users the same diagnostic surface.
			if pending, err := notify.ReadPending(paths.State); err == nil && len(pending) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(),
					"audr: %d dropped notification(s) in pending-notify.json — toasts the OS suppressed.\n",
					len(pending))
				fmt.Fprintln(cmd.OutOrStdout(),
					"      Run `audr daemon notify --test` to verify the OS pipeline.")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&off, "off", false, "disable OS notifications")
	cmd.Flags().BoolVar(&on, "on", false, "enable OS notifications")
	cmd.Flags().BoolVar(&showStatus, "status", false, "print current notification status (default if no flag passed)")
	cmd.Flags().BoolVar(&runTest, "test", false, "fire an on-demand test toast (bypasses all batching/cooldown to verify the OS pipeline)")
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

			// On macOS, trigger the system notification permission
			// dialog so the user sees it under audr's identity
			// before any real CRITICAL toast fires. osascript fires
			// a one-shot dummy notification; the first run shows the
			// "Allow Notifications" prompt, subsequent calls are
			// silent. We swallow any error — the daemon falls back
			// to pending-notify.json when toasts get denied.
			if runtime.GOOS == "darwin" {
				osa := exec.Command("osascript", "-e",
					`display notification "audr is installed. Permission prompt will appear once so audr can alert you to CRITICAL findings." with title "audr"`)
				if err := osa.Run(); err != nil {
					fmt.Fprintln(cmd.OutOrStdout(),
						"audr: macOS notification permission probe failed; you can request it later via System Settings → Notifications.")
				} else {
					fmt.Fprintln(cmd.OutOrStdout(),
						"audr: macOS notification permission requested (check the system dialog).")
				}
			}

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

				// Phase 4: the orchestrator subsystem replaces the
				// Phase 2 demo seeder. It runs an initial scan
				// immediately and then on a 10-minute cadence,
				// producing real findings + scanner statuses for the
				// dashboard.
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

				orch, err := orchestrator.New(orchestrator.Options{
					Store:            store,
					Logger:           orchLogger,
					ExternalTriggers: watcher.Triggers(),
					StateDir:         paths.State,
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

				// Notify subsystem. Subscribes to the store's event
				// bus and produces OS-native toasts for new CRITICAL
				// findings, with batching so a first-run sweep
				// doesn't bombard the user. Disabled-via-config does
				// not stop the subsystem — it just no-ops the toast
				// call, so the user can flip with `audr daemon
				// notify --off` without restarting.
				//
				// OnClick (Linux only today) opens the dashboard on
				// notification click. Reads the live state file each
				// time so token rotation across daemon restarts
				// doesn't strand stale URLs.
				notifier, err := notify.New(notify.Options{
					Store:    store,
					StateDir: paths.State,
					Logger:   orchLogger,
					OnClick: func() {
						st, found, err := daemon.ReadStateFile(paths.StateFile())
						if err != nil || !found {
							orchLogger.Warn("notification clicked but state file unreadable",
								"err", err, "found", found)
							return
						}
						url := fmt.Sprintf("http://127.0.0.1:%d/?t=%s", st.Port, st.Token)
						if err := openDashboardURL(url); err != nil {
							orchLogger.Warn("notification clicked but browser launch failed", "err", err)
						}
					},
				})
				if err != nil {
					_ = store.Close()
					return fmt.Errorf("build notifier: %w", err)
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
				//   5. notifier stops consuming store events
				//   6. updater stops (just halts the poll loop)
				//   7. store closes the DB last
				return daemon.Run(ctx, daemon.Options{
					Paths:      paths,
					Subsystems: []daemon.Subsystem{store, upd, notifier, srv, orch, policyWatcher, watcher},
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
