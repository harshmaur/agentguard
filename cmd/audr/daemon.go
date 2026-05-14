package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/harshmaur/audr/internal/daemon"
	"github.com/harshmaur/audr/internal/server"
	"github.com/harshmaur/audr/internal/state"
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
	cmd.AddCommand(newDaemonRunInternalCmd())
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
func newDaemonRunInternalCmd() *cobra.Command {
	return &cobra.Command{
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

				// State store: SQLite-backed persistent findings, scans,
				// scanner statuses, file_cache. Open() applies
				// migrations, reconciles crashed scans, and starts the
				// writer goroutine — so the store is immediately
				// usable for writes before Lifecycle.Run begins.
				store, err := state.Open(state.Options{Path: filepath.Join(paths.State, "audr.db")})
				if err != nil {
					return fmt.Errorf("open state store: %w", err)
				}

				// Phase 2 demo seed: insert the 8 demo findings so the
				// dashboard has content. Phase 4 will replace this
				// with real scan results from the watch+poll engine.
				if err := server.SeedDemoFindings(ctx, store); err != nil {
					_ = store.Close()
					return fmt.Errorf("seed demo findings: %w", err)
				}

				// Remediation library — Phase 6 swaps for real templates.
				rem, err := server.NewDemoRemediation()
				if err != nil {
					_ = store.Close()
					return fmt.Errorf("build remediation: %w", err)
				}

				// HTTP server subsystem. ListenPort=0 lets the kernel
				// assign a free port; the daemon publishes the chosen
				// port via the daemon.state file.
				srv, err := server.NewServer(server.Options{
					Paths:       paths,
					Store:       store,
					Remediation: rem,
					Version:     Version,
				})
				if err != nil {
					_ = store.Close()
					return fmt.Errorf("build server: %w", err)
				}

				// Register store first so it Closes LAST (reverse-order
				// shutdown — see daemon.Lifecycle.closeAll). The server
				// depends on the store; cleanly drain server first,
				// then close the DB.
				return daemon.Run(ctx, daemon.Options{
					Paths:      paths,
					Subsystems: []daemon.Subsystem{store, srv},
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
}

// newDaemonService constructs a daemon.Service the install/uninstall/
// start/stop/status commands share. The run callback is intentionally
// nil here — those operations don't need to invoke the service body;
// they just talk to the OS service manager. run-internal is the only
// flow that needs the callback wired up.
func newDaemonService() (*daemon.Service, error) {
	return daemon.NewService(daemon.DefaultServiceConfig(), nil)
}
