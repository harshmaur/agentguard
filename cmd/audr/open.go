package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/harshmaur/audr/internal/daemon"
	"github.com/spf13/cobra"
)

// newOpenCmd builds `audr open`: probe the running daemon and launch
// the dashboard in the user's default browser.
//
// Flow (per design-review D5 + D8):
//
//  1. Resolve the daemon's state file path.
//  2. If absent: report daemon-not-running with the canonical next steps.
//  3. If present: TCP-probe 127.0.0.1:port. If reachable, open browser.
//  4. If unreachable AND daemon installed: Phase 2 auto-starts; Phase 1
//     emits a "the HTTP server lands in phase 2" message.
func newOpenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "open",
		Short: "Open the audr dashboard in your default browser",
		Long: `Open the audr daemon's local dashboard in your default browser.

If the daemon is running, audr opens http://127.0.0.1:<port>/?t=<token> directly.
If it's installed but stopped, audr asks the service manager to start it.
If it isn't installed, audr tells you how to install it.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			paths, err := daemon.Resolve()
			if err != nil {
				return fmt.Errorf("resolve daemon paths: %w", err)
			}

			state, found, err := daemon.ReadStateFile(paths.StateFile())
			if err != nil {
				return fmt.Errorf("read daemon state %s: %w", paths.StateFile(), err)
			}

			if found {
				// State file present: probe + open.
				if tcpProbe(state.Port, 1*time.Second) {
					url := fmt.Sprintf("http://127.0.0.1:%d/?t=%s", state.Port, state.Token)
					return openDashboardURL(url)
				}
				// Port not answering — state file is stale. Fall
				// through to the diagnostic path below.
			}

			// No state file (or state file points at a dead port).
			// Use the daemon's service status to give a precise next step.
			svc, err := daemon.NewService(daemon.DefaultServiceConfig(), nil)
			if err != nil {
				return fmt.Errorf("inspect daemon service: %w", err)
			}
			status, statusErr := svc.Status()
			if statusErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: %v\n", statusErr)
				status = "unknown"
			}

			out := cmd.OutOrStdout()
			switch status {
			case "not-installed":
				return errors.New("audr daemon is not installed.\nRun: audr daemon install && audr daemon start")
			case "stopped":
				// In Phase 2+ we auto-start here. Phase 1 just signals
				// the user explicitly so they aren't left guessing.
				fmt.Fprintln(out, "audr daemon is installed but stopped.")
				fmt.Fprintln(out, "Run: audr daemon start")
				fmt.Fprintln(out, "(note: the dashboard HTTP server lands in phase 2; for now `audr daemon start` runs the scaffolded daemon only.)")
				return nil
			case "running":
				// Running but no usable state file = Phase 1 (no server yet).
				fmt.Fprintln(out, "audr daemon is running, but the dashboard HTTP server is not active yet.")
				fmt.Fprintln(out, "The dashboard server lands in phase 2 of the v1 build.")
				return nil
			default:
				return fmt.Errorf("audr daemon: unable to determine status (got %q). Try: audr daemon status", status)
			}
		},
	}
}

// tcpProbe returns true if 127.0.0.1:port accepts a TCP connection
// within the timeout.
func tcpProbe(port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// openDashboardURL launches the user's default browser at url. Detached
// from this process so the CLI doesn't block on the browser. main.go's
// openBrowser is file://-oriented; this variant handles http:// without
// touching that helper.
func openDashboardURL(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		opener := "xdg-open"
		// WSL hosts: prefer wslview so the URL opens in the Windows
		// browser, not the (often missing) Linux one.
		if isWSL() {
			if _, err := exec.LookPath("wslview"); err == nil {
				opener = "wslview"
			}
		}
		cmd = exec.Command(opener, url)
	case "windows":
		// rundll32 is Windows' canonical "open with default app" hook.
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("auto-open not supported on %s; visit %s manually", runtime.GOOS, url)
	}
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch browser: %w", err)
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// isWSL detects whether we're running under WSL by checking
// /proc/version for the microsoft marker WSL kernels carry.
func isWSL() bool {
	raw, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(raw)), "microsoft")
}
