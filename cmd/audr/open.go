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
// Flow:
//
//  1. Resolve the daemon's state file path.
//  2. If present + TCP probe succeeds → open browser at /?t=<token>.
//  3. If present + TCP probe fails → state file is stale; advise
//     restart.
//  4. If absent + service status = running → daemon JUST started
//     and hasn't written the state file yet; wait briefly (~2s
//     of polling), then retry. If still missing, the daemon's
//     HTTP server failed to bind — surface log location for
//     diagnosis.
//  5. If absent + service status = stopped → run `audr daemon start`.
//  6. If absent + service status = not-installed → run
//     `audr daemon install && audr daemon start`.
func newOpenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "open",
		Short: "Open the audr dashboard in your default browser",
		Long: `Open the audr daemon's local dashboard in your default browser.

If the daemon is running, audr opens http://127.0.0.1:<port>/?t=<token> directly.
If it's installed but stopped, audr tells you to start it.
If it isn't installed, audr tells you how to install it.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			paths, err := daemon.Resolve()
			if err != nil {
				return fmt.Errorf("resolve daemon paths: %w", err)
			}

			// Happy path: state file present + port answering.
			if state, found, err := daemon.ReadStateFile(paths.StateFile()); err != nil {
				return fmt.Errorf("read daemon state %s: %w", paths.StateFile(), err)
			} else if found && tcpProbe(state.Port, 1*time.Second) {
				url := fmt.Sprintf("http://127.0.0.1:%d/?t=%s", state.Port, state.Token)
				return openDashboardURL(url)
			}

			// Either no state file, or state file points at a dead
			// port. Service status drives the diagnostic.
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
				fmt.Fprintln(out, "audr daemon is installed but stopped.")
				fmt.Fprintln(out, "Run: audr daemon start")
				return nil

			case "running":
				// Service says running, but state file is missing OR
				// stale. Two real cases:
				//   (a) daemon JUST started — state file is written
				//       after the HTTP server's Bind() succeeds, which
				//       can take 50–500ms after the service-manager
				//       reports running.
				//   (b) HTTP server failed to bind — port in use,
				//       permission denied, etc. The daemon log is
				//       authoritative.
				//
				// Poll for the state file briefly. If it appears, open.
				// If not, surface where to look.
				if state, ok := waitForStateFile(paths.StateFile(), 3*time.Second); ok {
					if tcpProbe(state.Port, 1*time.Second) {
						url := fmt.Sprintf("http://127.0.0.1:%d/?t=%s", state.Port, state.Token)
						return openDashboardURL(url)
					}
					// State file present but the port isn't answering.
					// Probably mid-bind or just crashed.
					fmt.Fprintln(out, "audr daemon is running and wrote its state file,")
					fmt.Fprintf(out, "but http://127.0.0.1:%d isn't answering yet.\n", state.Port)
					fmt.Fprintln(out, "Wait a few seconds and re-run `audr open`, or check the daemon log:")
					fmt.Fprintf(out, "  %s\n", paths.LogFile())
					return nil
				}
				fmt.Fprintln(out, "audr daemon is running, but no state file was written within 3s.")
				fmt.Fprintln(out, "The HTTP server likely failed to bind (port collision, permission, etc.).")
				fmt.Fprintln(out, "Check the daemon log for the bind error:")
				fmt.Fprintf(out, "  %s\n", paths.LogFile())
				fmt.Fprintln(out, "Then: audr daemon stop && audr daemon start")
				return nil

			default:
				return fmt.Errorf("audr daemon: unable to determine status (got %q). Try: audr daemon status", status)
			}
		},
	}
}

// waitForStateFile polls the state file path until it appears + parses
// cleanly, or the deadline fires. Returns the parsed state on success.
// The audr daemon writes its state file after the HTTP server's
// Bind() succeeds, which is usually <500ms after the service-manager
// reports "running" but can drift to ~3s on cold-start with sidecar
// reprobing.
func waitForStateFile(path string, timeout time.Duration) (daemon.State, bool) {
	deadline := time.Now().Add(timeout)
	for {
		if state, found, err := daemon.ReadStateFile(path); err == nil && found {
			return state, true
		}
		if time.Now().After(deadline) {
			return daemon.State{}, false
		}
		time.Sleep(150 * time.Millisecond)
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
