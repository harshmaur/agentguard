// Package daemon implements audr's long-running background process: per-OS
// service install, lifecycle (root context + signal handler), PID-file
// locking, and sidecar health checks. Subsystems that ride on the daemon
// (state store, watch+poll engine, HTTP server, scanner orchestrator) live
// in their own packages and consume daemon.Lifecycle's context.
package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Paths is the set of platform-conventional directories audr's daemon
// writes to. Resolved once at startup; each field is an absolute path
// the daemon owns (created on first use, 0700 on Unix).
//
// Layout per OS:
//
//   - macOS:   state ~/Library/Application Support/audr/
//              logs  ~/Library/Logs/audr/
//   - Linux:   state ${XDG_STATE_HOME:-~/.local/state}/audr/
//              logs  same
//   - Windows: state %LOCALAPPDATA%\audr\
//              logs  same
type Paths struct {
	// State holds the daemon's authoritative on-disk state: the PID
	// lock file, the daemon-state file (port + token), the SQLite
	// findings DB (Phase 2), and any per-OS service unit references.
	State string

	// Logs holds rotating daemon logs. Separate from State so log
	// rotation / pruning doesn't risk colliding with state files.
	Logs string
}

// Resolve returns the canonical Paths for the current user on the current
// OS. The directories are NOT created here — callers do so under Ensure().
// We separate compute-the-paths from create-the-dirs so tests can stub
// the values without touching the filesystem.
func Resolve() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, fmt.Errorf("daemon paths: resolve home dir: %w", err)
	}

	switch runtime.GOOS {
	case "darwin":
		return Paths{
			State: filepath.Join(home, "Library", "Application Support", "audr"),
			Logs:  filepath.Join(home, "Library", "Logs", "audr"),
		}, nil

	case "windows":
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			// Sane fallback for misconfigured envs: under the user profile.
			base = filepath.Join(home, "AppData", "Local")
		}
		root := filepath.Join(base, "audr")
		return Paths{
			State: root,
			// On Windows we keep logs under the same root in a Logs subdir;
			// there's no equivalent of ~/Library/Logs.
			Logs: filepath.Join(root, "Logs"),
		}, nil

	default: // linux, *bsd, etc.
		stateBase := os.Getenv("XDG_STATE_HOME")
		if stateBase == "" {
			stateBase = filepath.Join(home, ".local", "state")
		}
		return Paths{
			State: filepath.Join(stateBase, "audr"),
			Logs:  filepath.Join(stateBase, "audr"),
		}, nil
	}
}

// Ensure creates any of p's directories that don't exist yet. Mode 0700
// on Unix so per-user state never leaks across users on shared machines.
// On Windows, MkdirAll uses the OS default ACLs; the per-user
// %LOCALAPPDATA% root already inherits user-only access.
func (p Paths) Ensure() error {
	for label, dir := range map[string]string{"state": p.State, "logs": p.Logs} {
		if dir == "" {
			return fmt.Errorf("daemon paths: %s dir is empty", label)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("daemon paths: create %s dir %s: %w", label, dir, err)
		}
	}
	return nil
}

// PIDFile returns the path to the daemon's PID lock file. Lives under
// State so the lifecycle of the lock matches the lifecycle of the state
// (uninstall wipes both atomically).
func (p Paths) PIDFile() string {
	return filepath.Join(p.State, "daemon.pid")
}

// StateFile returns the path to the daemon-state file containing the
// runtime port + auth token (populated by the HTTP server in Phase 2).
// Mode 0600 on Unix; the file content is the auth boundary against
// other users on the same machine.
func (p Paths) StateFile() string {
	return filepath.Join(p.State, "daemon.state")
}

// LogFile returns the path the daemon's primary log writes to. Phase 1
// uses simple append-only; rotation is a v1.1 concern.
func (p Paths) LogFile() string {
	return filepath.Join(p.Logs, "daemon.log")
}
