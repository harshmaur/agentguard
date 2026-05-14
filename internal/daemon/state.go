package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// State is the on-disk contract the daemon publishes for the CLI and
// any local helper tools: the running daemon's port + auth token,
// written when the HTTP server binds, removed when it shuts down.
//
// File lives at Paths.StateFile() (.../audr/daemon.state) and is
// always written mode 0600 — same-user readability is the auth
// boundary against other users on the machine. Format is JSON for
// forward-compat (new fields don't break old readers).
type State struct {
	// Port is the TCP port the HTTP server is bound to on 127.0.0.1.
	Port int `json:"port"`

	// Token is the per-startup 256-bit credential the dashboard must
	// present on /api/* requests. base64url-encoded, no padding.
	Token string `json:"token"`

	// WrittenAt is the Unix-seconds timestamp when the daemon wrote
	// this file. Used by `audr open` to detect stale files left behind
	// by a kill -9 (compare against the daemon's PID lock liveness).
	WrittenAt int64 `json:"written_at"`
}

// WriteStateFile atomically writes s to path with mode 0600. Uses the
// rename(2) trick (write to a temp file in the same directory, then
// rename over the target) so a concurrent reader either sees the old
// content or the new content — never a half-written one.
func WriteStateFile(path string, s State) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "daemon.state.*.tmp")
	if err != nil {
		return fmt.Errorf("state file: temp create in %s: %w", dir, err)
	}
	tmpName := tmp.Name()

	// Best-effort cleanup if anything goes wrong before rename.
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	// 0600 explicitly (CreateTemp returns 0600 on Unix but documenting
	// the intent here is the safer default if anyone copy-edits).
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("state file: chmod %s: %w", tmpName, err)
	}

	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("state file: encode: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("state file: sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("state file: close %s: %w", tmpName, err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("state file: rename %s -> %s: %w", tmpName, path, err)
	}
	committed = true
	return nil
}

// ReadStateFile reads + parses the on-disk state. Returns:
//
//   - (state, true, nil) when the file exists and parses cleanly.
//   - (zero, false, nil) when the file simply doesn't exist (daemon
//     not running, or first install before the server has bound).
//   - (zero, false, err) when the file exists but can't be parsed
//     (corrupt, truncated, or pointed at by a misconfigured shell).
func ReadStateFile(path string) (State, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, false, nil
		}
		return State{}, false, err
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return State{}, false, fmt.Errorf("state file %s unparseable: %w", path, err)
	}
	if s.Port == 0 {
		return State{}, false, fmt.Errorf("state file %s missing port", path)
	}
	if s.Token == "" {
		return State{}, false, fmt.Errorf("state file %s missing token", path)
	}
	return s, true, nil
}

// RemoveStateFile deletes the on-disk state. Called by the HTTP server
// on graceful shutdown so the next `audr open` doesn't TCP-probe a
// dead port. Best-effort: a remove failure isn't fatal.
func RemoveStateFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("state file: remove %s: %w", path, err)
	}
	return nil
}

// NowUnix is exposed so tests can swap the clock without monkey-
// patching time.Now globally.
var NowUnix = func() int64 { return time.Now().Unix() }
