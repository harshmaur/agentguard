package daemon

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// AugmentPATH prepends well-known package-manager bin directories to
// the daemon's PATH environment variable. Idempotent: re-running
// doesn't duplicate entries.
//
// Why: when launched by systemd --user (Linux) or launchd (macOS),
// the daemon inherits a minimal PATH — typically just
// `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`.
// Sidecar scanners installed via Homebrew, Linuxbrew, Cargo, or Go
// land in directories the user's interactive shell knows about
// (~/.bashrc / ~/.zshrc additions) but the systemd-user environment
// doesn't. Result: `secretscan.BackendStatus()` calls
// `exec.LookPath("betterleaks")` and gets ErrNotFound even though
// the binary is installed at `/home/linuxbrew/.linuxbrew/bin/betterleaks`.
//
// Originally observed 2026-05-14 with the previous secret-scanning
// backend installed via Linuxbrew; daemon kept reporting
// `secrets: unavailable`. PATH debugging revealed the daemon's PATH
// from systemd-user was missing the Linuxbrew bin dir. Same fix
// applies to betterleaks and osv-scanner installed in any of these
// locations.
//
// The directories below are append-safe: we only add them if they
// (a) exist on disk and (b) aren't already on PATH. Saves us from
// growing PATH on every restart.
func AugmentPATH() {
	current := os.Getenv("PATH")
	existing := strings.Split(current, string(os.PathListSeparator))
	have := make(map[string]struct{}, len(existing))
	for _, e := range existing {
		have[e] = struct{}{}
	}

	home, _ := os.UserHomeDir()

	candidates := []string{
		// macOS Homebrew (Apple Silicon).
		"/opt/homebrew/bin",
		"/opt/homebrew/sbin",
		// macOS Homebrew (Intel) + Linux fallback for system-wide
		// installs. Often already on PATH but defensive.
		"/usr/local/bin",
		// Linuxbrew, the most common case we hit on Ubuntu/Debian.
		"/home/linuxbrew/.linuxbrew/bin",
		"/home/linuxbrew/.linuxbrew/sbin",
	}
	if home != "" {
		candidates = append(candidates,
			// User-local Linuxbrew layout.
			filepath.Join(home, ".linuxbrew", "bin"),
			// Cargo binaries (Rust sidecars, future use).
			filepath.Join(home, ".cargo", "bin"),
			// Go binaries — common spot for `go install`ed tools.
			filepath.Join(home, "go", "bin"),
			// User-local pip / pipx.
			filepath.Join(home, ".local", "bin"),
		)
	}
	if runtime.GOOS == "windows" {
		// Windows paths look different and Homebrew doesn't apply;
		// adding common chocolatey/scoop locations could help here
		// but isn't observed-needed yet. Leave as a TODO.
		return
	}

	var toPrepend []string
	for _, dir := range candidates {
		if _, ok := have[dir]; ok {
			continue
		}
		if !isDir(dir) {
			continue
		}
		toPrepend = append(toPrepend, dir)
		have[dir] = struct{}{}
	}
	if len(toPrepend) == 0 {
		return
	}
	newPath := strings.Join(append(toPrepend, current), string(os.PathListSeparator))
	_ = os.Setenv("PATH", newPath)
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}
