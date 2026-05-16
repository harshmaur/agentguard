package ospkg

import (
	"fmt"
	"os"
	"path/filepath"
)

// PackageDBFingerprint returns a stable string that changes whenever
// the OS package database is modified (install / upgrade / remove).
// Used by the orchestrator's ospkg cache to skip the entire
// EnumerateAndScan pipeline (dpkg-query / rpm / apk → SBOM →
// osv-scanner) when nothing has changed since the last scan. On a
// typical dev machine packages move days or weeks apart, so the cache
// hit rate approaches 100% — that's tens of seconds of CPU per cycle
// that audr previously burned producing identical output.
//
// Returns ("", nil) when the platform isn't supported or when the
// manager's DB file can't be stat'd (permissions, missing file).
// Callers treat empty as "cache disabled — always run the sidecar."
// Errors are reserved for unexpected failures (e.g. /etc/os-release
// parse blew up).
//
// Format: "<manager>|<basename>:<mtime_ns>:<size>". The manager
// prefix prevents a cache hit from a previous OS reinstall onto the
// same disk silently reusing stale findings.
func PackageDBFingerprint() (string, error) {
	info, err := detectDistro()
	if err != nil {
		return "", err
	}
	if info.Manager == "" {
		return "", nil
	}
	for _, p := range packageDBPaths(info.Manager) {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		return fmt.Sprintf("%s|%s:%d:%d",
			info.Manager, filepath.Base(p), st.ModTime().UnixNano(), st.Size(),
		), nil
	}
	return "", nil
}

// packageDBPaths returns the candidate DB-file paths for a manager in
// priority order. The first stat-able path wins. Multiple entries
// cover format migrations within a single manager (rpm shifted from
// BDB Packages → Packages.db → rpmdb.sqlite over the v4.x line).
//
// Overridable as a package var so tests can target temp files without
// running as root or relying on specific OS state.
var packageDBPaths = func(m Manager) []string {
	switch m {
	case ManagerDpkg:
		return []string{"/var/lib/dpkg/status"}
	case ManagerRpm:
		return []string{
			"/var/lib/rpm/rpmdb.sqlite",
			"/var/lib/rpm/Packages.db",
			"/var/lib/rpm/Packages",
		}
	case ManagerApk:
		return []string{"/lib/apk/db/installed"}
	}
	return nil
}
