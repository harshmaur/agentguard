package daemon

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SidecarStatus reports the health of one of audr's shell-out
// dependencies: `osv-scanner` (deps + OS-pkg CVEs) or `betterleaks`
// (secrets). The daemon probes both at startup and surfaces them in the
// dashboard so a missing or outdated sidecar shows up as an unavailable
// category rather than a silent zero-findings verdict.
//
// One layer of subtlety: we do NOT auto-download or auto-update
// sidecars (that would violate the offline-by-default constraint and add
// a supply-chain risk surface). We DO clearly identify the issue and
// point the user at `audr update-scanners`.
type SidecarStatus struct {
	// Name is "osv-scanner" or "betterleaks".
	Name string

	// State is the overall health verdict the dashboard renders against.
	State SidecarState

	// Path is the resolved absolute path to the binary on $PATH, when
	// State is OK or Outdated.
	Path string

	// FoundVersion is the parsed semver of the installed binary, when
	// recognizable. Empty when the binary is missing or version parsing
	// failed (Outdated/Error states).
	FoundVersion string

	// MinVersion is the pinned minimum audr requires for daemon mode.
	MinVersion string

	// ErrorText is a short human description of the failure when State
	// is Error or Missing. Safe to render in a dashboard banner. Never
	// contains raw process output (which can leak secrets); we extract
	// only the version string.
	ErrorText string
}

// SidecarState enumerates the three states the daemon and dashboard care
// about. It deliberately mirrors the ScannerStatus contract from the
// design review (D4) so that downstream code can treat sidecar-missing
// and scanner-erroring uniformly.
type SidecarState string

const (
	// SidecarOK: binary present at or above MinVersion. Daemon may use it.
	SidecarOK SidecarState = "ok"

	// SidecarOutdated: binary present but BELOW MinVersion. Daemon
	// disables the category and surfaces a banner pointing at
	// `audr update-scanners`. Less severe than Missing because the user
	// can probably fix it with one command.
	SidecarOutdated SidecarState = "outdated"

	// SidecarMissing: binary not on $PATH. Daemon disables the category
	// and surfaces an install banner.
	SidecarMissing SidecarState = "missing"

	// SidecarError: binary present but `--version` failed or returned
	// unparseable output. Treated like Missing for daemon behavior; we
	// distinguish in telemetry only.
	SidecarError SidecarState = "error"
)

// SidecarConfig pins the minimum version audr's daemon requires for each
// sidecar. Bumping these values is the unambiguous knob for forcing
// users to upgrade. Defaults below match the versions audr v0.11+ ships
// against.
type SidecarConfig struct {
	OSVScannerMinVersion  string
	BetterleaksMinVersion string
	// ProbeTimeout caps how long we wait for each `--version` call.
	// Defensive: a hung sidecar must not block daemon startup.
	ProbeTimeout time.Duration
}

// DefaultSidecarConfig is the production pin. Conservative — the floor
// is the version audr is known to work with today. Bump on a release
// that depends on new sidecar behavior.
func DefaultSidecarConfig() SidecarConfig {
	return SidecarConfig{
		OSVScannerMinVersion:  "1.8.0",
		BetterleaksMinVersion: "1.2.0",
		ProbeTimeout:          5 * time.Second,
	}
}

// CheckSidecars probes both sidecars and returns their statuses in a
// stable order. Errors during probing are captured per-sidecar in the
// returned slice; CheckSidecars itself does not return an error so the
// daemon can always boot with a populated status map (the dashboard
// renders the failures).
func CheckSidecars(ctx context.Context, cfg SidecarConfig) []SidecarStatus {
	if cfg.ProbeTimeout <= 0 {
		cfg = DefaultSidecarConfig()
	}
	return []SidecarStatus{
		checkSidecar(ctx, "osv-scanner", cfg.OSVScannerMinVersion, cfg.ProbeTimeout, parseOSVScannerVersion),
		checkSidecar(ctx, "betterleaks", cfg.BetterleaksMinVersion, cfg.ProbeTimeout, parseBetterleaksVersion),
	}
}

// versionParser extracts a semver-shaped string from the stdout/stderr
// of a sidecar's `--version` invocation. Returns ("", false) when the
// shape doesn't match — caller treats that as SidecarError.
type versionParser func(stdout, stderr []byte) (version string, ok bool)

func checkSidecar(ctx context.Context, name, minVer string, timeout time.Duration, parse versionParser) SidecarStatus {
	status := SidecarStatus{Name: name, MinVersion: minVer}

	path, err := exec.LookPath(name)
	if err != nil {
		status.State = SidecarMissing
		status.ErrorText = fmt.Sprintf("%s not found on $PATH", name)
		return status
	}
	status.Path = path

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(probeCtx, path, "--version")
	out, runErr := cmd.Output()
	var stderr []byte
	if ee, ok := runErr.(*exec.ExitError); ok {
		stderr = ee.Stderr
	}
	if runErr != nil && !errors.Is(runErr, exec.ErrNotFound) {
		// Even a non-zero exit may still print the version on stdout
		// (some tools do that). Try to parse before giving up.
		if v, ok := parse(out, stderr); ok {
			status.FoundVersion = v
			status.State = compareToMin(v, minVer)
			return status
		}
		status.State = SidecarError
		status.ErrorText = fmt.Sprintf("%s --version failed: %s", name, shortError(runErr))
		return status
	}

	version, ok := parse(out, stderr)
	if !ok {
		status.State = SidecarError
		status.ErrorText = fmt.Sprintf("%s --version output did not match expected shape", name)
		return status
	}
	status.FoundVersion = version
	status.State = compareToMin(version, minVer)
	return status
}

// compareToMin returns SidecarOK when found >= min, SidecarOutdated when
// found < min, or SidecarError on parse failure. semver-ish, three-part.
func compareToMin(found, min string) SidecarState {
	cmp, ok := compareSemver(found, min)
	if !ok {
		return SidecarError
	}
	if cmp < 0 {
		return SidecarOutdated
	}
	return SidecarOK
}

// compareSemver returns (-1, 0, +1) for (a < b, a == b, a > b). Pure
// integer-segment comparison; handles two- and three-part versions and
// ignores any pre-release / build suffix after a dash (e.g., 3.63.0-rc1
// compares as 3.63.0). Returns (_, false) if either side isn't parseable.
func compareSemver(a, b string) (int, bool) {
	ap, ok := parseVersion(a)
	if !ok {
		return 0, false
	}
	bp, ok := parseVersion(b)
	if !ok {
		return 0, false
	}
	for i := 0; i < 3; i++ {
		if ap[i] < bp[i] {
			return -1, true
		}
		if ap[i] > bp[i] {
			return 1, true
		}
	}
	return 0, true
}

func parseVersion(s string) ([3]int, bool) {
	var out [3]int
	s = strings.TrimSpace(s)
	if cut := strings.IndexAny(s, "-+"); cut >= 0 {
		s = s[:cut]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// Version-string extractors. Each sidecar prints its version in its own
// shape; we deliberately bind to the shape rather than fishing with a
// generic regex, so a vendor format change is caught loudly.

// OSV-Scanner: `osv-scanner --version` prints (as of 1.8.0):
//
//	osv-scanner version: 1.8.0
//	commit: ...
//
// We extract the first "version: <semver>" run.
var osvVersionRE = regexp.MustCompile(`version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)

func parseOSVScannerVersion(stdout, stderr []byte) (string, bool) {
	if m := osvVersionRE.FindSubmatch(stdout); len(m) >= 2 {
		return string(m[1]), true
	}
	if m := osvVersionRE.FindSubmatch(stderr); len(m) >= 2 {
		return string(m[1]), true
	}
	return "", false
}

// Betterleaks: `betterleaks --version` prints (as of 1.2.0):
//
//	betterleaks version 1.2.0
//
// (Some builds may include a build suffix after a dash, which
// parseVersion strips.) We accept either `betterleaks version X.Y.Z`
// or `betterleaks X.Y.Z` or the bare semver on a line.
var betterleaksVersionRE = regexp.MustCompile(`(?m)(?:betterleaks(?:\s+version)?\s+)?([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][A-Za-z0-9.+]+)?)`)

func parseBetterleaksVersion(stdout, stderr []byte) (string, bool) {
	for _, blob := range [][]byte{stdout, stderr} {
		if m := betterleaksVersionRE.FindSubmatch(blob); len(m) >= 2 {
			return string(m[1]), true
		}
	}
	return "", false
}

// shortError trims long context off an exec error so it's safe to render
// in a dashboard banner. Defensive against stderr-leakage: never returns
// raw subprocess output here.
func shortError(err error) string {
	s := err.Error()
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}
