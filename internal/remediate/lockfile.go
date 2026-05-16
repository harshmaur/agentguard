// Package remediate renders user-actionable fix snippets and maintainer
// notification URLs for v1.3's rolled-up dashboard rows.
//
// The package is pure logic with no I/O. It is called by the server when
// building the wire-shape for the rolled-up findings view. It owns three
// concerns:
//
//  1. Lockfile format detection from a path basename.
//  2. Override snippet rendering per format (npm overrides, yarn
//     resolutions, pnpm.overrides, bun overrides, go replace,
//     cargo [patch]).
//  3. Ecosystem cross-check so audr never emits a Go-style replace
//     snippet against a yarn.lock (F6 mitigation in the design doc).
//
// OSV fixed-version extraction lives in osv.go and reads the
// canonical OSV dedup-key format that Lane C's OSV rule emits.
package remediate

import (
	"fmt"
	"path/filepath"
	"strings"
)

// LockfileFormat identifies which package-manager owns a lockfile, used
// to pick the override template.
type LockfileFormat string

const (
	// FormatNPM — package-lock.json. Override syntax: top-level
	// "overrides" map in package.json.
	FormatNPM LockfileFormat = "npm"
	// FormatYarn — yarn.lock. Override syntax: top-level "resolutions"
	// map in package.json.
	FormatYarn LockfileFormat = "yarn"
	// FormatPNPM — pnpm-lock.yaml. Override syntax: "pnpm.overrides"
	// nested in package.json.
	FormatPNPM LockfileFormat = "pnpm"
	// FormatBun — bun.lock (text) or bun.lockb (binary). Bun uses the
	// npm-shaped "overrides" map.
	FormatBun LockfileFormat = "bun"
	// FormatGo — go.sum or go.mod. Override syntax: `replace`
	// directive in go.mod.
	FormatGo LockfileFormat = "go"
	// FormatCargo — Cargo.lock. Override syntax: `[patch.crates-io]`
	// block in Cargo.toml.
	FormatCargo LockfileFormat = "cargo"
	// FormatUnknown — the basename did not match any known lockfile.
	// The UI falls back to a generic "update via your package manager"
	// hint and does not render a snippet.
	FormatUnknown LockfileFormat = ""
)

// DetectFormat returns the LockfileFormat for a given filesystem path.
// Only the basename matters. Returns FormatUnknown for paths that don't
// look like a lockfile.
func DetectFormat(path string) LockfileFormat {
	base := filepath.Base(path)
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json":
		return FormatNPM
	case "yarn.lock":
		return FormatYarn
	case "pnpm-lock.yaml":
		return FormatPNPM
	case "bun.lock", "bun.lockb":
		return FormatBun
	case "go.sum", "go.mod":
		return FormatGo
	case "Cargo.lock":
		return FormatCargo
	}
	return FormatUnknown
}

// EcosystemMatches checks whether an OSV-reported ecosystem string is
// consistent with a detected LockfileFormat. Mismatch means audr has
// either a data corruption (OSV pointed at a path with the wrong
// ecosystem) or a path-class detection bug. Either way, the snippet
// renderer refuses to emit anything against a mismatch — better to
// show "update via your package manager" than a wrong-format snippet.
//
// OSV's ecosystem strings:
//   - "npm" for any JS package manager that consumes the npm registry
//     (npm, yarn, pnpm, bun).
//   - "Go" for go modules.
//   - "crates.io" for cargo.
func EcosystemMatches(osvEcosystem string, format LockfileFormat) bool {
	norm := strings.ToLower(strings.TrimSpace(osvEcosystem))
	switch format {
	case FormatNPM, FormatYarn, FormatPNPM, FormatBun:
		return norm == "npm"
	case FormatGo:
		return norm == "go"
	case FormatCargo:
		return norm == "crates.io" || norm == "cratesio" || norm == "cargo"
	}
	return false
}

// Snippet renders the package-manager-specific override block that pins
// `pkg` to `fixedVersion`. Returns empty string when:
//
//   - format is FormatUnknown
//   - fixedVersion is empty (OSV had no patched version available;
//     the row should fall back to "Track upstream")
//
// The output is the snippet body only — the calling UI is expected to
// frame it with a "Copy" affordance and the F3-mitigation disclaimer.
func Snippet(format LockfileFormat, pkg, fixedVersion string) string {
	if format == FormatUnknown || strings.TrimSpace(fixedVersion) == "" || strings.TrimSpace(pkg) == "" {
		return ""
	}
	switch format {
	case FormatNPM, FormatBun:
		// npm + bun both support package.json "overrides".
		return fmt.Sprintf(`"overrides": {
  %q: %q
}`, pkg, "^"+fixedVersion)
	case FormatYarn:
		return fmt.Sprintf(`"resolutions": {
  %q: %q
}`, pkg, "^"+fixedVersion)
	case FormatPNPM:
		return fmt.Sprintf(`"pnpm": {
  "overrides": {
    %q: %q
  }
}`, pkg, "^"+fixedVersion)
	case FormatGo:
		// Go's replace directive needs the original module path and a
		// patched one. The most reliable form for a pin-to-fixed is
		// the version replacement.
		return fmt.Sprintf(`// In go.mod:
replace %s => %s v%s`, pkg, pkg, strings.TrimPrefix(fixedVersion, "v"))
	case FormatCargo:
		return fmt.Sprintf(`# In Cargo.toml:
[patch.crates-io]
%s = "%s"`, pkg, fixedVersion)
	}
	return ""
}
