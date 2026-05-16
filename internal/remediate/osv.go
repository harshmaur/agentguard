package remediate

import (
	"strings"
)

// OSVDedupKeyPrefix is the literal first component of an OSV-rule
// dedup key. Lane C's depscan emitter builds keys of the form:
//
//	osv:<ecosystem>:<package>:<fixed>:<advisory-id>
//
// `ecosystem` is lower-case and matches the OSV ecosystem string
// (e.g. "npm", "go", "crates.io"). `fixed` is the upstream-patched
// version with the leading "v" stripped; an empty fixed value means
// OSV had no patched version available. `advisory-id` is the CVE
// number when present, else the OSV ID (GHSA-...).
const OSVDedupKeyPrefix = "osv:"

// OSVKey is the structured form of an OSV dedup key. Parsed via
// ParseOSVDedupKey for use by the snippet renderer and the dashboard's
// row-level fix-authority grouping.
type OSVKey struct {
	Ecosystem    string
	Package      string
	FixedVersion string // empty when OSV had no patched version
	AdvisoryID   string
}

// ParseOSVDedupKey parses an OSV-rule dedup key into its components.
// Returns ok=false for any key that does not have the "osv:" prefix or
// the expected 5-segment shape — callers should fall back to a generic
// "update via your package manager" hint in that case rather than
// surfacing partial data.
//
// Package names may contain colons in some ecosystems (Maven, for one,
// uses group:artifact). v1.3 only supports npm/go/cargo ecosystems
// where colons are not allowed inside the package name, so simple
// 5-split is sufficient. If we ever add Maven, the emitter side needs
// to URL-encode the package component.
func ParseOSVDedupKey(key string) (OSVKey, bool) {
	if !strings.HasPrefix(key, OSVDedupKeyPrefix) {
		return OSVKey{}, false
	}
	parts := strings.SplitN(key, ":", 5)
	if len(parts) != 5 {
		return OSVKey{}, false
	}
	out := OSVKey{
		Ecosystem:    parts[1],
		Package:      parts[2],
		FixedVersion: parts[3],
		AdvisoryID:   parts[4],
	}
	if out.Package == "" {
		return OSVKey{}, false
	}
	return out, true
}

// BuildOSVDedupKey is the dual of ParseOSVDedupKey — used by Lane C's
// depscan emitter to construct the dedup key from the parsed OSV report.
// Centralising the format here keeps the parser and emitter in lockstep.
func BuildOSVDedupKey(ecosystem, pkg, fixedVersion, advisoryID string) string {
	return OSVDedupKeyPrefix +
		strings.ToLower(strings.TrimSpace(ecosystem)) + ":" +
		strings.TrimSpace(pkg) + ":" +
		strings.TrimPrefix(strings.TrimSpace(fixedVersion), "v") + ":" +
		strings.TrimSpace(advisoryID)
}

// SnippetForOSVFinding is the convenience that combines the four pieces:
//
//   - Parse the OSV dedup key into structured form.
//   - Detect lockfile format from path.
//   - Cross-check ecosystem against format (F6 guard).
//   - Render the format-appropriate snippet.
//
// Returns empty string when any step fails. Callers should display
// a "Track upstream — no upstream fix available" hint in that case.
func SnippetForOSVFinding(osvDedupKey, lockfilePath string) string {
	key, ok := ParseOSVDedupKey(osvDedupKey)
	if !ok {
		return ""
	}
	if key.FixedVersion == "" {
		// OSV had no patched version. The row stays visible but the
		// action shifts from "pin via override" to "track upstream."
		return ""
	}
	format := DetectFormat(lockfilePath)
	if !EcosystemMatches(key.Ecosystem, format) {
		// F6: ecosystem mismatch means we'd emit a wrong-format snippet.
		// Refuse rather than mislead.
		return ""
	}
	return Snippet(format, key.Package, key.FixedVersion)
}
