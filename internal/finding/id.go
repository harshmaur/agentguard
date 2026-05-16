package finding

// StableID and Fingerprint are the bridge between finding.Finding (the
// scanner-facing emit shape) and internal/state.Fingerprint (the daemon's
// canonical identity hash, used as PRIMARY KEY on the findings table and
// exposed to the dashboard). The CLI's `audr findings show <id>` and the
// dashboard's "Copy AI prompt" affordance address the same finding by the
// same id — drift between this bridge and internal/orchestrator/convert.go
// is a critical bug. The agreement test in id_test.go pins the invariant.
//
// Why this package imports internal/state: internal/finding is normally a
// leaf type-definition package, and persistence usually depends on types
// rather than the reverse. We accept the inverted layering here because
// (a) the daemon's fingerprint hash is the canonical identity (not
// finding.Finding's optional fields), (b) the audr binary already loads
// internal/state's sqlite driver via the daemon subcommand so there is no
// real runtime cost, and (c) the alternative — moving Fingerprint to a
// shared internal/fingerprint package — would invasively rewrite five
// production callsites in orchestrator and server packages without
// changing any behavior.

import (
	"encoding/json"
	"strings"

	"github.com/harshmaur/audr/internal/state"
)

// StableID returns the first 12 hex characters of the finding's canonical
// fingerprint. The full 64-char fingerprint comes from
// state.Fingerprint(ruleID, kind, locator, normalizedMatch); the locator
// shape is kind-specific and MUST match what internal/orchestrator emits
// (see fingerprintInputs below for the dispatch).
//
// 12 hex = 48 bits of namespace. Two findings with the same 12-char prefix
// is astronomically unlikely in any one repo, and `audr findings show
// <prefix>` errors with both candidates rather than picking one silently.
//
// Returns the empty string when fingerprinting fails (malformed locator).
// Callers that need to distinguish "fingerprint failed" from "valid empty
// finding" should use Fingerprint() instead.
func (f Finding) StableID() string {
	fp, err := f.Fingerprint()
	if err != nil {
		return ""
	}
	if len(fp) < 12 {
		return fp
	}
	return fp[:12]
}

// Fingerprint returns the full 64-character hex SHA-256 used as the
// daemon's primary key. Returns an error when the locator JSON fails to
// marshal (in practice never — locator values are simple types).
func (f Finding) Fingerprint() (string, error) {
	kind, ruleIDForFP, matchForFP, locator := f.fingerprintInputs()
	locatorBytes, err := json.Marshal(locator)
	if err != nil {
		return "", err
	}
	return state.Fingerprint(ruleIDForFP, kind, locatorBytes, matchForFP)
}

// fingerprintInputs decides which (kind, fingerprint-rule-id, match,
// locator) tuple to feed to state.Fingerprint. Mirrors the dispatch in
// internal/orchestrator/convert.go:
//
//   - Findings emitted by depscan (rule_id starts with "osv-" or "dep-",
//     mirroring orchestrator's categorizeRuleID) are dep-package kind
//     when their Match parses as "<ecosystem> <name>@<version>"; their
//     locator is {ecosystem, name, version, manifest_path} and the
//     match input is the parsed advisory ID (from Context).
//   - Everything else is file kind with locator {path, line}. This covers
//     agent-rule findings (path+line set by rules) and secret findings
//     (path+line set by Betterleaks).
//
// CRITICAL: the dispatch is keyed on the RuleID prefix, NOT on the Match
// string shape alone. An agent-rule like `mcp-unpinned-npx` emits
// Match strings such as `npx -y @foo/bar@1.0.0` that incidentally parse
// as <ecosystem> <name>@<version> — without the rule_id gate, those
// findings would be mis-fingerprinted as dep-package here while the
// daemon's orchestrator dispatches them through findingToStateFinding
// (kind=file) based on provenance. The TestStableID_DaemonAgreement test
// pins this invariant.
//
// os-package findings are daemon-only (orchestrator emits them directly
// into state.Finding without going through finding.Finding) so this
// dispatch does not need an os-package branch.
func (f Finding) fingerprintInputs() (kind, ruleIDForFP, matchForFP string, locator map[string]any) {
	if isDepRuleID(f.RuleID) {
		if eco, name, ver, ok := parseDepMatch(f.Match); ok {
			matchForFP = parseDepAdvisoryID(f.Context)
			if matchForFP == "" {
				matchForFP = f.RuleID
			}
			return "dep-package", f.RuleID, matchForFP, map[string]any{
				"ecosystem":     eco,
				"name":          name,
				"version":       ver,
				"manifest_path": f.Path,
			}
		}
		// Dep rule but Match didn't parse: orchestrator falls back to
		// file kind via findingToStateFinding. Mirror that fallback here.
	}
	return "file", fingerprintRuleID(f.RuleID), f.Match, map[string]any{
		"path": f.Path,
		"line": f.Line,
	}
}

// isDepRuleID mirrors internal/orchestrator/convert.go's categorizeRuleID:
// a finding's RuleID identifies it as a depscan-emitted package
// vulnerability if it carries the `osv-` or `dep-` prefix. Any other
// RuleID (including agent-rules that happen to produce Match strings
// matching the "<eco> <name>@<ver>" shape) is treated as file kind.
func isDepRuleID(ruleID string) bool {
	return strings.HasPrefix(ruleID, "osv-") || strings.HasPrefix(ruleID, "dep-")
}

// fingerprintRuleID mirrors internal/orchestrator/convert.go's identically-
// named helper: secret-betterleaks-valid and -unverified collapse to
// secret-betterleaks so a validation API flap (rate-limit, transient
// failure, key briefly revoked then restored) does not churn fingerprints
// between scans. Keep in lockstep with the orchestrator's version — the
// agreement test in id_test.go pins them.
func fingerprintRuleID(ruleID string) string {
	switch ruleID {
	case "secret-betterleaks-valid", "secret-betterleaks-unverified":
		return "secret-betterleaks"
	default:
		return ruleID
	}
}

// parseDepMatch parses depscan's Match field, built as
// `fmt.Sprintf("%s %s@%s", ecosystem, name, version)`. Mirrors
// internal/orchestrator/convert.go's parseDepscanMatch — keep in lockstep.
//
// Returns ok=false when the shape does not match. Caller falls back to
// file-kind treatment so the finding still surfaces.
func parseDepMatch(match string) (ecosystem, name, version string, ok bool) {
	space := strings.IndexByte(match, ' ')
	if space < 0 {
		return "", "", "", false
	}
	ecosystem = match[:space]
	rest := match[space+1:]
	at := strings.LastIndexByte(rest, '@')
	if at <= 0 {
		return "", "", "", false
	}
	name = rest[:at]
	version = rest[at+1:]
	if name == "" || version == "" {
		return "", "", "", false
	}
	return ecosystem, name, version, true
}

// parseDepAdvisoryID extracts advisory=<id> from depscan's Context field,
// formatted as `advisory=<id> fixed=<ver>`. Mirrors
// internal/orchestrator/convert.go's parseDepscanContext — keep in lockstep.
// Returns the empty string when no advisory token is present.
func parseDepAdvisoryID(ctx string) string {
	for _, part := range strings.Fields(ctx) {
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		if part[:eq] == "advisory" {
			return part[eq+1:]
		}
	}
	return ""
}
