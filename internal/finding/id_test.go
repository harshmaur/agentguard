package finding_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/state"
)

// TestStableID_Length asserts the 12-hex-character invariant.
func TestStableID_Length(t *testing.T) {
	f := finding.Finding{
		RuleID:   "secret-anthropic-key",
		Severity: finding.SeverityCritical,
		Path:     "src/config.ts",
		Line:     47,
		Match:    "sk-ant-api03-{REDACTED}",
	}
	id := f.StableID()
	if len(id) != 12 {
		t.Fatalf("StableID length = %d (want 12); got %q", len(id), id)
	}
	// hex-only
	for _, r := range id {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Fatalf("StableID has non-hex char %q in %q", r, id)
		}
	}
}

// TestStableID_StableAcrossCalls — fingerprint is deterministic.
func TestStableID_StableAcrossCalls(t *testing.T) {
	f := finding.Finding{
		RuleID: "agent-rule-claude-mcp-allowlist",
		Path:   "/home/u/.claude/claude.json",
		Line:   12,
		Match:  "some-redacted-match",
	}
	a := f.StableID()
	b := f.StableID()
	if a != b {
		t.Fatalf("StableID drifted across calls: %q vs %q", a, b)
	}
	if a == "" {
		t.Fatalf("StableID empty for valid finding")
	}
}

// TestStableID_DistinguishesByRuleID — same path+line, different rule = different id.
func TestStableID_DistinguishesByRuleID(t *testing.T) {
	base := finding.Finding{
		Path:  "/etc/foo",
		Line:  10,
		Match: "x",
	}
	a := base
	a.RuleID = "rule-a"
	b := base
	b.RuleID = "rule-b"
	if a.StableID() == b.StableID() {
		t.Fatalf("StableID collided across different rule_ids: %q", a.StableID())
	}
}

// TestStableID_StableAcrossLineShift documents the load-bearing property
// for the agent fix loop: when an agent edits a file and the secret moves
// from line 47 to line 49, the finding's id stays the same so the agent's
// reference to <id> remains valid. The current daemon fingerprint scheme
// includes Line in the locator, which means line shifts DO change the id.
//
// This test currently asserts the existing behavior (id changes on line
// shift) so we have an explicit pin. The plan's R2 / Open Question #1
// debates whether to remove Line from the file-kind locator; flipping this
// test's assertion is the test-side of that future change.
func TestStableID_LineShiftBehaviorIsPinned(t *testing.T) {
	f1 := finding.Finding{RuleID: "r", Path: "/p", Line: 47, Match: "m"}
	f2 := f1
	f2.Line = 49

	if f1.StableID() == f2.StableID() {
		t.Fatalf("line shift no longer changes StableID — review plan Open Question #1 before relaxing this test")
	}
}

// TestStableID_DepKindUsesAdvisoryID — depscan-shape findings fingerprint
// off the parsed advisory ID, not the redacted Match string.
func TestStableID_DepKindUsesAdvisoryID(t *testing.T) {
	f := finding.Finding{
		RuleID:  "osv-npm-package",
		Match:   "npm lodash@4.17.20",
		Context: "advisory=GHSA-jf85-cpcp-j695 fixed=4.17.21",
		Path:    "/repo/package-lock.json",
	}
	id := f.StableID()
	if id == "" {
		t.Fatalf("StableID empty for valid dep finding")
	}

	// Identity should not change when only the redacted match wording shifts
	// — it's the advisory ID that defines the dep-finding identity.
	f2 := f
	f2.Match = "npm lodash@4.17.20" // identical, but explicit pin
	if f.StableID() != f2.StableID() {
		t.Fatalf("dep finding id drifted across identical match strings")
	}

	// Different advisory IDs in the same package+version → different ids.
	f3 := f
	f3.Context = "advisory=GHSA-different-id fixed=4.17.21"
	if f.StableID() == f3.StableID() {
		t.Fatalf("dep finding id collided across different advisory IDs")
	}
}

// TestStableID_BetterleaksValidUnverifiedCollapse — the same redacted
// secret in the same file must have the same fingerprint regardless of
// whether the validation API call confirmed it valid or returned
// unverified this scan. Otherwise transient validation flaps would churn
// finding identity. This mirrors the orchestrator's collapse in
// internal/orchestrator/convert.go's fingerprintRuleID.
func TestStableID_BetterleaksValidUnverifiedCollapse(t *testing.T) {
	base := finding.Finding{
		Path:  "/repo/.env",
		Line:  3,
		Match: "sk-redacted",
	}
	valid := base
	valid.RuleID = "secret-betterleaks-valid"
	unverified := base
	unverified.RuleID = "secret-betterleaks-unverified"

	if valid.StableID() != unverified.StableID() {
		t.Fatalf("valid/unverified did not collapse: %q vs %q",
			valid.StableID(), unverified.StableID())
	}

	// Non-betterleaks rule with a similar name does NOT collapse.
	other := base
	other.RuleID = "secret-other-scanner"
	if valid.StableID() == other.StableID() {
		t.Fatalf("non-betterleaks rule got collapsed into betterleaks group")
	}
}

// TestStableID_DaemonAgreement is the load-bearing invariant: for every
// finding kind, the CLI's StableID() must equal the first 12 hex chars
// the daemon would compute via internal/orchestrator/convert.go's path.
//
// We don't import orchestrator directly (would create an import cycle in
// the test deps and orchestrator depends on heavyweight scan packages).
// Instead, we reconstruct the orchestrator's fingerprinting logic here.
// If the orchestrator's logic changes, this test MUST be updated in the
// same commit — diverging silently is exactly the drift bug this test
// exists to catch.
func TestStableID_DaemonAgreement(t *testing.T) {
	cases := []struct {
		name string
		f    finding.Finding
	}{
		{
			name: "agent-rule (file kind)",
			f: finding.Finding{
				RuleID: "claude-mcp-allowlist-missing",
				Path:   "/home/u/.claude/claude.json",
				Line:   42,
				Match:  "redacted-context",
			},
		},
		{
			name: "secret betterleaks valid (file kind, collapsed)",
			f: finding.Finding{
				RuleID: "secret-betterleaks-valid",
				Path:   "/repo/.env",
				Line:   3,
				Match:  "sk-redacted",
			},
		},
		{
			name: "secret betterleaks unverified (file kind, collapsed)",
			f: finding.Finding{
				RuleID: "secret-betterleaks-unverified",
				Path:   "/repo/.env",
				Line:   3,
				Match:  "sk-redacted",
			},
		},
		{
			name: "dep-package npm",
			f: finding.Finding{
				RuleID:  "osv-npm-package",
				Match:   "npm lodash@4.17.20",
				Context: "advisory=GHSA-jf85-cpcp-j695 fixed=4.17.21",
				Path:    "/repo/package-lock.json",
			},
		},
		{
			name: "dep-package scoped npm",
			f: finding.Finding{
				RuleID:  "osv-npm-package",
				Match:   "npm @types/node@18.0.0",
				Context: "advisory=GHSA-fake-scoped fixed=18.1.0",
				Path:    "/repo/package-lock.json",
			},
		},
		{
			name: "dep-package go",
			f: finding.Finding{
				RuleID:  "osv-go-package",
				Match:   "Go github.com/foo/bar@v1.2.3",
				Context: "advisory=GO-2024-1234 fixed=v1.2.4",
				Path:    "/repo/go.sum",
			},
		},
		{
			name: "dep-package with no advisory id (fallback)",
			f: finding.Finding{
				RuleID:  "osv-npm-package",
				Match:   "npm something@1.0.0",
				Context: "fixed=2.0.0", // no advisory= token
				Path:    "/repo/package-lock.json",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cliID := tc.f.StableID()
			daemonID := daemonReferenceFingerprint(t, tc.f)
			daemonShort := daemonID
			if len(daemonShort) > 12 {
				daemonShort = daemonShort[:12]
			}
			if cliID != daemonShort {
				t.Fatalf("CLI StableID %q != daemon first-12 %q (full daemon fp: %s)",
					cliID, daemonShort, daemonID)
			}
		})
	}
}

// daemonReferenceFingerprint reproduces the orchestrator's fingerprint
// dispatch in the test so we can assert byte-equality. Mirrors
// internal/orchestrator/convert.go::findingToStateFinding and
// depscanFindingToState. This duplication is intentional: the
// orchestrator and the bridge are not allowed to drift, and this test
// fails loudly if either side changes without the other.
func daemonReferenceFingerprint(t *testing.T, f finding.Finding) string {
	t.Helper()
	if eco, name, ver, ok := refParseDepMatch(f.Match); ok {
		locator, err := json.Marshal(map[string]any{
			"ecosystem":     eco,
			"name":          name,
			"version":       ver,
			"manifest_path": f.Path,
		})
		if err != nil {
			t.Fatalf("marshal dep locator: %v", err)
		}
		matchInput := refParseAdvisoryID(f.Context)
		if matchInput == "" {
			matchInput = f.RuleID
		}
		fp, err := state.Fingerprint(f.RuleID, "dep-package", locator, matchInput)
		if err != nil {
			t.Fatalf("state.Fingerprint dep: %v", err)
		}
		return fp
	}
	locator, err := json.Marshal(map[string]any{
		"path": f.Path,
		"line": f.Line,
	})
	if err != nil {
		t.Fatalf("marshal file locator: %v", err)
	}
	ruleID := f.RuleID
	if ruleID == "secret-betterleaks-valid" || ruleID == "secret-betterleaks-unverified" {
		ruleID = "secret-betterleaks"
	}
	fp, err := state.Fingerprint(ruleID, "file", locator, f.Match)
	if err != nil {
		t.Fatalf("state.Fingerprint file: %v", err)
	}
	return fp
}

func refParseDepMatch(match string) (eco, name, ver string, ok bool) {
	space := strings.IndexByte(match, ' ')
	if space < 0 {
		return "", "", "", false
	}
	eco = match[:space]
	rest := match[space+1:]
	at := strings.LastIndexByte(rest, '@')
	if at <= 0 {
		return "", "", "", false
	}
	name = rest[:at]
	ver = rest[at+1:]
	if name == "" || ver == "" {
		return "", "", "", false
	}
	return eco, name, ver, true
}

func refParseAdvisoryID(ctx string) string {
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
