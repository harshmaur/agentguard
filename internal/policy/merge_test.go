package policy

import (
	"testing"
	"time"

	"github.com/harshmaur/audr/internal/finding"
)

// TestPrecedence_AllSourcesSilenceTheFinding: each silencing source
// from B3.4 works in isolation. Four fixtures (rule disabled, scope
// excluded, scope-include-misses, suppression match). In each case
// the rule should not produce findings (or, where it does run, the
// finding should be suppressed).
func TestPrecedence_AllSourcesSilenceTheFinding(t *testing.T) {
	enabled := false
	p1 := Policy{Rules: map[string]RuleOverride{
		"r": {Enabled: &enabled},
	}}
	if NewEffective(p1, time.Time{}).IsRuleEnabled("r") {
		t.Errorf("rule with Enabled=false should be disabled")
	}

	p2 := Policy{Rules: map[string]RuleOverride{
		"r": {Scope: Scope{Exclude: []string{"/x/*"}}},
	}}
	if NewEffective(p2, time.Time{}).IsPathInScope("r", "/x/file.yaml") {
		t.Errorf("scope.exclude should remove path from scope")
	}

	p3 := Policy{Rules: map[string]RuleOverride{
		"r": {Scope: Scope{Include: []string{"/cursor/*"}}},
	}}
	if NewEffective(p3, time.Time{}).IsPathInScope("r", "/x/file.yaml") {
		t.Errorf("path not in include set should be out of scope")
	}

	p4 := Policy{Suppressions: []Suppression{
		{Rule: "r", Path: "/x/file.yaml", Reason: "fixture"},
	}}
	if !NewEffective(p4, time.Time{}).IsSuppressed("r", "/x/file.yaml") {
		t.Errorf("suppression match should fire IsSuppressed")
	}
}

// TestPrecedence_DisableBeatsScope: a rule with enabled=false MUST
// NOT fire even on a path explicitly in scope.include. Step 2 wins
// over step 3 in B3.4's order.
func TestPrecedence_DisableBeatsScope(t *testing.T) {
	enabled := false
	p := Policy{Rules: map[string]RuleOverride{
		"r": {
			Enabled: &enabled,
			Scope:   Scope{Include: []string{"/cursor/*"}},
		},
	}}
	eff := NewEffective(p, time.Time{})
	if eff.IsRuleEnabled("r") {
		t.Errorf("Enabled=false must win over Scope.Include match")
	}
	// IsPathInScope itself would say "yes, included" — that's fine.
	// The registry wrap checks IsRuleEnabled FIRST per precedence.
	if !eff.IsPathInScope("r", "/cursor/x") {
		t.Errorf("IsPathInScope independently reports include hit")
	}
}

// TestPrecedence_SeverityOverrideNeverRescuesSuppressed: a finding
// silenced via suppression must NOT be emitted at the override
// severity. Step 7 (severity rewrite) must not run before step 6
// (suppression). We verify this contract at the Effective surface
// level — IsSuppressed must come back true regardless of any
// severity override.
func TestPrecedence_SeverityOverrideNeverRescuesSuppressed(t *testing.T) {
	critical := "critical"
	p := Policy{
		Rules: map[string]RuleOverride{
			"r": {Severity: &critical},
		},
		Suppressions: []Suppression{
			{Rule: "r", Path: "/x", Reason: "false positive"},
		},
	}
	eff := NewEffective(p, time.Time{})
	if !eff.IsSuppressed("r", "/x") {
		t.Errorf("severity override must not interfere with suppression check")
	}
}

// TestPrecedence_ExpiredSuppressionsLeak: the load-bearing
// regression from B3.4. An expired suppression MUST NOT silence
// findings — they need to start firing again so the user notices
// the expired exclusion.
func TestPrecedence_ExpiredSuppressionsLeak(t *testing.T) {
	expired := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	p := Policy{
		Suppressions: []Suppression{
			{Rule: "r", Path: "/x", Reason: "temp; revisit", Expires: &expired},
		},
	}
	now := time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC) // way past expiry
	if NewEffective(p, now).IsSuppressed("r", "/x") {
		t.Errorf("expired suppression should NOT silence findings")
	}

	// Counter-test: an unexpired suppression still works.
	future := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	p2 := Policy{
		Suppressions: []Suppression{
			{Rule: "r", Path: "/x", Reason: "still valid", Expires: &future},
		},
	}
	if !NewEffective(p2, now).IsSuppressed("r", "/x") {
		t.Errorf("unexpired suppression must silence findings")
	}
}

// TestSeverityOverride_AppliesWhenSet: when a rule has a severity
// override AND the path is in scope AND not suppressed, the
// finding's severity should be rewritten.
func TestSeverityOverride_AppliesWhenSet(t *testing.T) {
	med := "medium"
	p := Policy{Rules: map[string]RuleOverride{
		"r": {Severity: &med},
	}}
	eff := NewEffective(p, time.Time{})
	got := eff.EffectiveSeverity("r", finding.SeverityHigh)
	if got != finding.SeverityMedium {
		t.Errorf("severity override = %v, want medium", got)
	}
}

// TestSeverityOverride_FallsThroughToNatural: no override → natural
// severity used.
func TestSeverityOverride_FallsThroughToNatural(t *testing.T) {
	p := Policy{}
	eff := NewEffective(p, time.Time{})
	got := eff.EffectiveSeverity("r", finding.SeverityCritical)
	if got != finding.SeverityCritical {
		t.Errorf("no-override severity = %v, want critical", got)
	}
}

// TestAllowlistContains: rules consume allowlists via
// ctx.AllowlistContains. Verify the basic lookup.
func TestAllowlistContains(t *testing.T) {
	p := Policy{
		Allowlists: map[string]Allowlist{
			"approved-mcp": {Entries: []string{"x", "y", "z"}},
		},
	}
	eff := NewEffective(p, time.Time{})
	for _, item := range []string{"x", "y", "z"} {
		if !eff.AllowlistContains("approved-mcp", item) {
			t.Errorf("allowlist should contain %q", item)
		}
	}
	if eff.AllowlistContains("approved-mcp", "missing") {
		t.Errorf("allowlist should not contain 'missing'")
	}
	if eff.AllowlistContains("does-not-exist", "x") {
		t.Errorf("unknown allowlist must return false, not panic")
	}
}

// TestScope_HomeRelativeGlob: ~/... globs match against the actual
// home dir. Pin the override so the test is deterministic.
func TestScope_HomeRelativeGlob(t *testing.T) {
	prev := userHomeDirFunc
	defer func() { userHomeDirFunc = prev }()
	userHomeDirFunc = func() (string, error) { return "/Users/test", nil }

	p := Policy{Rules: map[string]RuleOverride{
		"r": {Scope: Scope{Include: []string{"~/.cursor/*"}}},
	}}
	eff := NewEffective(p, time.Time{})
	if !eff.IsPathInScope("r", "/Users/test/.cursor/mcp.json") {
		t.Errorf("~/.cursor/* should match /Users/test/.cursor/mcp.json")
	}
	if eff.IsPathInScope("r", "/Users/other/.cursor/mcp.json") {
		t.Errorf("~/.cursor/* should NOT match a different user's home")
	}
}

// TestScope_WindowsPathSeparators: a Unix-style glob in the policy
// should match a Windows-native path with backslashes. Same
// normalization audr's parse layer applies.
func TestScope_WindowsPathSeparators(t *testing.T) {
	prev := userHomeDirFunc
	defer func() { userHomeDirFunc = prev }()
	userHomeDirFunc = func() (string, error) { return `C:\Users\X`, nil }

	p := Policy{Rules: map[string]RuleOverride{
		"r": {Scope: Scope{Include: []string{"~/.cursor/**"}}},
	}}
	eff := NewEffective(p, time.Time{})
	if !eff.IsPathInScope("r", `C:\Users\X\.cursor\mcp.json`) {
		t.Errorf("Unix glob should match Windows path after normalization")
	}
}

// TestScope_DoubleStarFallsBackToSingleStar: filepath.Match doesn't
// support `**`. Document the v1.2 limitation: `**` is treated as `*`.
// The dashboard tooltip warns users; this test pins the fallback
// semantics so the behavior is intentional, not accidental.
func TestScope_DoubleStarFallsBackToSingleStar(t *testing.T) {
	p := Policy{Rules: map[string]RuleOverride{
		"r": {Scope: Scope{Include: []string{"/cursor/**"}}},
	}}
	eff := NewEffective(p, time.Time{})
	// /cursor/** → after normalization treated as `/cursor/*` PLUS
	// prefix-match. So `/cursor/anything` matches even if nested.
	if !eff.IsPathInScope("r", "/cursor/mcp.json") {
		t.Errorf("/cursor/** should match /cursor/mcp.json")
	}
	if !eff.IsPathInScope("r", "/cursor/sub/deep/file.json") {
		t.Errorf("/cursor/** should match nested path via prefix fallback")
	}
	if eff.IsPathInScope("r", "/elsewhere/file.json") {
		t.Errorf("/cursor/** should NOT match /elsewhere/file.json")
	}
}
