package orchestrator

import (
	"encoding/json"
	"testing"

	"github.com/harshmaur/audr/internal/finding"
)

func TestCategorizeRuleIDDispatch(t *testing.T) {
	cases := []struct {
		ruleID string
		want   string
	}{
		{"claude-hook-shell-rce", "ai-agent"},
		{"codex-trust-home-or-broad", "ai-agent"},
		{"secret-trufflehog-verified", "secrets"},
		{"secret-trufflehog-unverified", "secrets"},
		{"osv-dpkg-openssl", "deps"},
		{"dep-something", "deps"},
		{"ospkg-some-cve", "os-pkg"},
		{"unknown-future-rule", "ai-agent"}, // fallback bucket
	}
	for _, tt := range cases {
		t.Run(tt.ruleID, func(t *testing.T) {
			if got := categorizeRuleID(tt.ruleID); got != tt.want {
				t.Errorf("category(%q) = %q, want %q", tt.ruleID, got, tt.want)
			}
		})
	}
}

func TestFindingToStateFindingShape(t *testing.T) {
	args := finding.Args{
		RuleID:      "rule-x",
		Severity:    finding.SeverityHigh,
		Title:       "title",
		Description: "desc",
		Path:        "/a/b/c.toml",
		Line:        42,
		Match:       "redacted-match",
	}
	f := finding.New(args)

	got, err := findingToStateFinding(f, 7, "ai-agent")
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if got.RuleID != "rule-x" {
		t.Errorf("RuleID = %q, want rule-x", got.RuleID)
	}
	if got.Severity != "high" {
		t.Errorf("Severity = %q, want high (typed Severity must stringify)", got.Severity)
	}
	if got.Category != "ai-agent" {
		t.Errorf("Category = %q, want ai-agent", got.Category)
	}
	if got.Kind != "file" {
		t.Errorf("Kind = %q, want file (all rule findings are file-kind in v1)", got.Kind)
	}
	if got.FirstSeenScan != 7 || got.LastSeenScan != 7 {
		t.Errorf("scan IDs = %d/%d, want 7/7", got.FirstSeenScan, got.LastSeenScan)
	}

	// Locator round-trips through JSON with {path, line}.
	var loc map[string]any
	if err := json.Unmarshal(got.Locator, &loc); err != nil {
		t.Fatalf("locator JSON: %v", err)
	}
	if loc["path"] != "/a/b/c.toml" {
		t.Errorf("locator.path = %v, want /a/b/c.toml", loc["path"])
	}
	// line round-trips as float64 from json.Unmarshal into any.
	if l, ok := loc["line"].(float64); !ok || int(l) != 42 {
		t.Errorf("locator.line = %v (%T), want 42", loc["line"], loc["line"])
	}

	// Fingerprint is non-empty and hex-shaped.
	if len(got.Fingerprint) != 64 {
		t.Errorf("fingerprint length = %d, want 64 (sha256 hex)", len(got.Fingerprint))
	}
}

func TestFindingToStateFindingFingerprintStableAcrossEquivalentInputs(t *testing.T) {
	// Same rule + same path/line + same match → same fingerprint.
	// This is the contract that lets resolution detection work:
	// re-detecting the same finding next cycle MUST produce the same
	// fingerprint so it doesn't look like a new row.
	mk := func() finding.Finding {
		return finding.New(finding.Args{
			RuleID: "r", Severity: finding.SeverityHigh,
			Path: "/p", Line: 10, Match: "m",
		})
	}
	a, err := findingToStateFinding(mk(), 1, "ai-agent")
	if err != nil {
		t.Fatal(err)
	}
	b, err := findingToStateFinding(mk(), 2, "ai-agent") // different scan ID — irrelevant to fingerprint
	if err != nil {
		t.Fatal(err)
	}
	if a.Fingerprint != b.Fingerprint {
		t.Errorf("fingerprint drift across equivalent inputs: %s vs %s", a.Fingerprint, b.Fingerprint)
	}
}
