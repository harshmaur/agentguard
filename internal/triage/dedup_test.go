package triage

import (
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/finding"
)

func TestDefaultDedupKey_StableAcrossPaths(t *testing.T) {
	// Two findings of the same rule on different paths with the same
	// match payload MUST produce the same dedup key — that is the
	// whole point of the v1.3 roll-up.
	a := finding.Finding{
		RuleID: "dependency-osv-vulnerability",
		Match:  "picomatch < 2.3.1 (CVE-2024-xxxx)",
		Path:   "/home/alice/projects/foo/package-lock.json",
	}
	b := finding.Finding{
		RuleID: "dependency-osv-vulnerability",
		Match:  "picomatch < 2.3.1 (CVE-2024-xxxx)",
		Path:   "/home/alice/.claude/plugins/cache/vercel/0.42.1/bun.lock",
	}
	if DefaultDedupKey(a) != DefaultDedupKey(b) {
		t.Errorf("same rule + same match across paths must collapse — got %q vs %q",
			DefaultDedupKey(a), DefaultDedupKey(b))
	}
}

func TestDefaultDedupKey_DistinctAcrossRules(t *testing.T) {
	// Different rule IDs must produce different keys even when match
	// strings collide — guarantees cross-rule false-positive collapses
	// are impossible by construction.
	a := finding.Finding{RuleID: "rule-one", Match: "same-payload"}
	b := finding.Finding{RuleID: "rule-two", Match: "same-payload"}
	if DefaultDedupKey(a) == DefaultDedupKey(b) {
		t.Errorf("different rules must NOT collapse: %q == %q",
			DefaultDedupKey(a), DefaultDedupKey(b))
	}
	// Sanity — both keys are prefixed by rule_id.
	if !strings.HasPrefix(DefaultDedupKey(a), "rule-one:") {
		t.Errorf("key lost rule prefix: %q", DefaultDedupKey(a))
	}
	if !strings.HasPrefix(DefaultDedupKey(b), "rule-two:") {
		t.Errorf("key lost rule prefix: %q", DefaultDedupKey(b))
	}
}

func TestDefaultDedupKey_DistinctAcrossMatches(t *testing.T) {
	a := finding.Finding{RuleID: "rx", Match: "picomatch < 2.3.1"}
	b := finding.Finding{RuleID: "rx", Match: "undici < 5.28.4"}
	if DefaultDedupKey(a) == DefaultDedupKey(b) {
		t.Errorf("different matches must NOT collapse: %q == %q",
			DefaultDedupKey(a), DefaultDedupKey(b))
	}
}

func TestDefaultDedupKey_NormalisesWhitespaceAndCase(t *testing.T) {
	a := finding.Finding{RuleID: "rx", Match: "Foo Bar"}
	b := finding.Finding{RuleID: "rx", Match: "  foo bar  "}
	if DefaultDedupKey(a) != DefaultDedupKey(b) {
		t.Errorf("case+whitespace variants must collapse: %q vs %q",
			DefaultDedupKey(a), DefaultDedupKey(b))
	}
}

func TestDefaultDedupKey_FallsBackToTitleWhenMatchEmpty(t *testing.T) {
	// Rules without a redacted match payload (e.g. structural checks)
	// must still get a distinct key per (rule, title).
	a := finding.Finding{RuleID: "structural", Title: "Hook exposes shell"}
	b := finding.Finding{RuleID: "structural", Title: "Permission allowlist too broad"}
	if DefaultDedupKey(a) == DefaultDedupKey(b) {
		t.Errorf("title fallback must distinguish: got identical key %q", DefaultDedupKey(a))
	}
}

func TestFillTriageFields_RulePopulatedFieldsWin(t *testing.T) {
	const home = "/home/alice"
	rulePopulated := finding.Finding{
		RuleID:          "dependency-osv-vulnerability",
		Path:            home + "/.claude/plugins/cache/vercel/0.42.1/bun.lock",
		DedupGroupKey:   "osv:picomatch:2.3.1:CVE-2024-xxxx",
		FixAuthority:    finding.FixAuthorityMaintainer,
		SecondaryNotify: "vercel-pinned-from-rule",
	}
	got := FillTriageFields(rulePopulated, home)
	if got.DedupGroupKey != "osv:picomatch:2.3.1:CVE-2024-xxxx" {
		t.Errorf("rule-supplied DedupGroupKey was overwritten: %q", got.DedupGroupKey)
	}
	if got.FixAuthority != finding.FixAuthorityMaintainer {
		t.Errorf("rule-supplied FixAuthority was overwritten: %q", got.FixAuthority)
	}
	if got.SecondaryNotify != "vercel-pinned-from-rule" {
		t.Errorf("rule-supplied SecondaryNotify was overwritten: %q", got.SecondaryNotify)
	}
}

func TestFillTriageFields_BlanksGetClassified(t *testing.T) {
	const home = "/home/alice"
	f := finding.Finding{
		RuleID: "dependency-osv-vulnerability",
		Match:  "picomatch < 2.3.1",
		Path:   home + "/.claude/plugins/cache/vercel/0.42.1/bun.lock",
	}
	got := FillTriageFields(f, home)
	if got.DedupGroupKey == "" {
		t.Error("blank DedupGroupKey should be filled with default")
	}
	if got.FixAuthority != finding.FixAuthorityMaintainer {
		t.Errorf("blank FixAuthority should be classified MAINTAINER, got %q", got.FixAuthority)
	}
	if got.SecondaryNotify != "vercel" {
		t.Errorf("SecondaryNotify should be 'vercel' from path-class, got %q", got.SecondaryNotify)
	}
}

func TestFillTriageFields_UserProjectFallthrough(t *testing.T) {
	const home = "/home/alice"
	f := finding.Finding{
		RuleID: "dependency-osv-vulnerability",
		Match:  "picomatch < 2.3.1",
		Path:   home + "/projects/audr/package-lock.json",
	}
	got := FillTriageFields(f, home)
	if got.FixAuthority != finding.FixAuthorityYou {
		t.Errorf("user project should fall through to YOU, got %q", got.FixAuthority)
	}
	if got.SecondaryNotify != "" {
		t.Errorf("user project should not carry SecondaryNotify, got %q", got.SecondaryNotify)
	}
}
