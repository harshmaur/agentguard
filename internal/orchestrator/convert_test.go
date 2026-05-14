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

func TestParseDepscanMatchSplitsCorrectly(t *testing.T) {
	cases := []struct {
		match            string
		wantEco, wantName, wantVer string
		wantOK           bool
	}{
		{"npm lodash@4.17.20", "npm", "lodash", "4.17.20", true},
		{"npm @types/node@20.10.5", "npm", "@types/node", "20.10.5", true},
		{"PyPI requests@2.31.0", "PyPI", "requests", "2.31.0", true},
		{"Go github.com/foo/bar@v1.2.3", "Go", "github.com/foo/bar", "v1.2.3", true},
		{"crates serde@1.0.193", "crates", "serde", "1.0.193", true},
		// Malformed inputs return ok=false (caller falls back).
		{"no-spaces", "", "", "", false},
		{"ecosystem name-no-at", "", "", "", false},
		{"ecosystem @leading-at-only", "", "", "", false},
	}
	for _, tt := range cases {
		t.Run(tt.match, func(t *testing.T) {
			eco, name, ver, ok := parseDepscanMatch(tt.match)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (eco=%q name=%q ver=%q)", ok, tt.wantOK, eco, name, ver)
			}
			if !tt.wantOK {
				return
			}
			if eco != tt.wantEco || name != tt.wantName || ver != tt.wantVer {
				t.Errorf("got (%q, %q, %q), want (%q, %q, %q)", eco, name, ver, tt.wantEco, tt.wantName, tt.wantVer)
			}
		})
	}
}

func TestParseDepscanContextExtractsAdvisoryAndFixed(t *testing.T) {
	advisory, fixed := parseDepscanContext("advisory=CVE-2020-8203 fixed=4.17.21")
	if advisory != "CVE-2020-8203" {
		t.Errorf("advisory = %q, want CVE-2020-8203", advisory)
	}
	if fixed != "4.17.21" {
		t.Errorf("fixed = %q, want 4.17.21", fixed)
	}

	// Missing fixed is OK.
	advisory, fixed = parseDepscanContext("advisory=GHSA-xxxx")
	if advisory != "GHSA-xxxx" || fixed != "" {
		t.Errorf("got (%q, %q), want (GHSA-xxxx, empty)", advisory, fixed)
	}
}

func TestDepscanFindingToStateProducesDepPackageKind(t *testing.T) {
	f := finding.New(finding.Args{
		RuleID:      "osv-vulnerability",
		Severity:    finding.SeverityHigh,
		Title:       "Vulnerable dependency: lodash",
		Description: "CVE-2020-8203: prototype pollution",
		Path:        "/home/u/code/dashboard-app/package-lock.json",
		Match:       "npm lodash@4.17.20",
		Context:     "advisory=CVE-2020-8203 fixed=4.17.21",
	})
	sf, err := depscanFindingToState(f, 42)
	if err != nil {
		t.Fatal(err)
	}
	if sf.Kind != "dep-package" {
		t.Errorf("kind = %q, want dep-package", sf.Kind)
	}
	if sf.Category != "deps" {
		t.Errorf("category = %q, want deps", sf.Category)
	}
	if sf.MatchRedacted != "CVE-2020-8203" {
		t.Errorf("MatchRedacted = %q, want CVE-2020-8203 (advisory extracted from Context)", sf.MatchRedacted)
	}
	if sf.RuleID != "osv-npm-package" {
		t.Errorf("rule_id = %q, want osv-npm-package (ecosystem dispatch)", sf.RuleID)
	}

	// Locator round-trips with the structured shape.
	var loc map[string]any
	if err := json.Unmarshal(sf.Locator, &loc); err != nil {
		t.Fatal(err)
	}
	if loc["ecosystem"] != "npm" || loc["name"] != "lodash" || loc["version"] != "4.17.20" {
		t.Errorf("locator = %+v, missing fields", loc)
	}
	if loc["manifest_path"] != "/home/u/code/dashboard-app/package-lock.json" {
		t.Errorf("manifest_path = %v, want the file path", loc["manifest_path"])
	}
}

func TestDepscanFindingToStateFallbackOnUnparseableMatch(t *testing.T) {
	// Match doesn't fit "<eco> <name>@<ver>" — converter falls back
	// to file-kind treatment so the finding still surfaces (better
	// than dropping it silently).
	f := finding.New(finding.Args{
		RuleID:   "osv-vulnerability",
		Severity: finding.SeverityMedium,
		Title:    "weird match",
		Path:     "/m.json",
		Match:    "unparseable",
	})
	sf, err := depscanFindingToState(f, 1)
	if err != nil {
		t.Fatal(err)
	}
	if sf.Kind != "file" {
		t.Errorf("kind = %q, want file (fallback)", sf.Kind)
	}
}

func TestRuleIDForDepEcosystemNormalizes(t *testing.T) {
	cases := map[string]string{
		"npm":     "osv-npm-package",
		"NPM":     "osv-npm-package",
		"PyPI":    "osv-pypi-package",
		"Go":      "osv-go-package",
		"Maven":   "osv-maven-package",
		"crates.io": "osv-crates-io-package",
	}
	for in, want := range cases {
		if got := ruleIDForDepEcosystem(in); got != want {
			t.Errorf("ruleIDForDepEcosystem(%q) = %q, want %q", in, got, want)
		}
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
