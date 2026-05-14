package templates

import (
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/state"
)

func mkFinding(ruleID, kind string, locator string, match string) state.Finding {
	return state.Finding{
		Fingerprint:   "test-fp",
		RuleID:        ruleID,
		Severity:      "high",
		Category:      "ai-agent",
		Kind:          kind,
		Locator:       []byte(locator),
		Title:         "test title",
		Description:   "test description",
		MatchRedacted: match,
	}
}

func TestRegistryDispatchExactMatch(t *testing.T) {
	r := New()
	f := mkFinding("codex-trust-home-or-broad", "file",
		`{"path":"/home/u/.codex/config.toml","line":12}`, "")
	human, ai, ok := r.Lookup(f)
	if !ok {
		t.Fatal("Lookup ok=false; want true")
	}
	if !strings.Contains(human, "codex") || !strings.Contains(human, "config.toml") {
		t.Errorf("human steps missing context: %q", human)
	}
	if !strings.Contains(ai, "trust_level") {
		t.Errorf("AI prompt missing trust_level mention: %q", ai)
	}
	if !strings.Contains(ai, "/home/u/.codex/config.toml") {
		t.Errorf("AI prompt missing path parameterization: %q", ai)
	}
}

func TestRegistryDispatchEcosystemPrefix(t *testing.T) {
	r := New()
	f := mkFinding("osv-npm-package", "dep-package",
		`{"ecosystem":"npm","name":"lodash","version":"4.17.20","manifest_path":"/x/package-lock.json"}`,
		"CVE-2020-8203")
	human, ai, _ := r.Lookup(f)
	if !strings.Contains(human, "npm update lodash") {
		t.Errorf("human steps missing npm update command: %q", human)
	}
	if !strings.Contains(ai, "/x/package-lock.json") {
		t.Errorf("AI prompt missing manifest path: %q", ai)
	}
	if !strings.Contains(ai, "CVE-2020-8203") {
		t.Errorf("AI prompt missing advisory ID: %q", ai)
	}
}

func TestRegistryDispatchOSPkgPrefix(t *testing.T) {
	r := New()
	f := mkFinding("osv-dpkg-openssl", "os-package",
		`{"manager":"dpkg","name":"openssl","version":"3.0.7"}`, "CVE-2026-43581")
	human, ai, _ := r.Lookup(f)
	if !strings.Contains(human, "apt upgrade openssl") {
		t.Errorf("dpkg recipe missing apt upgrade openssl: %q", human)
	}
	if !strings.Contains(ai, "sudo") {
		t.Errorf("AI prompt should warn about sudo: %q", ai)
	}
}

func TestRegistrySecretsRotationFlow(t *testing.T) {
	r := New()
	f := mkFinding("secret-trufflehog-verified", "file",
		`{"path":"~/.env","line":3}`, "detector=AWS secret=AKIA****")
	human, ai, _ := r.Lookup(f)
	// Rotation must come BEFORE editing the file.
	rotateIdx := strings.Index(human, "ROTATE")
	editIdx := strings.Index(human, "Remove the leaked value")
	if rotateIdx < 0 || editIdx < 0 {
		t.Fatalf("missing rotate-or-edit steps: %q", human)
	}
	if rotateIdx >= editIdx {
		t.Errorf("rotate must come before edit; got rotate@%d edit@%d", rotateIdx, editIdx)
	}
	// AWS-specific provider URL must appear.
	if !strings.Contains(human, "AWS IAM console") {
		t.Errorf("missing AWS-specific rotation URL: %q", human)
	}
	// AI prompt must instruct NOT to print the secret back.
	if !strings.Contains(ai, "Do not print the redacted value back") {
		t.Errorf("AI prompt missing the no-echo instruction: %q", ai)
	}
}

func TestRegistryFallbackForUnknownRule(t *testing.T) {
	r := New()
	f := mkFinding("brand-new-rule-not-in-templates", "file", `{"path":"/x.txt"}`, "")
	human, ai, ok := r.Lookup(f)
	if !ok {
		t.Fatal("fallback should always claim, got ok=false")
	}
	if !strings.Contains(ai, "audr does not have a hand-authored remediation template") {
		t.Errorf("fallback AI prompt should be honest about being a fallback: %q", ai)
	}
	if !strings.Contains(human, "test title") {
		t.Errorf("fallback human steps should surface the title: %q", human)
	}
}

func TestEcosystemHandlerFallsBackOnMissingLocator(t *testing.T) {
	r := New()
	// rule_id matches the ecosystem prefix but locator is missing the
	// name field — the ecosystem handler should return ok=false and
	// dispatch should fall through to the generic fallback.
	f := mkFinding("osv-npm-package", "dep-package", `{}`, "")
	_, ai, ok := r.Lookup(f)
	if !ok {
		t.Fatal("fallback should still claim")
	}
	if strings.Contains(ai, "npm update") {
		t.Errorf("ecosystem-specific command leaked through when locator was empty: %q", ai)
	}
}

func TestLocatorIntHandlesFloat64FromJSON(t *testing.T) {
	r := New()
	f := mkFinding("claude-hook-shell-rce", "file",
		`{"path":"~/.claude/settings.json","line":47}`, "")
	human, _, _ := r.Lookup(f)
	// Don't strictly require the line number to appear (this handler
	// doesn't currently render it), but the lookup must succeed.
	if len(human) == 0 {
		t.Fatal("empty human steps for line-bearing finding")
	}
}

func TestAllEcosystemAliasesDispatch(t *testing.T) {
	// Each alias must route to a handler that includes the correct
	// upgrade command in the human steps.
	cases := map[string]string{
		"osv-npm-package":     "npm update",
		"osv-pypi-package":    "pip install --upgrade",
		"osv-pip-package":     "pip install --upgrade",
		"osv-go-package":      "go get -u",
		"osv-rubygems-package": "bundle update",
		"osv-gem-package":     "bundle update",
		"osv-crates-io-package": "cargo update",
		"osv-cargo-package":   "cargo update",
		"osv-maven-package":   "mvn dependency",
		"osv-packagist-package": "composer update",
		"osv-composer-package":  "composer update",
		"osv-nuget-package":   "dotnet add package",
		"osv-hex-package":     "mix deps.update",
		"osv-pub-package":     "dart pub upgrade",
	}
	r := New()
	for ruleID, wantCmd := range cases {
		t.Run(ruleID, func(t *testing.T) {
			f := mkFinding(ruleID, "dep-package",
				`{"ecosystem":"any","name":"some-pkg","version":"1.0.0","manifest_path":"/x"}`,
				"CVE-2024-1234")
			human, _, _ := r.Lookup(f)
			if !strings.Contains(human, wantCmd) {
				t.Errorf("rule %q: human missing %q\n  got: %s", ruleID, wantCmd, human)
			}
		})
	}
}

func TestAllOSPkgManagersDispatch(t *testing.T) {
	cases := map[string]string{
		"osv-dpkg-openssl": "apt upgrade openssl",
		"osv-rpm-glibc":    "dnf upgrade glibc",
		"osv-apk-busybox":  "apk upgrade busybox",
	}
	r := New()
	for ruleID, wantCmd := range cases {
		t.Run(ruleID, func(t *testing.T) {
			parts := strings.SplitN(ruleID, "-", 3)
			pkgName := parts[2]
			f := mkFinding(ruleID, "os-package",
				`{"manager":"`+parts[1]+`","name":"`+pkgName+`","version":"1.0"}`,
				"CVE-2024-1234")
			human, _, _ := r.Lookup(f)
			if !strings.Contains(human, wantCmd) {
				t.Errorf("rule %q: human missing %q\n  got: %s", ruleID, wantCmd, human)
			}
		})
	}
}
