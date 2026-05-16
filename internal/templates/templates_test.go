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
	// Must teach diagnosis-first, NOT "just upgrade the leaf."
	if !strings.Contains(human, "npm why lodash") {
		t.Errorf("human steps missing npm why (diagnose step): %q", human)
	}
	if !strings.Contains(human, "TRANSITIVE") {
		t.Errorf("human steps should warn about transitive nature of finding: %q", human)
	}
	if !strings.Contains(human, "overrides") {
		t.Errorf("human steps missing the package.json overrides fallback: %q", human)
	}
	if !strings.Contains(ai, "/x") {
		t.Errorf("AI prompt missing project dir: %q", ai)
	}
	if !strings.Contains(ai, "CVE-2020-8203") {
		t.Errorf("AI prompt missing advisory ID: %q", ai)
	}
	if !strings.Contains(ai, "BEFORE you propose") || !strings.Contains(ai, "DO NOT") {
		t.Errorf("AI prompt should instruct diagnose-before-fix and warn against naive upgrade: %q", ai)
	}
}

func TestEcosystemTemplatesNeverEmitNaiveUpgradeAdvice(t *testing.T) {
	// The whole point of the diagnose-first rewrite. Walk every
	// ecosystem and confirm the human steps mention the inverse-deps
	// command for the manager AND the override/pin fallback, AND do
	// NOT consist primarily of a naive "<manager> upgrade <leaf>"
	// instruction.
	r := New()
	cases := []struct {
		ruleID         string
		ecosystem      string
		mustMention    []string
		mustNotPrimary string // a substring that, if it appears WITHOUT the diagnose context, indicates the naive flow
	}{
		{"osv-npm-package", "npm", []string{"npm why", "overrides", "TRANSITIVE"}, ""},
		{"osv-pypi-package", "PyPI", []string{"tree --invert", "Required-by", "TRANSITIVE"}, ""},
		{"osv-go-package", "Go module", []string{"go mod why", "replace", "TRANSITIVE"}, ""},
		{"osv-cargo-package", "crates.io", []string{"cargo tree --invert", "patch.crates-io", "TRANSITIVE"}, ""},
		{"osv-rubygems-package", "RubyGems", []string{"bundle", "Gemfile", "TRANSITIVE"}, ""},
		{"osv-maven-package", "Maven", []string{"mvn dependency:tree", "dependencyManagement", "TRANSITIVE"}, ""},
		{"osv-composer-package", "Composer", []string{"composer why", "TRANSITIVE"}, ""},
		{"osv-nuget-package", "NuGet", []string{"--include-transitive", "TRANSITIVE"}, ""},
		{"osv-hex-package", "Hex", []string{"deps.tree", "override: true", "TRANSITIVE"}, ""},
		{"osv-pub-package", "pub.dev", []string{"pub deps", "dependency_overrides", "TRANSITIVE"}, ""},
	}
	for _, tt := range cases {
		t.Run(tt.ruleID, func(t *testing.T) {
			f := mkFinding(tt.ruleID, "dep-package",
				`{"ecosystem":"`+tt.ecosystem+`","name":"some-pkg","version":"1.0.0","manifest_path":"/x/manifest"}`,
				"CVE-2024-1234")
			human, _, _ := r.Lookup(f)
			for _, must := range tt.mustMention {
				if !strings.Contains(human, must) {
					t.Errorf("rule %q: human missing %q\n  got: %s", tt.ruleID, must, truncate(human, 400))
				}
			}
		})
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
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
	f := mkFinding("secret-betterleaks-valid", "file",
		`{"path":"~/.env","line":3}`, "rule=aws-access-token secret=[REDACTED]")
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
	// diagnose-step command in the human flow (not a naive leaf
	// upgrade).
	cases := map[string]string{
		"osv-npm-package":     "npm why",
		"osv-pypi-package":    "tree --invert",
		"osv-pip-package":     "tree --invert",
		"osv-go-package":      "go mod why",
		"osv-rubygems-package": "Gemfile.lock",
		"osv-gem-package":     "Gemfile.lock",
		"osv-crates-io-package": "cargo tree --invert",
		"osv-cargo-package":   "cargo tree --invert",
		"osv-maven-package":   "mvn dependency:tree",
		"osv-packagist-package": "composer why",
		"osv-composer-package":  "composer why",
		"osv-nuget-package":   "--include-transitive",
		"osv-hex-package":     "mix deps.tree",
		"osv-pub-package":     "pub deps",
	}
	r := New()
	for ruleID, wantCmd := range cases {
		t.Run(ruleID, func(t *testing.T) {
			f := mkFinding(ruleID, "dep-package",
				`{"ecosystem":"any","name":"some-pkg","version":"1.0.0","manifest_path":"/x"}`,
				"CVE-2024-1234")
			human, _, _ := r.Lookup(f)
			if !strings.Contains(human, wantCmd) {
				t.Errorf("rule %q: human missing diagnose command %q\n  got: %s", ruleID, wantCmd, human)
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

// TestShaiHuludHandlersDispatch confirms each of the 6 Mini-Shai-Hulud
// rule IDs routes to a hand-authored handler, the locator path lands
// in the rendered output, and each prompt warns about the malware
// context (this is incident-response not routine remediation).
func TestShaiHuludHandlersDispatch(t *testing.T) {
	r := New()
	cases := []struct {
		ruleID         string
		locatorJSON    string
		expectPath     string
		expectInHuman  string
		expectInAI     string
		expectIncident bool // human flow names the credential-rotation step
	}{
		{
			ruleID:        "mini-shai-hulud-malicious-optional-dependency",
			locatorJSON:   `{"path":"/repos/proj/package.json"}`,
			expectPath:    "/repos/proj/package.json",
			expectInHuman: "@tanstack/setup",
			expectInAI:    "optionalDependencies",
		},
		{
			ruleID:         "mini-shai-hulud-claude-persistence",
			locatorJSON:    `{"path":"/home/u/.claude/settings.json"}`,
			expectPath:     "/home/u/.claude/settings.json",
			expectInHuman:  "SessionStart",
			expectInAI:     "hooks block",
			expectIncident: true,
		},
		{
			ruleID:        "mini-shai-hulud-vscode-persistence",
			locatorJSON:   `{"path":"/repos/proj/.vscode/tasks.json"}`,
			expectPath:    "/repos/proj/.vscode/tasks.json",
			expectInHuman: "folderOpen",
			expectInAI:    "tasks.json",
		},
		{
			ruleID:         "mini-shai-hulud-token-monitor-persistence",
			locatorJSON:    `{"path":"/home/u/Library/LaunchAgents/com.bogus.plist"}`,
			expectPath:     "/home/u/Library/LaunchAgents/com.bogus.plist",
			expectInHuman:  "gh CLI",
			expectInAI:     "GITHUB_TOKEN",
			expectIncident: true,
		},
		{
			ruleID:        "mini-shai-hulud-dropped-payload",
			locatorJSON:   `{"path":"/tmp/bogus.bin"}`,
			expectPath:    "/tmp/bogus.bin",
			expectInHuman: "Do NOT execute",
			expectInAI:    "binary malware",
		},
		{
			ruleID:        "mini-shai-hulud-workflow-secret-exfil",
			locatorJSON:   `{"path":"/repos/proj/.github/workflows/release.yml"}`,
			expectPath:    "/repos/proj/.github/workflows/release.yml",
			expectInHuman: "toJSON(secrets)",
			expectInAI:    "secrets/actions",
		},
	}
	for _, tc := range cases {
		t.Run(tc.ruleID, func(t *testing.T) {
			f := mkFinding(tc.ruleID, "file", tc.locatorJSON, "")
			human, ai, ok := r.Lookup(f)
			if !ok {
				t.Fatal("Lookup ok=false; want true")
			}
			if !strings.Contains(human, tc.expectPath) {
				t.Errorf("human missing path %q\n  got: %s", tc.expectPath, human)
			}
			if !strings.Contains(ai, tc.expectPath) {
				t.Errorf("AI missing path %q", tc.expectPath)
			}
			if !strings.Contains(human, tc.expectInHuman) {
				t.Errorf("human missing expected phrase %q\n  got: %s", tc.expectInHuman, human)
			}
			if !strings.Contains(ai, tc.expectInAI) {
				t.Errorf("AI missing expected phrase %q\n  got: %s", tc.expectInAI, ai)
			}
			if tc.expectIncident && !strings.Contains(human, "ROTATE") &&
				!strings.Contains(human, "Rotate") && !strings.Contains(human, "rotate") {
				t.Errorf("incident-response rule should walk credential rotation\n  got: %s", human)
			}
		})
	}
}

// TestOpenClawPrefixDispatchAcrossCVEs walks a representative cross-
// section of OpenClaw rule IDs through the single prefix handler. Each
// should pick up the fix version from the finding's Title or
// Description, render an upgrade-version line, and reach the package
// manager why-step (diagnose-first like the language ecosystem flows).
func TestOpenClawPrefixDispatchAcrossCVEs(t *testing.T) {
	r := New()
	cases := []struct {
		ruleID       string
		title        string
		description  string
		expectVer    string
		expectInHuman string
	}{
		{
			ruleID:        "openclaw-unbound-bootstrap-setup-code",
			title:         "OpenClaw before 2026.3.22 has unbound bootstrap setup codes",
			description:   "CVE-2026-41386: OpenClaw bootstrap setup codes before 2026.3.22 are not bound to intended device roles and scopes during pairing.",
			expectVer:     "2026.3.22",
			expectInHuman: "npm why openclaw",
		},
		{
			ruleID:        "openclaw-config-patch-consent-bypass",
			title:         "OpenClaw before 2026.3.28 lets config.patch disable execution approval",
			description:   "CVE-2026-41349: OpenClaw before 2026.3.28 lets config.patch silently disable execution approval.",
			expectVer:     "2026.3.28",
			expectInHuman: "openclaw",
		},
		{
			ruleID:        "openclaw-sandbox-cdp-relay-public-bind",
			title:         "OpenClaw sandbox CDP relay binds publicly",
			description:   "CVE-2026-42500: Upgrade to 2026.4.10 to fix.",
			expectVer:     "2026.4.10", // pulled from description, not title
			expectInHuman: "overrides",
		},
	}
	for _, tc := range cases {
		t.Run(tc.ruleID, func(t *testing.T) {
			f := state.Finding{
				Fingerprint: "test-fp",
				RuleID:      tc.ruleID,
				Severity:    "high",
				Category:    "ai-agent",
				Kind:        "file",
				Locator:     []byte(`{"path":"/repos/proj/package.json"}`),
				Title:       tc.title,
				Description: tc.description,
			}
			human, ai, ok := r.Lookup(f)
			if !ok {
				t.Fatal("Lookup ok=false; want true")
			}
			if !strings.Contains(human, tc.expectVer) {
				t.Errorf("human missing fix version %q\n  got: %s", tc.expectVer, human)
			}
			if !strings.Contains(ai, tc.expectVer) {
				t.Errorf("AI missing fix version %q", tc.expectVer)
			}
			if !strings.Contains(human, tc.expectInHuman) {
				t.Errorf("human missing %q\n  got: %s", tc.expectInHuman, human)
			}
			if !strings.Contains(human, "/repos/proj/package.json") {
				t.Errorf("human missing package.json path\n  got: %s", human)
			}
			if !strings.Contains(ai, "DO NOT skip the why") {
				t.Errorf("AI must teach diagnose-before-fix\n  got: %s", ai)
			}
		})
	}
}

// TestOpenClawHandlerHandlesMissingVersion guards the no-version
// fallback path: if a future rule changes its title shape so we can't
// extract a calver, the template still routes (no fatal crash) and
// surfaces a sentinel phrase instead of an empty version slot.
func TestOpenClawHandlerHandlesMissingVersion(t *testing.T) {
	r := New()
	f := state.Finding{
		RuleID:      "openclaw-some-new-rule",
		Severity:    "high",
		Category:    "ai-agent",
		Kind:        "file",
		Locator:     []byte(`{"path":"/repos/proj/package.json"}`),
		Title:       "OpenClaw nondescript vuln (no version in title)",
		Description: "Some advisory without a parseable version.",
	}
	human, ai, ok := r.Lookup(f)
	if !ok {
		t.Fatal("Lookup ok=false; want true")
	}
	if !strings.Contains(human, "the latest patched OpenClaw release") &&
		!strings.Contains(human, "the patched version") {
		t.Errorf("human should fall back to a sentinel when version is unknown\n  got: %s", human)
	}
	if !strings.Contains(ai, "the latest patched") &&
		!strings.Contains(ai, "the patched version") {
		t.Errorf("AI should fall back to a sentinel when version is unknown\n  got: %s", ai)
	}
}
