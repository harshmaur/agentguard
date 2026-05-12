package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestAgentPackageKnownVulnerable_FlagsPythonRequirements(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("praisonaiagents==1.6.8\n"))
	findings := (agentPackageKnownVulnerable{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1: %#v", len(findings), findings)
	}
	if findings[0].Line != 1 || findings[0].RuleID != "agent-package-known-vulnerable" {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestAgentPackageKnownVulnerable_AllowsFixedPythonVersion(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("praisonaiagents==1.6.9\n"))
	findings := (agentPackageKnownVulnerable{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0: %#v", len(findings), findings)
	}
}

func TestAgentPackageKnownVulnerable_FlagsNPMRangeWithVulnerableMinimum(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"dependencies":{"@anthropic-ai/sdk":"^0.90.0"}}`))
	findings := (agentPackageKnownVulnerable{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1: %#v", len(findings), findings)
	}
}

func TestAgentPackageKnownVulnerable_SkipsUnboundedMinimum(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"dependencies":{"@anthropic-ai/sdk":">=0.79.0"}}`))
	findings := (agentPackageKnownVulnerable{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0: %#v", len(findings), findings)
	}
}

func TestAgentPackageKnownVulnerable_FlagsExactMCPPackages(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version string
	}{
		{"xhs-mcp", "0.8.11"},
		{"directus-mcp", "1.0.0"},
		{"automagik-genie", "2.5.27"},
	} {
		doc := parse.Parse("package.json", []byte(`{"dependencies":{"`+tc.name+`":"`+tc.version+`"}}`))
		findings := (agentPackageKnownVulnerable{}).Apply(doc)
		if len(findings) != 1 {
			t.Fatalf("%s len(findings) = %d, want 1: %#v", tc.name, len(findings), findings)
		}
	}
}

func TestAgentPackageKnownVulnerable_DoesNotFlagUnsupportedEcosystemWithoutAdvisory(t *testing.T) {
	doc := parse.Parse("go.mod", []byte("module fixture\nrequire github.com/modelcontextprotocol/go-sdk v0.1.0\n"))
	findings := (agentPackageKnownVulnerable{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0 until a Go advisory is added: %#v", len(findings), findings)
	}
}

func TestDependencyVersionComparison(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"==1.6.8", true},
		{"^0.90.0", true},
		{">=0.79.0", false},
		{"git+https://example.com/pkg", false},
	}
	for _, tc := range cases {
		_, got := dependencyVersion(tc.raw)
		if got != tc.want {
			t.Fatalf("dependencyVersion(%q) ok = %v, want %v", tc.raw, got, tc.want)
		}
	}
}
