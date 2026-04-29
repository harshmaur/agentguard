package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestOpenClawUnboundBootstrapSetupCode_FlagsVulnerablePackage(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"name":"openclaw","version":"2026.3.21"}`))
	findings := (openclawUnboundBootstrapSetupCode{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "openclaw-unbound-bootstrap-setup-code" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}
}

func TestOpenClawUnboundBootstrapSetupCode_FlagsVulnerableDependency(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"dependencies":{"openclaw":"^2026.3.1"}}`))
	findings := (openclawUnboundBootstrapSetupCode{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestOpenClawUnboundBootstrapSetupCode_AllowsFixedVersion(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"name":"openclaw","version":"2026.3.22","dependencies":{"openclaw":"2026.4.1"}}`))
	findings := (openclawUnboundBootstrapSetupCode{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}
