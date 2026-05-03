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

func TestOpenClawConfigPatchConsentBypass_FlagsVulnerablePackage(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"name":"openclaw","version":"2026.3.27"}`))
	findings := (openclawConfigPatchConsentBypass{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "openclaw-config-patch-consent-bypass" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}
}

func TestOpenClawConfigPatchConsentBypass_FlagsVulnerableDependency(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"devDependencies":{"openclaw":"~2026.3.24"}}`))
	findings := (openclawConfigPatchConsentBypass{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestOpenClawConfigPatchConsentBypass_AllowsFixedVersion(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"name":"openclaw","version":"2026.3.28","dependencies":{"openclaw":"2026.4.1"}}`))
	findings := (openclawConfigPatchConsentBypass{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}

func TestOpenClawWebsocketUpgradeExhaustion_FlagsVulnerablePackage(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"name":"openclaw","version":"2026.3.27"}`))
	findings := (openclawWebsocketUpgradeExhaustion{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "openclaw-websocket-upgrade-exhaustion" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}
}

func TestOpenClawWebsocketUpgradeExhaustion_FlagsVulnerableDependency(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"dependencies":{"openclaw":"^2026.3.24"}}`))
	findings := (openclawWebsocketUpgradeExhaustion{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestOpenClawWebsocketUpgradeExhaustion_AllowsFixedVersion(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"name":"openclaw","version":"2026.3.28","dependencies":{"openclaw":"2026.4.1"}}`))
	findings := (openclawWebsocketUpgradeExhaustion{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}

func TestOpenClawNodePairApproveScopeBypass_FlagsVulnerablePackage(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"name":"openclaw","version":"2026.4.7"}`))
	findings := (openclawNodePairApproveScopeBypass{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "openclaw-node-pair-approve-scope-bypass" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}
}

func TestOpenClawNodePairApproveScopeBypass_FlagsVulnerableDependency(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"optionalDependencies":{"openclaw":"^2026.4.1"}}`))
	findings := (openclawNodePairApproveScopeBypass{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestOpenClawNodePairApproveScopeBypass_AllowsFixedVersion(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"name":"openclaw","version":"2026.4.8","dependencies":{"openclaw":"2026.4.9"}}`))
	findings := (openclawNodePairApproveScopeBypass{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}

func TestOpenClawPluginAuthOperatorWriteBypass_FlagsVulnerablePackage(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"name":"openclaw","version":"2026.3.30"}`))
	findings := (openclawPluginAuthOperatorWriteBypass{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "openclaw-plugin-auth-operator-write-bypass" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}
}

func TestOpenClawPluginAuthOperatorWriteBypass_FlagsVulnerableDependency(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"peerDependencies":{"openclaw":"^2026.3.24"}}`))
	findings := (openclawPluginAuthOperatorWriteBypass{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestOpenClawPluginAuthOperatorWriteBypass_AllowsFixedVersion(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"name":"openclaw","version":"2026.3.31","dependencies":{"openclaw":"2026.4.1"}}`))
	findings := (openclawPluginAuthOperatorWriteBypass{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}

func TestOpenClawTeamsWebhookPreauthBodyDos_FlagsVulnerablePackage(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"name":"openclaw","version":"2026.3.30"}`))
	findings := (openclawTeamsWebhookPreauthBodyDos{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "openclaw-teams-webhook-preauth-body-dos" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}
}

func TestOpenClawTeamsWebhookPreauthBodyDos_FlagsVulnerableDependency(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"dependencies":{"openclaw":"^2026.3.24"}}`))
	findings := (openclawTeamsWebhookPreauthBodyDos{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestOpenClawTeamsWebhookPreauthBodyDos_AllowsFixedVersion(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"name":"openclaw","version":"2026.3.31","dependencies":{"openclaw":"2026.4.1"}}`))
	findings := (openclawTeamsWebhookPreauthBodyDos{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}
