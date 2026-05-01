package finding

import "testing"

func TestLessBreaksSameLocationTiesByFindingContent(t *testing.T) {
	deploy := Finding{
		RuleID:      "gha-secrets-in-agent-step",
		Severity:    SeverityHigh,
		Path:        ".github/workflows/agent.yml",
		Line:        0,
		Title:       "Secret passed to step that invokes an AI coding agent",
		Description: "Step exposes DEPLOY_TOKEN via env.",
		Match:       "DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}",
	}
	anthropic := Finding{
		RuleID:      "gha-secrets-in-agent-step",
		Severity:    SeverityHigh,
		Path:        ".github/workflows/agent.yml",
		Line:        0,
		Title:       "Secret passed to step that invokes an AI coding agent",
		Description: "Step exposes ANTHROPIC_API_KEY via env.",
		Match:       "ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}",
	}

	if !Less(anthropic, deploy) {
		t.Fatalf("expected Less to order same-location duplicate findings by content")
	}
	if Less(deploy, anthropic) {
		t.Fatalf("Less must be antisymmetric for same-location duplicate findings")
	}
}
