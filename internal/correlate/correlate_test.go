package correlate

import (
	"strings"
	"testing"

	"github.com/agentguard/agentguard/internal/finding"
	"github.com/agentguard/agentguard/internal/parse"
)

// helper to build a finding with given rule + path
func mkF(ruleID, path, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:   ruleID,
		Severity: finding.SeverityCritical,
		Taxonomy: finding.TaxEnforced,
		Title:    "test",
		Path:     path,
		Match:    match,
	})
}

func TestChain_RepoCloneHookRCE(t *testing.T) {
	findings := []finding.Finding{
		mkF("claude-hook-shell-rce", "/repo/proj/.claude/settings.json", "any-buddy apply"),
	}
	chains := Run(findings, nil)
	if len(chains) == 0 {
		t.Fatal("expected at least one chain")
	}
	ids := map[string]bool{}
	for _, c := range chains {
		ids[c.ID] = true
	}
	if !ids["repo-clone-hook-rce"] {
		t.Errorf("repo-clone-hook-rce did not fire; got: %v", ids)
	}
}

func TestChain_RepoCloneHookRCE_ContainsCommandMatch(t *testing.T) {
	findings := []finding.Finding{
		mkF("claude-hook-shell-rce", "/repo/proj/.claude/settings.json", "any-buddy apply --silent"),
	}
	chains := Run(findings, nil)
	for _, c := range chains {
		if c.ID == "repo-clone-hook-rce" {
			if !strings.Contains(c.Narrative, "any-buddy") {
				t.Errorf("narrative missing command match; got: %s", c.Narrative)
			}
			return
		}
	}
	t.Fatal("repo-clone-hook-rce did not fire")
}

func TestChain_AgentReadsProdSecrets_RequiresBoth(t *testing.T) {
	// Capability alone — should NOT fire (no secrets reachable).
	findingsCapOnly := []finding.Finding{
		mkF("claude-skip-permission-prompt", "/u/.claude/settings.json", "skipDangerousModePermissionPrompt"),
	}
	chains := Run(findingsCapOnly, nil)
	for _, c := range chains {
		if c.ID == "agent-reads-prod-secrets" {
			t.Errorf("chain fired with capability only (no secrets), should not fire")
		}
	}

	// Secret alone — should NOT fire (no capability).
	findingsSecOnly := []finding.Finding{
		mkF("shellrc-secret-export", "/u/.zprofile", "GH_TOKEN=ghp_x"),
	}
	chains = Run(findingsSecOnly, nil)
	for _, c := range chains {
		if c.ID == "agent-reads-prod-secrets" {
			t.Errorf("chain fired with secret only (no capability), should not fire")
		}
	}

	// Both → should fire.
	findingsBoth := []finding.Finding{
		mkF("claude-skip-permission-prompt", "/u/.claude/settings.json", "skipDangerousModePermissionPrompt"),
		mkF("shellrc-secret-export", "/u/.zprofile", "GH_TOKEN=ghp_x"),
	}
	chains = Run(findingsBoth, nil)
	found := false
	for _, c := range chains {
		if c.ID == "agent-reads-prod-secrets" {
			found = true
		}
	}
	if !found {
		t.Errorf("chain should fire with both capability + secret; got chains: %d", len(chains))
	}
}

func TestChain_TrustedHomePlusPlaintextKey(t *testing.T) {
	findings := []finding.Finding{
		mkF("codex-trust-home-or-broad", "/u/.codex/config.toml", `[projects."/Users/h"] trust_level = "trusted"`),
		mkF("mcp-plaintext-api-key", "/u/.codex/config.toml", "CONTEXT7_API_KEY=ctx7sk-..."),
	}
	chains := Run(findings, nil)
	found := false
	for _, c := range chains {
		if c.ID == "codex-trusted-home-plaintext-key" {
			found = true
			if c.Severity != finding.SeverityCritical {
				t.Errorf("severity = %d, want Critical", c.Severity)
			}
			if !strings.Contains(c.Narrative, "trusted") {
				t.Errorf("narrative missing 'trusted'; got: %s", c.Narrative)
			}
		}
	}
	if !found {
		t.Errorf("codex-trusted-home-plaintext-key chain did not fire")
	}
}

func TestChain_TrustedHomePlusPlaintextKey_OnlyFiresWhenBothInCodex(t *testing.T) {
	// Plaintext key NOT in Codex (in .mcp.json) — should not fire.
	findings := []finding.Finding{
		mkF("codex-trust-home-or-broad", "/u/.codex/config.toml", `trust_level = "trusted"`),
		mkF("mcp-plaintext-api-key", "/u/.cursor/mcp.json", "TOKEN=ghp_x"),
	}
	chains := Run(findings, nil)
	for _, c := range chains {
		if c.ID == "codex-trusted-home-plaintext-key" {
			t.Errorf("chain fired with plaintext key in Cursor, not Codex")
		}
	}
}

func TestChain_PluginBundledMCPWithoutAuth(t *testing.T) {
	// mcp-unauth-remote-url under a plugin path → should fire.
	findings := []finding.Finding{
		mkF("mcp-unauth-remote-url", "/u/.claude/plugins/cache/vercel-vercel-plugin/0.24.0/.mcp.json", "https://mcp.vercel.com"),
		mkF("claude-third-party-plugin-enabled", "/u/.claude/settings.json", "vercel-plugin@vercel-vercel-plugin"),
	}
	chains := Run(findings, nil)
	found := false
	for _, c := range chains {
		if c.ID == "plugin-bundled-mcp-no-auth" {
			found = true
		}
	}
	if !found {
		t.Errorf("plugin-bundled-mcp-no-auth chain did not fire on plugin-cache path")
	}

	// mcp-unauth-remote-url NOT under a plugin path → should NOT fire (other chains may still).
	findings = []finding.Finding{
		mkF("mcp-unauth-remote-url", "/u/.cursor/mcp.json", "https://gitlab.com"),
	}
	chains = Run(findings, nil)
	for _, c := range chains {
		if c.ID == "plugin-bundled-mcp-no-auth" {
			t.Errorf("chain fired without plugin path")
		}
	}
}

func TestChain_SameSecretAcrossHarnesses(t *testing.T) {
	// Same key NAME across two different harness paths → fire.
	findings := []finding.Finding{
		mkF("mcp-plaintext-api-key", "/u/.codex/config.toml", "CONTEXT7_API_KEY=ctx7sk-aaaa"),
		mkF("mcp-plaintext-api-key", "/u/.codeium/windsurf/mcp_config.json", "CONTEXT7_API_KEY=ctx7sk-bbbb"),
	}
	chains := Run(findings, nil)
	found := false
	for _, c := range chains {
		if c.ID == "same-secret-across-harnesses" {
			found = true
			if !strings.Contains(c.Title, "CONTEXT7_API_KEY") {
				t.Errorf("title missing key name; got: %s", c.Title)
			}
		}
	}
	if !found {
		t.Errorf("same-secret-across-harnesses did not fire across two harnesses")
	}

	// Same key NAME but only one harness → no fire.
	findings = []finding.Finding{
		mkF("mcp-plaintext-api-key", "/u/.codex/config.toml", "CONTEXT7_API_KEY=ctx7sk-aaaa"),
	}
	chains = Run(findings, nil)
	for _, c := range chains {
		if c.ID == "same-secret-across-harnesses" {
			t.Errorf("chain fired with single harness")
		}
	}
}

// End-to-end: simulate the verbatim Mac scan finding set and verify the
// expected chains all fire.
func TestRun_RealMacFindingsProduceExpectedChains(t *testing.T) {
	findings := []finding.Finding{
		// alpha.1 + alpha.2 fires on the actual Mac:
		mkF("claude-hook-shell-rce", "/Users/h/.claude/settings.json", "any-buddy apply --silent"),
		mkF("claude-skip-permission-prompt", "/Users/h/.claude/settings.json", "skipDangerousModePermissionPrompt"),
		mkF("codex-trust-home-or-broad", "/Users/h/.codex/config.toml", `[projects."/Users/h"]`),
		mkF("mcp-plaintext-api-key", "/Users/h/.codex/config.toml", "CONTEXT7_API_KEY=ctx7sk-aaaa"),
		mkF("mcp-plaintext-api-key", "/Users/h/.codeium/windsurf/mcp_config.json", "CONTEXT7_API_KEY=ctx7sk-bbbb"),
		mkF("claude-third-party-plugin-enabled", "/Users/h/.claude/settings.json", "vercel-plugin@vercel-vercel-plugin"),
		mkF("mcp-unauth-remote-url", "/Users/h/.claude/plugins/cache/vercel-vercel-plugin/0.24.0/.mcp.json", "https://mcp.vercel.com"),
		mkF("mcp-unauth-remote-url", "/Users/h/.cursor/mcp.json", "https://gitlab.com/api/v4/mcp"),
	}
	chains := Run(findings, nil)
	want := map[string]bool{
		"repo-clone-hook-rce":               false,
		"agent-reads-prod-secrets":          false,
		"codex-trusted-home-plaintext-key":  false,
		"plugin-bundled-mcp-no-auth":        false,
		"same-secret-across-harnesses":      false,
	}
	for _, c := range chains {
		if _, ok := want[c.ID]; ok {
			want[c.ID] = true
		}
	}
	missing := []string{}
	for id, ok := range want {
		if !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		titles := []string{}
		for _, c := range chains {
			titles = append(titles, c.ID)
		}
		t.Errorf("expected chains did not fire: %v (got %d chains: %v)", missing, len(chains), titles)
	}
}

// silence unused import in some build configs
var _ = parse.FormatMCPConfig
