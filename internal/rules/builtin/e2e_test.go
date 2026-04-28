package builtin

import (
	"strings"
	"testing"

	"github.com/harshmaur/agentguard/internal/parse"
)

// End-to-end tests that cross multiple harnesses in a single fixture.
// These are the v0.2 design's acceptance tests — the rules in question
// must fire on the verbatim contents of a real Mac dev machine.

// TestV02_RealMacConfigEndToEnd asserts all 5 alpha.1 rules fire on the
// real Mac configs that v0.1 missed.
func TestV02_RealMacConfigEndToEnd(t *testing.T) {
	codexTOML := `
model = "gpt-5.4"
approval_policy = "never"

[projects."/Users/harshmaur"]
trust_level = "trusted"

[mcp_servers.context7]
url = "https://mcp.context7.com/mcp"

[mcp_servers.context7.http_headers]
CONTEXT7_API_KEY = "ctx7sk-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
`
	claudeJSON := `{
  "hooks": {"SessionStart": [{"hooks":[{"type":"command","command":"any-buddy apply --silent"}]}]},
  "skipDangerousModePermissionPrompt": true,
  "statusLine": {"type":"command","command":"input=$(cat); echo \"$input\" | jq -r '.model.display_name' | tr -d '\\n'"}
}`

	codexDoc := parse.Parse("/u/.codex/config.toml", []byte(codexTOML))
	claudeDoc := parse.Parse("/u/.claude/settings.json", []byte(claudeJSON))

	want := map[string]bool{
		"codex-approval-disabled":       false,
		"codex-trust-home-or-broad":     false,
		"mcp-plaintext-api-key":         false, // alpha.3 generalized from codex-mcp-plaintext-header-key
		"claude-hook-shell-rce":         false,
		"claude-skip-permission-prompt": false,
	}
	for _, id := range applyRule(codexDoc) {
		if _, ok := want[id]; ok {
			want[id] = true
		}
	}
	for _, id := range applyRule(claudeDoc) {
		if _, ok := want[id]; ok {
			want[id] = true
		}
	}

	missing := []string{}
	for id, fired := range want {
		if !fired {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		t.Errorf("v0.2 acceptance test failed — these rules did not fire on the real Mac configs: %s", strings.Join(missing, ", "))
	}
}

// TestV02Alpha2_RealMacConfigEndToEnd: alpha.2's third-party-plugin rule
// fires twice (enabled list + sideloaded marketplace) on the Mac.
func TestV02Alpha2_RealMacConfigEndToEnd(t *testing.T) {
	macSettings := `{
  "permissions": {
    "allow": [
      "Bash(bun add:*)"
    ]
  },
  "enabledPlugins": {
    "harshmaur-typescript-review@harshmaur-marketplace": true,
    "example-skills@anthropic-agent-skills": true,
    "playwright-cli@playwright-cli": true,
    "coderabbit@coderabbit": true,
    "telegram@claude-plugins-official": true,
    "vercel-plugin@vercel-vercel-plugin": true
  },
  "extraKnownMarketplaces": {
    "vercel-vercel-plugin": {
      "source": {
        "source": "directory",
        "path": "/Users/harshmaur/.cache/plugins/github.com-vercel-vercel-plugin"
      }
    }
  }
}`
	doc := parse.Parse("/u/.claude/settings.json", []byte(macSettings))
	want := map[string]int{
		"claude-third-party-plugin-enabled": 2,
	}
	got := map[string]int{}
	for _, id := range applyRule(doc) {
		got[id]++
	}
	for id, n := range want {
		if got[id] != n {
			t.Errorf("rule %s: fired %d times, want %d (full apply: %v)", id, got[id], n, applyRule(doc))
		}
	}
	// Bash(bun add:*) is a safe-verb arg-wildcard; rule must not fire.
	if got["claude-bash-allowlist-too-broad"] != 0 {
		t.Errorf("bash-allowlist rule should not fire on bun add:*, got %d", got["claude-bash-allowlist-too-broad"])
	}
}

// TestV02Alpha3_GeneralizedRulesAcrossThreeHarnesses: alpha.3 normalized
// MCP model — a single rule should fire across Codex + Windsurf when the
// same risk shape is present in different config files.
func TestV02Alpha3_GeneralizedRulesAcrossThreeHarnesses(t *testing.T) {
	codexTOML := `
[mcp_servers.GitLab]
url = "https://gitlab.com/api/v4/mcp"

[mcp_servers.context7]
url = "https://mcp.context7.com/mcp"

[mcp_servers.context7.http_headers]
CONTEXT7_API_KEY = "ctx7sk-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
`
	windsurfJSON := `{"mcpServers":{
		"GitLab":{"type":"http","url":"https://gitlab.com/api/v4/mcp"},
		"context7":{"serverUrl":"https://mcp.context7.com/mcp","headers":{"CONTEXT7_API_KEY":"ctx7sk-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}},
		"mastra":{"command":"npx","args":["-y","@mastra/mcp-docs-server"]}
	}}`

	codexDoc := parse.Parse("/u/.codex/config.toml", []byte(codexTOML))
	windsurfDoc := parse.Parse("/u/.codeium/windsurf/mcp_config.json", []byte(windsurfJSON))

	count := map[string]int{}
	for _, id := range applyRule(codexDoc) {
		count[id]++
	}
	for _, id := range applyRule(windsurfDoc) {
		count[id]++
	}

	if count["mcp-plaintext-api-key"] < 2 {
		t.Errorf("mcp-plaintext-api-key fires=%d, want >=2 (Codex + Windsurf)", count["mcp-plaintext-api-key"])
	}
	if count["mcp-unauth-remote-url"] < 2 {
		t.Errorf("mcp-unauth-remote-url fires=%d, want >=2", count["mcp-unauth-remote-url"])
	}
	if count["mcp-unpinned-npx"] < 1 {
		t.Errorf("mcp-unpinned-npx fires=%d, want >=1", count["mcp-unpinned-npx"])
	}
}
