package builtin

import (
	"testing"

	"github.com/agentguard/agentguard/internal/parse"
)

// alpha.3 generalized rules: existing rule IDs (mcp-unpinned-npx,
// mcp-plaintext-api-key) keep working on .mcp.json (Cursor) but ALSO fire
// on Codex TOML and Windsurf JSON. New rule mcp-unauth-remote-url fires
// across all three.

func TestRule_MCPUnpinnedNPX_GeneralizedAcrossSources(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want bool
	}{
		{
			name: "Cursor .mcp.json with unpinned npx (existing v0.1 behavior)",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"foo":{"command":"npx","args":["@modelcontextprotocol/server-foo"]}}}`,
			want: true,
		},
		{
			name: "Codex TOML with unpinned @latest (Mac scan case)",
			path: "/test/.codex/config.toml",
			body: `[mcp_servers.playwright]` + "\n" + `command = "npx"` + "\n" + `args = ["@playwright/mcp@latest"]`,
			want: false, // @latest is technically pinned by our rule (any @ counts) - documented quirk
		},
		{
			name: "Codex TOML with truly unpinned package",
			path: "/test/.codex/config.toml",
			body: `[mcp_servers.foo]` + "\n" + `command = "npx"` + "\n" + `args = ["server-foo"]`,
			want: true,
		},
		{
			name: "Windsurf JSON with unpinned npx (Mac scan case: mastra/sequential-thinking)",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"mastra":{"command":"npx","args":["-y","@mastra/mcp-docs-server"]}}}`,
			want: true, // @mastra/mcp-docs-server with no @version
		},
		{
			name: "Windsurf JSON with pinned package",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"foo":{"command":"npx","args":["-y","pkg@2.0.0"]}}}`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse(c.path, []byte(c.body))
			if got := fired(doc, "mcp-unpinned-npx"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

func TestRule_MCPPlaintextAPIKey_GeneralizedAcrossSources(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want bool
	}{
		{
			name: "Cursor .mcp.json env (existing v0.1 behavior)",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"gh":{"command":"node","env":{"GITHUB_TOKEN":"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}}`,
			want: true,
		},
		{
			name: "Codex headers (subsumes deleted codex-mcp-plaintext-header-key from alpha.1)",
			path: "/test/.codex/config.toml",
			body: `[mcp_servers.context7.http_headers]` + "\n" + `CONTEXT7_API_KEY = "ctx7sk-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"`,
			want: true,
		},
		{
			name: "Windsurf headers (Mac scan case)",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"context7":{"serverUrl":"https://x.com","headers":{"CONTEXT7_API_KEY":"ctx7sk-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}}}}`,
			want: true,
		},
		{
			name: "Windsurf with no credentials",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"foo":{"url":"https://example.com"}}}`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse(c.path, []byte(c.body))
			if got := fired(doc, "mcp-plaintext-api-key"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

func TestRule_MCPUnauthRemoteURL(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want bool
	}{
		{
			name: "Cursor: GitLab URL with no headers (Mac scan case)",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"GitLab":{"url":"https://gitlab.com/api/v4/mcp"}}}`,
			want: true,
		},
		{
			name: "Codex: GitLab URL with no headers (Mac scan case)",
			path: "/test/.codex/config.toml",
			body: `[mcp_servers.GitLab]` + "\n" + `url = "https://gitlab.com/api/v4/mcp"`,
			want: true,
		},
		{
			name: "Windsurf: GitLab URL with no headers (Mac scan case)",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"GitLab":{"type":"http","url":"https://gitlab.com/api/v4/mcp"}}}`,
			want: true,
		},
		{
			name: "Codex: URL with auth header (safe)",
			path: "/test/.codex/config.toml",
			body: `[mcp_servers.x]` + "\n" + `url = "https://example.com"` + "\n" +
				`[mcp_servers.x.http_headers]` + "\n" + `Authorization = "Bearer aaaaaaaaaaaaaaaaaaaa"`,
			want: false,
		},
		{
			name: "Windsurf: URL with X-API-Key (safe)",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"x":{"url":"https://example.com","headers":{"X-API-Key":"aaaaaaaaaaaaaaaaaaaa"}}}}`,
			want: false,
		},
		{
			name: "stdio server has no URL (rule does not apply)",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"local":{"command":"node","args":["server.js"]}}}`,
			want: false,
		},
		{
			name: "localhost URL (different threat model — skip)",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"dev":{"url":"http://localhost:3000/mcp"}}}`,
			want: false,
		},
		{
			name: "127.0.0.1 URL (skip)",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"dev":{"url":"http://127.0.0.1:8080/mcp"}}}`,
			want: false,
		},
		{
			name: "credential-name-suffix header counts as auth (CONTEXT7_API_KEY)",
			path: "/test/.codex/config.toml",
			body: `[mcp_servers.x]` + "\n" + `url = "https://example.com"` + "\n" +
				`[mcp_servers.x.http_headers]` + "\n" + `CONTEXT7_API_KEY = "ctx7sk-aaa"`,
			want: false, // header has API_KEY suffix → counts as auth-configured
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse(c.path, []byte(c.body))
			if got := fired(doc, "mcp-unauth-remote-url"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

// End-to-end: alpha.3 generalized rules fire on Windsurf, Codex, AND Cursor
// from a single config-corpus traversal. This is the architectural validation
// of the normalized model: same rules, different sources.
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

	// Each rule should fire across both docs:
	count := map[string]int{}
	for _, id := range applyRule(codexDoc) {
		count[id]++
	}
	for _, id := range applyRule(windsurfDoc) {
		count[id]++
	}

	// mcp-plaintext-api-key: 1 in Codex (CONTEXT7) + 1 in Windsurf (CONTEXT7) = 2
	if count["mcp-plaintext-api-key"] < 2 {
		t.Errorf("mcp-plaintext-api-key fires=%d, want >=2 (Codex + Windsurf)", count["mcp-plaintext-api-key"])
	}
	// mcp-unauth-remote-url: 1 in Codex (GitLab) + 1 in Windsurf (GitLab) = 2
	// (context7 has API_KEY header, counts as authed; mastra is stdio, no URL)
	if count["mcp-unauth-remote-url"] < 2 {
		t.Errorf("mcp-unauth-remote-url fires=%d, want >=2", count["mcp-unauth-remote-url"])
	}
	// mcp-unpinned-npx: 0 in Codex (no npx servers in this fixture) + 1 in Windsurf (mastra)
	if count["mcp-unpinned-npx"] < 1 {
		t.Errorf("mcp-unpinned-npx fires=%d, want >=1", count["mcp-unpinned-npx"])
	}
}
