package builtin

import (
	"strings"
	"testing"

	"github.com/harshmaur/agentguard/internal/parse"
	"github.com/harshmaur/agentguard/internal/rules"
)

// --- mcp-unpinned-npx ------------------------------------------------------

func TestRule_MCPUnpinnedNPX(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		wantFires int
	}{
		{
			name:      "unpinned npx triggers",
			raw:       `{"mcpServers":{"foo":{"command":"npx","args":["@modelcontextprotocol/server-foo"]}}}`,
			wantFires: 1,
		},
		{
			name:      "pinned @version does not trigger",
			raw:       `{"mcpServers":{"foo":{"command":"npx","args":["@modelcontextprotocol/server-foo@1.2.3"]}}}`,
			wantFires: 0,
		},
		{
			name:      "non-npx command does not trigger",
			raw:       `{"mcpServers":{"foo":{"command":"node","args":["server.js"]}}}`,
			wantFires: 0,
		},
		{
			name:      "npx with -y flag and pinned version OK",
			raw:       `{"mcpServers":{"foo":{"command":"npx","args":["-y","my-pkg@2.0.0"]}}}`,
			wantFires: 0,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			doc := parse.Parse("/test/.mcp.json", []byte(tt.raw))
			fires := 0
			for _, id := range applyRule(doc) {
				if id == "mcp-unpinned-npx" {
					fires++
				}
			}
			if fires != tt.wantFires {
				t.Errorf("got %d fires, want %d", fires, tt.wantFires)
			}
		})
	}
}

// Generalized: same rule fires across .mcp.json, Codex TOML, Windsurf JSON
// via the normalized MCP model.
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
			name: "Codex TOML with @latest (counts as pinned per existing rule semantics)",
			path: "/test/.codex/config.toml",
			body: `[mcp_servers.playwright]` + "\n" + `command = "npx"` + "\n" + `args = ["@playwright/mcp@latest"]`,
			want: false,
		},
		{
			name: "Codex TOML with truly unpinned package",
			path: "/test/.codex/config.toml",
			body: `[mcp_servers.foo]` + "\n" + `command = "npx"` + "\n" + `args = ["server-foo"]`,
			want: true,
		},
		{
			name: "Windsurf JSON with unpinned npx (Mac scan: mastra/sequential-thinking)",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"mastra":{"command":"npx","args":["-y","@mastra/mcp-docs-server"]}}}`,
			want: true,
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

// --- mcp-prod-secret-env --------------------------------------------------

func TestRule_MCPProdSecretEnv(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		wantFires int
	}{
		{
			name:      "PROD_ env var fires",
			raw:       `{"mcpServers":{"foo":{"command":"x","env":{"PROD_DB_URL":"postgres://..."}}}}`,
			wantFires: 1,
		},
		{
			name:      "STRIPE_LIVE_ env var fires",
			raw:       `{"mcpServers":{"foo":{"command":"x","env":{"STRIPE_LIVE_KEY":"sk_live_xxx"}}}}`,
			wantFires: 1,
		},
		{
			name:      "staging env does not fire",
			raw:       `{"mcpServers":{"foo":{"command":"x","env":{"STAGING_DB_URL":"postgres://..."}}}}`,
			wantFires: 0,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			doc := parse.Parse("/test/.mcp.json", []byte(tt.raw))
			fires := 0
			for _, id := range applyRule(doc) {
				if id == "mcp-prod-secret-env" {
					fires++
				}
			}
			if fires != tt.wantFires {
				t.Errorf("got %d fires, want %d", fires, tt.wantFires)
			}
		})
	}
}

// --- mcp-plaintext-api-key (existing) -------------------------------------

func TestRule_MCPPlaintextAPIKey(t *testing.T) {
	doc := parse.Parse("/test/.mcp.json", []byte(`{"mcpServers":{"github":{"command":"x","env":{"GITHUB_TOKEN":"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}}`))
	fires := 0
	var fr []string
	for _, id := range applyRule(doc) {
		if id == "mcp-plaintext-api-key" {
			fires++
		}
		fr = append(fr, id)
	}
	if fires == 0 {
		t.Errorf("plaintext github token should fire; rules fired: %v", fr)
	}

	// Verify redaction in finding output.
	for _, r := range rules.All() {
		if r.ID() != "mcp-plaintext-api-key" {
			continue
		}
		findings := r.Apply(doc)
		for _, f := range findings {
			if strings.Contains(f.Match, "ghp_aaa") {
				t.Errorf("finding match leaked secret: %q", f.Match)
			}
		}
	}
}

// alpha.1 → alpha.3 transition: codex-mcp-plaintext-header-key was removed,
// the generalized mcp-plaintext-api-key now covers Codex headers too.
func TestRule_MCPPlaintextAPIKey_CodexHeaders(t *testing.T) {
	cases := []struct {
		name string
		toml string
		want bool
	}{
		{
			name: "ctx7sk- prefix in header (Mac scan case)",
			toml: `[mcp_servers.context7]` + "\n" +
				`url = "https://mcp.context7.com/mcp"` + "\n" +
				`[mcp_servers.context7.http_headers]` + "\n" +
				`CONTEXT7_API_KEY = "ctx7sk-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"`,
			want: true,
		},
		{
			name: "github token in header (well-known prefix)",
			toml: `[mcp_servers.gh.http_headers]` + "\n" +
				`Authorization = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,
			want: true,
		},
		{
			name: "no headers at all",
			toml: `[mcp_servers.simple]` + "\n" + `url = "https://example.com"`,
			want: false,
		},
		{
			name: "header value too short to be a credential",
			toml: `[mcp_servers.s.http_headers]` + "\n" + `X-Foo = "bar"`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse("/u/.codex/config.toml", []byte(c.toml))
			if got := fired(doc, "mcp-plaintext-api-key"); got != c.want {
				t.Errorf("fired = %v, want %v (full apply: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

// alpha.3 generalization: same rule fires on Codex + Windsurf headers.
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
			name: "Codex headers (subsumes deleted codex-mcp-plaintext-header-key)",
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

// --- mcp-unauth-remote-url -------------------------------------------------

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
			want: false,
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
