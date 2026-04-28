package parse

import (
	"strings"
	"testing"
)

// Real-world Codex config.toml shape, drawn from a live Mac dev-machine.
// Captures every TOML construct the v0.2 ruleset cares about: top-level
// approval/sandbox flags, [projects."<path>"] tables with trust_level, and
// [mcp_servers.<name>] with optional [mcp_servers.<name>.http_headers].
const codexConfigRealWorld = `
model = "gpt-5.4"
model_reasoning_effort = "high"
approval_policy = "never"
sandbox_mode = "danger-full-access"

[features]
unified_exec = true
web_search = true

[projects."/Users/harshmaur/projects"]
trust_level = "trusted"

[projects."/Users/harshmaur"]
trust_level = "trusted"

[projects."/Users/harshmaur/projects/tinker/reddit-scraper-pro"]
trust_level = "trusted"

[mcp_servers.playwright]
args = ["@playwright/mcp@latest"]
command = "npx"

[mcp_servers.context7]
enabled = true
url = "https://mcp.context7.com/mcp"

[mcp_servers.context7.http_headers]
CONTEXT7_API_KEY = "ctx7sk-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

[mcp_servers.GitLab]
url = "https://gitlab.com/api/v4/mcp"
`

func TestDetectFormat_CodexConfig(t *testing.T) {
	cases := []struct {
		path string
		want Format
	}{
		{"/home/u/.codex/config.toml", FormatCodexConfig},
		{"/Users/h/.codex/config.toml", FormatCodexConfig},
		{"/repo/.codex/config.toml", FormatCodexConfig},
		{"/repo/random/config.toml", FormatUnknown},
		{"/repo/.codex/sessions/foo.jsonl", FormatUnknown}, // wrong basename
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			if got := DetectFormat(c.path); got != c.want {
				t.Errorf("DetectFormat(%q) = %q, want %q", c.path, got, c.want)
			}
		})
	}
}

func TestParseCodexConfig_RealWorld(t *testing.T) {
	doc := Parse("/home/u/.codex/config.toml", []byte(codexConfigRealWorld))
	if doc.Format != FormatCodexConfig {
		t.Fatalf("format = %q", doc.Format)
	}
	if doc.ParseError != nil {
		t.Fatalf("parse error: %v", doc.ParseError)
	}
	c := doc.CodexConfig
	if c == nil {
		t.Fatal("CodexConfig nil")
	}

	// Top-level scalars.
	if c.ApprovalPolicy != "never" {
		t.Errorf("ApprovalPolicy = %q, want never", c.ApprovalPolicy)
	}
	if c.SandboxMode != "danger-full-access" {
		t.Errorf("SandboxMode = %q, want danger-full-access", c.SandboxMode)
	}

	// Trust map: 3 entries, including one for $HOME.
	if len(c.TrustedProjects) != 3 {
		t.Errorf("TrustedProjects count = %d, want 3 (got %v)", len(c.TrustedProjects), c.TrustedProjects)
	}
	if c.TrustedProjects["/Users/harshmaur"] != "trusted" {
		t.Errorf("$HOME trust_level = %q, want trusted", c.TrustedProjects["/Users/harshmaur"])
	}

	// MCP servers: 3 named (playwright, context7, GitLab).
	if len(c.MCPServers) != 3 {
		t.Fatalf("MCPServers count = %d, want 3", len(c.MCPServers))
	}

	// Find each by name and verify shape.
	byName := map[string]CodexMCPServer{}
	for _, s := range c.MCPServers {
		byName[s.Name] = s
	}
	if pw, ok := byName["playwright"]; !ok {
		t.Error("missing playwright server")
	} else {
		if pw.Command != "npx" {
			t.Errorf("playwright command = %q", pw.Command)
		}
		if len(pw.Args) != 1 || pw.Args[0] != "@playwright/mcp@latest" {
			t.Errorf("playwright args = %v", pw.Args)
		}
	}
	if c7, ok := byName["context7"]; !ok {
		t.Error("missing context7 server")
	} else {
		if c7.URL != "https://mcp.context7.com/mcp" {
			t.Errorf("context7 URL = %q", c7.URL)
		}
		if c7.HTTPHeaders["CONTEXT7_API_KEY"] == "" {
			t.Error("context7 plaintext header key not captured")
		}
		if !strings.HasPrefix(c7.HTTPHeaders["CONTEXT7_API_KEY"], "ctx7sk-") {
			t.Errorf("context7 key value = %q", c7.HTTPHeaders["CONTEXT7_API_KEY"])
		}
		if c7.Enabled == nil || !*c7.Enabled {
			t.Errorf("context7 enabled = %v", c7.Enabled)
		}
	}
	if gl, ok := byName["GitLab"]; !ok {
		t.Error("missing GitLab server")
	} else {
		if gl.URL == "" {
			t.Error("GitLab URL empty")
		}
		if len(gl.HTTPHeaders) != 0 {
			t.Errorf("GitLab unexpected headers = %v", gl.HTTPHeaders)
		}
	}
}

func TestParseCodexConfig_Empty(t *testing.T) {
	// An empty config is valid TOML; should produce a non-nil but empty CodexConfig.
	doc := Parse("/home/u/.codex/config.toml", []byte(""))
	if doc.ParseError != nil {
		t.Fatalf("parse error on empty file: %v", doc.ParseError)
	}
	if doc.CodexConfig == nil {
		t.Fatal("CodexConfig nil for empty input")
	}
	if len(doc.CodexConfig.TrustedProjects) != 0 || len(doc.CodexConfig.MCPServers) != 0 {
		t.Errorf("empty config should have no entries, got %+v", doc.CodexConfig)
	}
}

func TestParseCodexConfig_Malformed(t *testing.T) {
	doc := Parse("/home/u/.codex/config.toml", []byte("this is not = [toml at all]]"))
	if doc.ParseError == nil {
		t.Error("expected ParseError on malformed TOML")
	}
}
