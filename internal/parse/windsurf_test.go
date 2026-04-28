package parse

import (
	"testing"
)

const windsurfMCPRealWorld = `{
  "mcpServers": {
    "GitLab": {
      "type": "http",
      "url": "https://gitlab.com/api/v4/mcp"
    },
    "context7": {
      "disabled": false,
      "headers": {
        "CONTEXT7_API_KEY": "ctx7sk-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
      },
      "serverUrl": "https://mcp.context7.com/mcp"
    },
    "mastra": {
      "args": ["-y", "@mastra/mcp-docs-server"],
      "command": "npx",
      "disabled": true
    },
    "mcp-playwright": {
      "args": ["-y", "@playwright/mcp@latest"],
      "command": "npx",
      "disabled": true,
      "env": {}
    },
    "sequential-thinking": {
      "args": ["-y", "@modelcontextprotocol/server-sequential-thinking"],
      "command": "npx",
      "disabled": true,
      "env": {}
    }
  }
}`

func TestDetectFormat_Windsurf(t *testing.T) {
	cases := []struct {
		path string
		want Format
	}{
		{"/Users/h/.codeium/windsurf/mcp_config.json", FormatWindsurfMCP},
		{"/home/u/.codeium/windsurf/mcp_config.json", FormatWindsurfMCP},
		{"/Users/h/.codeium/mcp_config.json", FormatUnknown}, // not under /windsurf/
		{"/.codeium/windsurf/foo.json", FormatUnknown},        // wrong basename
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			if got := DetectFormat(c.path); got != c.want {
				t.Errorf("DetectFormat(%q) = %q, want %q", c.path, got, c.want)
			}
		})
	}
}

func TestParseWindsurfMCP_RealWorld(t *testing.T) {
	doc := Parse("/Users/h/.codeium/windsurf/mcp_config.json", []byte(windsurfMCPRealWorld))
	if doc.Format != FormatWindsurfMCP {
		t.Fatalf("format = %q", doc.Format)
	}
	if doc.ParseError != nil {
		t.Fatalf("parse error: %v", doc.ParseError)
	}
	w := doc.WindsurfMCP
	if w == nil {
		t.Fatal("WindsurfMCP nil")
	}
	if len(w.Servers) != 5 {
		t.Fatalf("server count = %d, want 5", len(w.Servers))
	}
	byName := map[string]WindsurfMCPServer{}
	for _, s := range w.Servers {
		byName[s.Name] = s
	}

	// GitLab: http URL only, no headers, not disabled.
	gl := byName["GitLab"]
	if gl.URL != "https://gitlab.com/api/v4/mcp" {
		t.Errorf("GitLab URL = %q", gl.URL)
	}
	if gl.Disabled {
		t.Error("GitLab should not be disabled")
	}

	// context7: serverUrl alternate spelling, plaintext header.
	c7 := byName["context7"]
	if c7.URL != "https://mcp.context7.com/mcp" {
		t.Errorf("context7 URL = %q (serverUrl alternate spelling not picked up)", c7.URL)
	}
	if c7.Headers["CONTEXT7_API_KEY"] == "" {
		t.Error("context7 headers should contain CONTEXT7_API_KEY")
	}

	// mcp-playwright: stdio command + disabled.
	pw := byName["mcp-playwright"]
	if pw.Command != "npx" {
		t.Errorf("playwright command = %q", pw.Command)
	}
	if !pw.Disabled {
		t.Error("playwright should be disabled")
	}
}

func TestNormalizeMCPServers_AcrossFormats(t *testing.T) {
	cursorMCP := `{"mcpServers":{"foo":{"command":"npx","args":["pkg@1.0"]}}}`
	codexTOML := `[mcp_servers.bar]` + "\n" + `command = "npx"` + "\n" + `args = ["@scope/x"]`
	windsurfJSON := `{"mcpServers":{"baz":{"command":"npx","args":["-y","y"],"headers":{"Authorization":"Bearer t"}}}}`

	docs := []*Document{
		Parse("/test/.cursor/mcp.json", []byte(cursorMCP)),
		Parse("/test/.codex/config.toml", []byte(codexTOML)),
		Parse("/test/.codeium/windsurf/mcp_config.json", []byte(windsurfJSON)),
	}

	totalServers := 0
	sources := map[Format]int{}
	for _, doc := range docs {
		servers := NormalizeMCPServers(doc)
		totalServers += len(servers)
		for _, s := range servers {
			sources[s.Source]++
		}
	}
	if totalServers != 3 {
		t.Errorf("expected 3 normalized servers, got %d", totalServers)
	}
	if sources[FormatMCPConfig] != 1 || sources[FormatCodexConfig] != 1 || sources[FormatWindsurfMCP] != 1 {
		t.Errorf("source distribution wrong: %v", sources)
	}
}

func TestAllMCPFormats(t *testing.T) {
	formats := AllMCPFormats()
	if len(formats) != 3 {
		t.Fatalf("expected 3 formats, got %d (%v)", len(formats), formats)
	}
	want := map[Format]bool{FormatMCPConfig: true, FormatCodexConfig: true, FormatWindsurfMCP: true}
	for _, f := range formats {
		delete(want, f)
	}
	if len(want) > 0 {
		t.Errorf("missing formats: %v", want)
	}
}
