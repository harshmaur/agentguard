package parse

import "testing"

func TestDetectFormat_CursorPermissions(t *testing.T) {
	cases := []struct {
		path string
		want Format
	}{
		{"/home/u/.cursor/permissions.json", FormatCursorPermissions},
		{"/Users/h/.cursor/permissions.json", FormatCursorPermissions},
		{"/home/u/.cursor/mcp.json", FormatMCPConfig}, // mcp.json stays MCPConfig
		{"/home/u/permissions.json", FormatUnknown},   // not under .cursor
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			if got := DetectFormat(c.path); got != c.want {
				t.Errorf("DetectFormat(%q) = %q, want %q", c.path, got, c.want)
			}
		})
	}
}

func TestParseCursorPermissions(t *testing.T) {
	cases := []struct {
		name              string
		raw               string
		wantHasMCP        bool
		wantHasTerm       bool
		wantMCPLen        int
		wantTermLen       int
	}{
		{
			name:        "both fields present",
			raw:         `{"mcpAllowlist":["github:*"],"terminalAllowlist":["git","npm"]}`,
			wantHasMCP:  true,
			wantHasTerm: true,
			wantMCPLen:  1,
			wantTermLen: 2,
		},
		{
			name:        "only mcpAllowlist",
			raw:         `{"mcpAllowlist":["*:*"]}`,
			wantHasMCP:  true,
			wantHasTerm: false,
			wantMCPLen:  1,
		},
		{
			name:        "explicit empty arrays (different from missing)",
			raw:         `{"mcpAllowlist":[],"terminalAllowlist":[]}`,
			wantHasMCP:  true,
			wantHasTerm: true,
			wantMCPLen:  0,
			wantTermLen: 0,
		},
		{
			name:       "empty file (both missing)",
			raw:        `{}`,
			wantHasMCP: false,
			wantHasTerm: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := Parse("/u/.cursor/permissions.json", []byte(c.raw))
			if doc.Format != FormatCursorPermissions {
				t.Fatalf("format = %q", doc.Format)
			}
			if doc.ParseError != nil {
				t.Fatalf("parse error: %v", doc.ParseError)
			}
			cp := doc.CursorPermissions
			if cp == nil {
				t.Fatal("CursorPermissions nil")
			}
			if cp.HasMCPAllowlist != c.wantHasMCP {
				t.Errorf("HasMCPAllowlist = %v, want %v", cp.HasMCPAllowlist, c.wantHasMCP)
			}
			if cp.HasTerminalAllowlist != c.wantHasTerm {
				t.Errorf("HasTerminalAllowlist = %v, want %v", cp.HasTerminalAllowlist, c.wantHasTerm)
			}
			if len(cp.MCPAllowlist) != c.wantMCPLen {
				t.Errorf("MCPAllowlist len = %d, want %d", len(cp.MCPAllowlist), c.wantMCPLen)
			}
			if len(cp.TerminalAllowlist) != c.wantTermLen {
				t.Errorf("TerminalAllowlist len = %d, want %d", len(cp.TerminalAllowlist), c.wantTermLen)
			}
		})
	}
}
