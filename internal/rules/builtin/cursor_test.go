package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestRule_CursorAllowlistTooBroad(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{
			name: "* total wildcard (Critical)",
			raw:  `{"terminalAllowlist":["*"]}`,
			want: true,
		},
		{
			name: "bare bash shell escape",
			raw:  `{"terminalAllowlist":["bash"]}`,
			want: true,
		},
		{
			name: "curl exfil verb",
			raw:  `{"terminalAllowlist":["curl"]}`,
			want: true,
		},
		{
			name: "sudo:* privilege escalation",
			raw:  `{"terminalAllowlist":["sudo:*"]}`,
			want: true,
		},
		{
			name: "rsync:install* (rsync is dangerous)",
			raw:  `{"terminalAllowlist":["rsync:install*"]}`,
			want: true,
		},
		// Safe entries
		{
			name: "git",
			raw:  `{"terminalAllowlist":["git"]}`,
			want: false,
		},
		{
			name: "npm:install*",
			raw:  `{"terminalAllowlist":["npm:install*"]}`,
			want: false,
		},
		{
			name: "cargo build (exact)",
			raw:  `{"terminalAllowlist":["cargo build"]}`,
			want: false,
		},
		{
			name: "explicit empty array (no auto-run)",
			raw:  `{"terminalAllowlist":[]}`,
			want: false,
		},
		{
			name: "no terminalAllowlist key at all",
			raw:  `{"mcpAllowlist":["github:*"]}`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse("/u/.cursor/permissions.json", []byte(c.raw))
			if got := fired(doc, "cursor-allowlist-too-broad"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

func TestRule_CursorMCPWildcard(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{
			name: "*:* total wildcard (Critical)",
			raw:  `{"mcpAllowlist":["*:*"]}`,
			want: true,
		},
		{
			name: "*:my_tool (any server claims this tool name)",
			raw:  `{"mcpAllowlist":["*:my_tool"]}`,
			want: true,
		},
		{
			name: "github:* (all tools from github server)",
			raw:  `{"mcpAllowlist":["github:*"]}`,
			want: true,
		},
		// Safe entries
		{
			name: "explicit server:tool",
			raw:  `{"mcpAllowlist":["github:list_pulls","linear:list_issues"]}`,
			want: false,
		},
		{
			name: "explicit empty array",
			raw:  `{"mcpAllowlist":[]}`,
			want: false,
		},
		{
			name: "no mcpAllowlist at all",
			raw:  `{"terminalAllowlist":["git"]}`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse("/u/.cursor/permissions.json", []byte(c.raw))
			if got := fired(doc, "cursor-mcp-wildcard"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}
