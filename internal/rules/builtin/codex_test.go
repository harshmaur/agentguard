package builtin

import (
	"testing"

	"github.com/agentguard/agentguard/internal/parse"
)

func TestRule_CodexApprovalDisabled(t *testing.T) {
	cases := []struct {
		name string
		toml string
		want bool
	}{
		{
			name: "approval=never AND sandbox=danger-full-access (Critical)",
			toml: `approval_policy = "never"` + "\n" + `sandbox_mode = "danger-full-access"`,
			want: true,
		},
		{
			name: "approval=never alone (High)",
			toml: `approval_policy = "never"`,
			want: true,
		},
		{
			name: "sandbox=danger-full-access alone (High)",
			toml: `sandbox_mode = "danger-full-access"`,
			want: true,
		},
		{
			name: "safe defaults",
			toml: `approval_policy = "on-request"` + "\n" + `sandbox_mode = "workspace-write"`,
			want: false,
		},
		{
			name: "neither set (omitted)",
			toml: `model = "gpt-5.4"`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse("/u/.codex/config.toml", []byte(c.toml))
			if got := fired(doc, "codex-approval-disabled"); got != c.want {
				t.Errorf("fired = %v, want %v", got, c.want)
			}
		})
	}
}

func TestRule_CodexTrustHomeOrBroad(t *testing.T) {
	cases := []struct {
		name string
		toml string
		want bool
	}{
		{
			name: "trust on /Users/harshmaur ($HOME) — Mac scan case",
			toml: `[projects."/Users/harshmaur"]` + "\n" + `trust_level = "trusted"`,
			want: true,
		},
		{
			name: "trust on /home/parallels (Linux $HOME)",
			toml: `[projects."/home/parallels"]` + "\n" + `trust_level = "trusted"`,
			want: true,
		},
		{
			name: "trust on / (root)",
			toml: `[projects."/"]` + "\n" + `trust_level = "trusted"`,
			want: true,
		},
		{
			name: "trust on a specific project (safe)",
			toml: `[projects."/Users/harshmaur/projects/foo"]` + "\n" + `trust_level = "trusted"`,
			want: false,
		},
		{
			name: "trust on /Users (broad parent)",
			toml: `[projects."/Users"]` + "\n" + `trust_level = "trusted"`,
			want: true,
		},
		{
			name: "trust_level untrusted on $HOME (no risk)",
			toml: `[projects."/Users/harshmaur"]` + "\n" + `trust_level = "untrusted"`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse("/u/.codex/config.toml", []byte(c.toml))
			if got := fired(doc, "codex-trust-home-or-broad"); got != c.want {
				t.Errorf("fired = %v, want %v", got, c.want)
			}
		})
	}
}
