package builtin

import (
	"testing"

	"github.com/agentguard/agentguard/internal/parse"
)

func TestRule_ClaudeMCPAutoApprove(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{
			name: "enableAllProjectMcpServers true",
			raw:  `{"enableAllProjectMcpServers":true}`,
			want: true,
		},
		{
			name: "enabledMcpjsonServers list non-empty",
			raw:  `{"enabledMcpjsonServers":["github","gitlab"]}`,
			want: true,
		},
		{
			name: "enableAllProjectMcpServers false (explicit safe)",
			raw:  `{"enableAllProjectMcpServers":false}`,
			want: false,
		},
		{
			name: "empty enabledMcpjsonServers list",
			raw:  `{"enabledMcpjsonServers":[]}`,
			want: false,
		},
		{
			name: "neither key present",
			raw:  `{"voiceEnabled":true}`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse("/u/.claude/settings.json", []byte(c.raw))
			if got := fired(doc, "claude-mcp-auto-approve"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

func TestRule_ClaudeBashAllowlistTooBroad(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		// Total wildcards
		{name: "Bash(*) total wildcard", raw: `{"permissions":{"allow":["Bash(*)"]}}`, want: true},
		{name: "Bash() empty arg", raw: `{"permissions":{"allow":["Bash()"]}}`, want: true},
		{name: "Bash(:*) verb-and-args wildcard", raw: `{"permissions":{"allow":["Bash(:*)"]}}`, want: true},
		// Dangerous verbs with arg wildcard
		{name: "Bash(curl:*) exfil verb", raw: `{"permissions":{"allow":["Bash(curl:*)"]}}`, want: true},
		{name: "Bash(rsync:*) bulk file copy", raw: `{"permissions":{"allow":["Bash(rsync:*)"]}}`, want: true},
		{name: "Bash(sudo:*) privilege escalation", raw: `{"permissions":{"allow":["Bash(sudo:*)"]}}`, want: true},
		{name: "Bash(eval:*) shell evaluation", raw: `{"permissions":{"allow":["Bash(eval:*)"]}}`, want: true},
		{name: "Bash(aws:*) AWS CLI broad", raw: `{"permissions":{"allow":["Bash(aws:*)"]}}`, want: true},
		{name: "Bash(gh:*) GitHub CLI broad", raw: `{"permissions":{"allow":["Bash(gh:*)"]}}`, want: true},
		{name: "Bash(docker:*) container broad", raw: `{"permissions":{"allow":["Bash(docker:*)"]}}`, want: true},
		// Safe verbs even with arg wildcard
		{name: "Bash(python3 -c:*) python with -c flag", raw: `{"permissions":{"allow":["Bash(python3 -c:*)"]}}`, want: false},
		{name: "Bash(npm:*) npm broad - not in danger list", raw: `{"permissions":{"allow":["Bash(npm:*)"]}}`, want: false},
		{name: "Bash(git:*) git broad - not in danger list", raw: `{"permissions":{"allow":["Bash(git:*)"]}}`, want: false},
		// Fully specified (Mac case)
		{name: "Bash(rsync -a fixed-paths)", raw: `{"permissions":{"allow":["Bash(rsync -a __VAR__/projects/ __VAR__/projects/)"]}}`, want: false},
		{name: "Bash(git status) fully specified", raw: `{"permissions":{"allow":["Bash(git status)"]}}`, want: false},
		{name: "Bash(systemctl --user is-active foo) fully specified", raw: `{"permissions":{"allow":["Bash(systemctl --user is-active handy.service)"]}}`, want: false},
		// Other tools
		{name: "WebFetch entries (irrelevant to this rule)", raw: `{"permissions":{"allow":["WebFetch(domain:github.com)"]}}`, want: false},
		// No allow array
		{name: "no permissions", raw: `{"voiceEnabled":true}`, want: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse("/u/.claude/settings.json", []byte(c.raw))
			if got := fired(doc, "claude-bash-allowlist-too-broad"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

func TestRule_ClaudeThirdPartyPluginEnabled(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{
			name: "Mac scan case: 4 third-party plugins enabled",
			raw: `{"enabledPlugins":{
				"harshmaur-typescript-review@harshmaur-marketplace": true,
				"example-skills@anthropic-agent-skills": true,
				"playwright-cli@playwright-cli": true,
				"coderabbit@coderabbit": true,
				"telegram@claude-plugins-official": true,
				"vercel-plugin@vercel-vercel-plugin": true
			}}`,
			want: true,
		},
		{
			name: "only Anthropic-curated plugins enabled (safe)",
			raw: `{"enabledPlugins":{
				"example-skills@anthropic-agent-skills": true,
				"telegram@claude-plugins-official": true
			}}`,
			want: false,
		},
		{
			name: "third-party plugin disabled (explicit false)",
			raw: `{"enabledPlugins":{
				"foo@bar-marketplace": false
			}}`,
			want: false,
		},
		{
			name: "no enabledPlugins key",
			raw:  `{"voiceEnabled":true}`,
			want: false,
		},
		{
			name: "extraKnownMarketplaces with directory source (Mac scan case)",
			raw: `{"extraKnownMarketplaces":{
				"vercel-vercel-plugin": {"source": {"source": "directory", "path": "/Users/h/.cache/plugins/x"}}
			}}`,
			want: true,
		},
		{
			name: "extraKnownMarketplaces with git source (safer)",
			raw: `{"extraKnownMarketplaces":{
				"foo": {"source": {"source": "git", "url": "https://github.com/x/y", "ref": "v1.0"}}
			}}`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse("/u/.claude/settings.json", []byte(c.raw))
			if got := fired(doc, "claude-third-party-plugin-enabled"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

// Extend the v0.2 acceptance test from alpha.1 — alpha.2 rules should also
// fire on the actual Mac config.
func TestV02Alpha2_RealMacConfigEndToEnd(t *testing.T) {
	// Verbatim from the live Mac scan, trimmed to fields relevant to alpha.2.
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
		// alpha.2 rules: third-party-plugin-enabled fires twice (enabled list + sideloaded marketplace)
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
	// Note: claude-bash-allowlist-too-broad does NOT fire here because the
	// only Bash entry is `Bash(bun add:*)` which is a safe-verb arg-wildcard.
	// That's correct behavior — this rule is precision-tuned, not noisy.
	if got["claude-bash-allowlist-too-broad"] != 0 {
		t.Errorf("bash-allowlist rule should not fire on bun add:*, got %d", got["claude-bash-allowlist-too-broad"])
	}
}
