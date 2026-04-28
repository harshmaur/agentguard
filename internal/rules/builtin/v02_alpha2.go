// Package builtin v0.2.0-alpha.2 rules. All three read from
// ClaudeSettings.Raw — no new format detector required.
package builtin

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/agentguard/agentguard/internal/finding"
	"github.com/agentguard/agentguard/internal/parse"
)

// --- claude-mcp-auto-approve ----------------------------------------------
//
// Catches the CVE-2025-59536 MCP-consent-bypass shape. Two known keys grant
// blanket auto-approval to project-level MCP servers without prompting:
//
//	"enableAllProjectMcpServers": true   // every .mcp.json found auto-loads
//	"enabledMcpjsonServers": [...]       // explicit allowlist of servers (always-on)
//
// `enableAllProjectMcpServers: true` is the dangerous one — clone a malicious
// repo with a `.mcp.json` that points at an attacker-controlled MCP server,
// open the project, attacker has tool access. `enabledMcpjsonServers` is
// less broadly dangerous (it's an explicit list of known servers), but
// still flagged at High because every entry is a consent-prompt that won't
// fire.

type claudeMCPAutoApprove struct{}

func (claudeMCPAutoApprove) ID() string                 { return "claude-mcp-auto-approve" }
func (claudeMCPAutoApprove) Title() string              { return "Claude Code auto-approves MCP servers without prompting" }
func (claudeMCPAutoApprove) Severity() finding.Severity { return finding.SeverityCritical }
func (claudeMCPAutoApprove) Taxonomy() finding.Taxonomy { return finding.TaxEnforced }
func (claudeMCPAutoApprove) Formats() []parse.Format    { return []parse.Format{parse.FormatClaudeSettings} }

func (claudeMCPAutoApprove) Apply(doc *parse.Document) []finding.Finding {
	if doc.ClaudeSettings == nil || doc.ClaudeSettings.Raw == nil {
		return nil
	}
	var out []finding.Finding

	if v, ok := doc.ClaudeSettings.Raw["enableAllProjectMcpServers"]; ok {
		if b, ok := v.(bool); ok && b {
			out = append(out, finding.New(finding.Args{
				RuleID:       "claude-mcp-auto-approve",
				Severity:     finding.SeverityCritical,
				Taxonomy:     finding.TaxEnforced,
				Title:        "Claude Code auto-loads every project .mcp.json",
				Description:  "`enableAllProjectMcpServers = true` causes Claude Code to load and trust every .mcp.json in any project you open, with no consent prompt. Cloning a malicious repo with a poisoned .mcp.json is one open-project away from arbitrary tool access. CVE-2025-59536 consent-bypass shape.",
				Path:         doc.Path,
				Line:         findKeyLineRaw(doc.Raw, "enableAllProjectMcpServers"),
				Match:        "enableAllProjectMcpServers = true",
				SuggestedFix: "Set `enableAllProjectMcpServers` to false (or remove the key). Use `enabledMcpjsonServers` with an explicit allowlist if you want trusted project MCPs.",
				Tags:         []string{"claude", "mcp", "consent-bypass", "cve-2025-59536"},
			}))
		}
	}

	if v, ok := doc.ClaudeSettings.Raw["enabledMcpjsonServers"]; ok {
		if arr, ok := v.([]any); ok && len(arr) > 0 {
			names := make([]string, 0, len(arr))
			for _, n := range arr {
				if s, ok := n.(string); ok {
					names = append(names, s)
				}
			}
			out = append(out, finding.New(finding.Args{
				RuleID:       "claude-mcp-auto-approve",
				Severity:     finding.SeverityHigh,
				Taxonomy:     finding.TaxDetectable,
				Title:        "Claude Code has an MCP server allowlist (no prompt for these)",
				Description: fmt.Sprintf(
					"`enabledMcpjsonServers` lists %d server(s) Claude Code loads without prompting: %s. Each one needs to actually be trusted — a compromised entry on this list is a silent foothold.",
					len(names), strings.Join(names, ", "),
				),
				Path:         doc.Path,
				Line:         findKeyLineRaw(doc.Raw, "enabledMcpjsonServers"),
				Match:        truncate(strings.Join(names, ","), 200),
				SuggestedFix: "Audit each entry. Move untrusted servers off the list so the consent prompt re-engages.",
				Tags:         []string{"claude", "mcp"},
			}))
		}
	}

	return out
}

// --- claude-bash-allowlist-too-broad ---------------------------------------
//
// `permissions.allow` entries take the shape `Bash(<pattern>)`. A safe entry
// looks like `Bash(git status)` (fully specified) or `Bash(python3 -c:*)`
// (broad-arg but locked to one binary). A dangerous entry has the shape
// `Bash(<exfil-or-shell-verb>:*)` which gives any prompt-injected command
// using that verb a free pass.
//
// Three risk shapes:
//   - Total wildcards: `Bash(*)`, `Bash(:*)`, `Bash()`.
//   - Exfil verbs with arg wildcard: `Bash(curl:*)`, `Bash(wget:*)`,
//     `Bash(nc:*)`, `Bash(scp:*)`, `Bash(sftp:*)`, `Bash(rsync:*)`,
//     `Bash(aws:*)` (s3 cp), `Bash(gh:*)` (gist create).
//   - Shell-escape verbs with arg wildcard: `Bash(bash:*)`, `Bash(sh:*)`,
//     `Bash(zsh:*)`, `Bash(eval:*)`, `Bash(exec:*)`.
//   - Privilege escalation: `Bash(sudo:*)`, `Bash(doas:*)`, `Bash(su:*)`.

type claudeBashAllowlistTooBroad struct{}

func (claudeBashAllowlistTooBroad) ID() string                 { return "claude-bash-allowlist-too-broad" }
func (claudeBashAllowlistTooBroad) Title() string              { return "Claude Code Bash allowlist permits a too-broad pattern" }
func (claudeBashAllowlistTooBroad) Severity() finding.Severity { return finding.SeverityHigh }
func (claudeBashAllowlistTooBroad) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (claudeBashAllowlistTooBroad) Formats() []parse.Format    { return []parse.Format{parse.FormatClaudeSettings} }

// dangerousBashVerbs are commands that should never be allowlisted with
// arbitrary args (`<verb>:*`). Each maps to a one-line reason for the
// finding's description.
var dangerousBashVerbs = map[string]string{
	"curl":   "network egress (any HTTP request to any host)",
	"wget":   "network egress (any HTTP request to any host)",
	"nc":     "network egress / shell tunneling",
	"ncat":   "network egress / shell tunneling",
	"scp":    "file exfil over SSH",
	"sftp":   "file exfil over SFTP",
	"rsync":  "bulk file copy (anywhere on disk)",
	"aws":    "AWS CLI (s3 cp, sts assume-role, ...)",
	"gh":     "GitHub CLI (gist create, repo create, ...)",
	"glab":   "GitLab CLI",
	"bash":   "arbitrary shell command",
	"sh":     "arbitrary shell command",
	"zsh":    "arbitrary shell command",
	"fish":   "arbitrary shell command",
	"eval":   "arbitrary shell evaluation",
	"exec":   "process replacement",
	"sudo":   "privilege escalation",
	"doas":   "privilege escalation",
	"su":     "user switching",
	"docker": "container ops (docker run --privileged, mount /, ...)",
	"kubectl": "Kubernetes ops (apply, exec into any pod)",
}

// totalWildcardPattern matches `Bash()`, `Bash(*)`, `Bash(:*)`, `Bash( :* )`.
var totalWildcardPattern = regexp.MustCompile(`^Bash\(\s*[:*]?\s*\*?\s*\)$`)

// verbArgWildcard matches `Bash(<verb>:*)`. Captures the verb.
var verbArgWildcard = regexp.MustCompile(`^Bash\(\s*([A-Za-z][A-Za-z0-9_\-]*)\s*:\*\s*\)$`)

func (claudeBashAllowlistTooBroad) Apply(doc *parse.Document) []finding.Finding {
	if doc.ClaudeSettings == nil || doc.ClaudeSettings.Permissions == nil {
		return nil
	}
	allowAny, ok := doc.ClaudeSettings.Permissions["allow"]
	if !ok {
		return nil
	}
	arr, ok := allowAny.([]any)
	if !ok {
		return nil
	}
	var out []finding.Finding
	for _, v := range arr {
		entry, ok := v.(string)
		if !ok {
			continue
		}
		// Total wildcard.
		if totalWildcardPattern.MatchString(entry) {
			out = append(out, finding.New(finding.Args{
				RuleID:       "claude-bash-allowlist-too-broad",
				Severity:     finding.SeverityCritical, // total wildcard is worse than verb-specific
				Taxonomy:     finding.TaxEnforced,
				Title:        "Claude Code allowlist contains an unrestricted Bash entry",
				Description:  fmt.Sprintf("The entry `%s` permits Claude Code to run any Bash command without prompting. Equivalent to `--dangerously-skip-permissions` for shell.", entry),
				Path:         doc.Path,
				Line:         findKeyLineRaw(doc.Raw, "allow"),
				Match:        entry,
				SuggestedFix: "Remove this entry, or replace it with specific allowlist entries (e.g. `Bash(git status)`, `Bash(npm test)`).",
				Tags:         []string{"claude", "allowlist"},
			}))
			continue
		}
		// Verb + arg wildcard.
		if m := verbArgWildcard.FindStringSubmatch(entry); m != nil {
			verb := m[1]
			reason, ok := dangerousBashVerbs[strings.ToLower(verb)]
			if !ok {
				continue // safe verb (e.g. `python3:*`, `npm:*`)
			}
			out = append(out, finding.New(finding.Args{
				RuleID:       "claude-bash-allowlist-too-broad",
				Severity:     finding.SeverityHigh,
				Taxonomy:     finding.TaxDetectable,
				Title:        fmt.Sprintf("Claude Code allowlist permits %s with any args", verb),
				Description: fmt.Sprintf(
					"`%s` allows Claude Code to invoke `%s` with arbitrary arguments. Risk: %s. Any prompt injection that produces a `%s ...` command is auto-approved.",
					entry, verb, reason, verb,
				),
				Path:         doc.Path,
				Line:         findKeyLineRaw(doc.Raw, "allow"),
				Match:        entry,
				SuggestedFix: fmt.Sprintf("Replace `%s` with explicit, fully-specified entries: e.g. `Bash(%s --version)`, `Bash(%s help)`.", entry, verb, verb),
				Tags:         []string{"claude", "allowlist", verb},
			}))
		}
	}
	return out
}

// --- claude-third-party-plugin-enabled -------------------------------------
//
// Plugin entries are keyed `<plugin>@<marketplace>`. Anthropic-curated
// marketplaces are known-safe; everything else is third-party — same blast
// radius as a malicious MCP server but enabled silently via settings.json.
// Severity Advisory: this is an inventory finding, not a vulnerability claim.
// The Attack Chains layer (later alpha) combines this with other findings.

type claudeThirdPartyPluginEnabled struct{}

func (claudeThirdPartyPluginEnabled) ID() string                 { return "claude-third-party-plugin-enabled" }
func (claudeThirdPartyPluginEnabled) Title() string              { return "Claude Code third-party plugin enabled" }
func (claudeThirdPartyPluginEnabled) Severity() finding.Severity { return finding.SeverityMedium }
func (claudeThirdPartyPluginEnabled) Taxonomy() finding.Taxonomy { return finding.TaxAdvisory }
func (claudeThirdPartyPluginEnabled) Formats() []parse.Format    { return []parse.Format{parse.FormatClaudeSettings} }

// trustedMarketplaces are Anthropic-controlled or vendor-curated marketplaces
// considered low-risk. Everything else is "third party" for inventory purposes.
var trustedMarketplaces = map[string]bool{
	"anthropic-agent-skills":  true,
	"anthropic":               true,
	"claude-plugins-official": true,
}

func (claudeThirdPartyPluginEnabled) Apply(doc *parse.Document) []finding.Finding {
	if doc.ClaudeSettings == nil || doc.ClaudeSettings.Raw == nil {
		return nil
	}
	var out []finding.Finding

	// enabledPlugins: { "<plugin>@<marketplace>": true|false }
	if pluginsRaw, ok := doc.ClaudeSettings.Raw["enabledPlugins"].(map[string]any); ok {
		thirdParty := []string{}
		for key, v := range pluginsRaw {
			b, ok := v.(bool)
			if !ok || !b {
				continue
			}
			at := strings.LastIndex(key, "@")
			if at < 0 {
				continue
			}
			marketplace := key[at+1:]
			if trustedMarketplaces[marketplace] {
				continue
			}
			thirdParty = append(thirdParty, key)
		}
		if len(thirdParty) > 0 {
			out = append(out, finding.New(finding.Args{
				RuleID:       "claude-third-party-plugin-enabled",
				Severity:     finding.SeverityMedium,
				Taxonomy:     finding.TaxAdvisory,
				Title:        "Claude Code third-party plugin(s) enabled",
				Description: fmt.Sprintf(
					"%d enabled plugin(s) are loaded from non-Anthropic-owned marketplaces: %s. Each runs with the same blast radius as Claude Code itself; a compromised plugin can override built-in tools, exfiltrate context, or run arbitrary code.",
					len(thirdParty), strings.Join(thirdParty, ", "),
				),
				Path:         doc.Path,
				Line:         findKeyLineRaw(doc.Raw, "enabledPlugins"),
				Match:        truncate(strings.Join(thirdParty, ", "), 200),
				SuggestedFix: "Audit each third-party plugin's source. Pin to a specific commit or version. Remove plugins you don't actively use.",
				Tags:         []string{"claude", "plugins", "supply-chain"},
			}))
		}
	}

	// extraKnownMarketplaces.<name>.source.source = "directory" → sideloaded
	// marketplace (loaded from a local path). Higher risk than a remote
	// marketplace with version pinning.
	if extraRaw, ok := doc.ClaudeSettings.Raw["extraKnownMarketplaces"].(map[string]any); ok {
		sideloaded := []string{}
		for name, v := range extraRaw {
			entry, ok := v.(map[string]any)
			if !ok {
				continue
			}
			source, ok := entry["source"].(map[string]any)
			if !ok {
				continue
			}
			if srcType, _ := source["source"].(string); srcType == "directory" {
				sideloaded = append(sideloaded, name)
			}
		}
		if len(sideloaded) > 0 {
			out = append(out, finding.New(finding.Args{
				RuleID:       "claude-third-party-plugin-enabled",
				Severity:     finding.SeverityHigh, // sideloaded marketplace is higher risk than registered third-party
				Taxonomy:     finding.TaxAdvisory,
				Title:        "Claude Code sideloaded marketplace from local directory",
				Description: fmt.Sprintf(
					"%d marketplace(s) loaded from a local directory rather than a published source: %s. Anyone who can write to the local path can ship plugins. Common shape after a `npm link`-style local install.",
					len(sideloaded), strings.Join(sideloaded, ", "),
				),
				Path:         doc.Path,
				Line:         findKeyLineRaw(doc.Raw, "extraKnownMarketplaces"),
				Match:        truncate(strings.Join(sideloaded, ", "), 200),
				SuggestedFix: "Replace the directory source with a `git` or `tarball` source pinned to a known commit / version.",
				Tags:         []string{"claude", "plugins", "sideloaded"},
			}))
		}
	}

	return out
}
