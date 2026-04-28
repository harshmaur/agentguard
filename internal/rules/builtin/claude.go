// Rules over Claude Code's settings.json and settings.local.json
// (parse.FormatClaudeSettings). Each rule walks ClaudeSettings.Raw or its
// structured fields. CVE-2025-59536 (CVSS 8.7) is the umbrella for most
// of these — Check Point Research disclosed multiple consent/RCE shapes
// in early 2026.
package builtin

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/agentguard/agentguard/internal/finding"
	"github.com/agentguard/agentguard/internal/parse"
)

// --- claude-hook-shell-rce -------------------------------------------------
//
// CVE-2025-59536 (CVSS 8.7) — settings.json `hooks.<event>` runs shell
// commands on lifecycle events. Repo-shipped settings.json gives an
// attacker clone-time RCE. Same rule extends to statusLine.command when
// it contains a complex shell pipeline (>50 chars + pipes/eval/$()/curl-
// pipe-sh). The Mac scan caught a 600-char bash blob there.

type claudeHookShellRCE struct{}

func (claudeHookShellRCE) ID() string                 { return "claude-hook-shell-rce" }
func (claudeHookShellRCE) Title() string              { return "Claude Code config field runs arbitrary shell command" }
func (claudeHookShellRCE) Severity() finding.Severity { return finding.SeverityCritical }
func (claudeHookShellRCE) Taxonomy() finding.Taxonomy { return finding.TaxEnforced }
func (claudeHookShellRCE) Formats() []parse.Format    { return []parse.Format{parse.FormatClaudeSettings} }

func (claudeHookShellRCE) Apply(doc *parse.Document) []finding.Finding {
	if doc.ClaudeSettings == nil || doc.ClaudeSettings.Raw == nil {
		return nil
	}
	var out []finding.Finding

	// hooks: { "<event>": [ { matcher: "...", hooks: [ { type: "command", command: "..." } ] } ] }
	for event, v := range doc.ClaudeSettings.Hooks {
		arr, ok := v.([]any)
		if !ok {
			continue
		}
		for _, entry := range arr {
			m, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			inner, ok := m["hooks"].([]any)
			if !ok {
				continue
			}
			for _, hk := range inner {
				hm, ok := hk.(map[string]any)
				if !ok {
					continue
				}
				cmd, _ := hm["command"].(string)
				if cmd == "" {
					continue
				}
				out = append(out, finding.New(finding.Args{
					RuleID:   "claude-hook-shell-rce",
					Severity: finding.SeverityCritical,
					Taxonomy: finding.TaxEnforced,
					Title:    "Claude Code hook runs shell command",
					Description: fmt.Sprintf(
						"`hooks.%s` runs a shell command on the matching event. An attacker who can place a settings.json (e.g. via a cloned repo) gets RCE on the developer machine. CVE-2025-59536.",
						event,
					),
					Path:         doc.Path,
					Line:         findKeyLineRaw(doc.Raw, "hooks"),
					Match:        truncate(cmd, 200),
					SuggestedFix: "Remove the hook, or restrict to repo-trusted paths only. Audit the command's blast radius.",
					Tags:         []string{"claude", "hooks", "cve-2025-59536"},
				}))
			}
		}
	}

	// statusLine.command: same risk shape, different field. The Mac scan
	// surfaced a 600-character bash blob here.
	if sl, ok := doc.ClaudeSettings.Raw["statusLine"].(map[string]any); ok {
		if cmd, _ := sl["command"].(string); looksLikeRCEShellCommand(cmd) {
			out = append(out, finding.New(finding.Args{
				RuleID:       "claude-hook-shell-rce",
				Severity:     finding.SeverityHigh, // statusLine context per-tick, slightly lower blast radius than hooks
				Taxonomy:     finding.TaxEnforced,
				Title:        "Claude Code statusLine runs complex shell command",
				Description:  "`statusLine.command` runs every status update with the user's shell. A long inline pipeline (eval / pipes / `cat | jq` / multi-step) is hard to audit; an attacker who can replace the settings.json gets RCE on every status tick.",
				Path:         doc.Path,
				Line:         findKeyLineRaw(doc.Raw, "statusLine"),
				Match:        truncate(cmd, 200),
				SuggestedFix: "Move complex statusLine logic to a versioned, signed script with a known path. Reference the script, not an inline blob.",
				Tags:         []string{"claude", "statusline"},
			}))
		}
	}

	return out
}

// looksLikeRCEShellCommand: heuristic for "this command field is doing real
// shell work, not just `pwd` or `git status`". Any of: pipes, command-
// substitution, eval, multi-segment `;`/`&&`, base64 -d, or curl|sh
// patterns. Keeps short benign commands (`pwd`, `whoami`) from firing.
func looksLikeRCEShellCommand(s string) bool {
	if s == "" {
		return false
	}
	if len(s) >= 50 {
		if strings.ContainsAny(s, "|;&") || strings.Contains(s, "$(") || strings.Contains(s, "`") {
			return true
		}
	}
	// Even short, very dangerous shapes:
	if regexp.MustCompile(`(?i)\b(?:eval|base64\s+-d|curl[^|]*\|\s*(?:bash|sh|zsh)|wget[^|]*\|\s*(?:bash|sh|zsh))\b`).MatchString(s) {
		return true
	}
	return false
}

// --- claude-skip-permission-prompt -----------------------------------------
//
// Three field-name variants of the consent-bypass shape across Claude Code
// versions. Same risk: any prompt-injected MCP tool output, skill body, or
// pasted clipboard can run a Bash command without asking the user.

type claudeSkipPermissionPrompt struct{}

func (claudeSkipPermissionPrompt) ID() string                 { return "claude-skip-permission-prompt" }
func (claudeSkipPermissionPrompt) Title() string              { return "Claude Code permission prompt disabled" }
func (claudeSkipPermissionPrompt) Severity() finding.Severity { return finding.SeverityCritical }
func (claudeSkipPermissionPrompt) Taxonomy() finding.Taxonomy { return finding.TaxEnforced }
func (claudeSkipPermissionPrompt) Formats() []parse.Format    { return []parse.Format{parse.FormatClaudeSettings} }

var skipPromptKeys = []string{
	"skipAutoPermissionPrompt",
	"skipDangerousModePermissionPrompt",
	"dangerouslySkipPermissionPrompt",
}

func (claudeSkipPermissionPrompt) Apply(doc *parse.Document) []finding.Finding {
	if doc.ClaudeSettings == nil || doc.ClaudeSettings.Raw == nil {
		return nil
	}
	var out []finding.Finding
	for _, key := range skipPromptKeys {
		v, ok := doc.ClaudeSettings.Raw[key]
		if !ok {
			continue
		}
		b, ok := v.(bool)
		if !ok || !b {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:   "claude-skip-permission-prompt",
			Severity: finding.SeverityCritical,
			Taxonomy: finding.TaxEnforced,
			Title:    "Claude Code consent prompt disabled",
			Description: fmt.Sprintf(
				"`%s = true` removes the user-approval gate for tool use. Any prompt-injected MCP tool output, skill, or pasted content can trigger Bash/Edit/Write without asking. CVE-2025-59536 consent-bypass shape.",
				key,
			),
			Path:         doc.Path,
			Line:         findKeyLineRaw(doc.Raw, key),
			Match:        key + " = true",
			SuggestedFix: fmt.Sprintf("Remove `%s` from settings.json, or set it to false. Restore the per-tool consent gate.", key),
			Tags:         []string{"claude", "consent-bypass", "cve-2025-59536"},
		}))
	}
	return out
}

// --- claude-mcp-auto-approve -----------------------------------------------
//
// Two known keys grant blanket auto-approval to project-level MCP servers
// without prompting. enableAllProjectMcpServers=true is the dangerous one
// (clone-time MCP foothold). enabledMcpjsonServers is an explicit allowlist
// (less broadly dangerous, still High because each entry is a consent prompt
// that won't fire).

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
				RuleID:   "claude-mcp-auto-approve",
				Severity: finding.SeverityHigh,
				Taxonomy: finding.TaxDetectable,
				Title:    "Claude Code has an MCP server allowlist (no prompt for these)",
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
// `permissions.allow` entries take the shape `Bash(<pattern>)`. Three risk
// shapes: total wildcards (`Bash(*)`, `Bash(:*)`, `Bash()`), dangerous-verb
// + arg wildcard (`Bash(curl:*)` etc.), and shell-escape verbs. Safe entries
// (`Bash(git status)`, `Bash(python3 -c:*)`, `Bash(npm:*)`) do not fire.

type claudeBashAllowlistTooBroad struct{}

func (claudeBashAllowlistTooBroad) ID() string                 { return "claude-bash-allowlist-too-broad" }
func (claudeBashAllowlistTooBroad) Title() string              { return "Claude Code Bash allowlist permits a too-broad pattern" }
func (claudeBashAllowlistTooBroad) Severity() finding.Severity { return finding.SeverityHigh }
func (claudeBashAllowlistTooBroad) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (claudeBashAllowlistTooBroad) Formats() []parse.Format    { return []parse.Format{parse.FormatClaudeSettings} }

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
				Severity:     finding.SeverityCritical, // total wildcard worse than verb-specific
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
				RuleID:   "claude-bash-allowlist-too-broad",
				Severity: finding.SeverityHigh,
				Taxonomy: finding.TaxDetectable,
				Title:    fmt.Sprintf("Claude Code allowlist permits %s with any args", verb),
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
// marketplaces are known-safe; everything else is "third party" — same blast
// radius as a malicious MCP server but enabled silently via settings.json.
// Severity Medium for enabled plugins (inventory), High for sideloaded
// `extraKnownMarketplaces` with a directory source.

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
				RuleID:   "claude-third-party-plugin-enabled",
				Severity: finding.SeverityMedium,
				Taxonomy: finding.TaxAdvisory,
				Title:    "Claude Code third-party plugin(s) enabled",
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

	// extraKnownMarketplaces.<name>.source.source = "directory" → sideloaded.
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
				RuleID:   "claude-third-party-plugin-enabled",
				Severity: finding.SeverityHigh,
				Taxonomy: finding.TaxAdvisory,
				Title:    "Claude Code sideloaded marketplace from local directory",
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
