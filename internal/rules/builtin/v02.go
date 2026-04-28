// Package builtin v0.2 rules. Each rule below targets a specific risk shape
// confirmed present on a real Mac dev machine during v0.2 design — see the
// CHANGELOG and the design doc at ~/.gstack/projects/harshmaur-agentguard/.
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
// Catches CVE-2025-59536 (CVSS 8.7): a Claude Code hooks entry that runs an
// arbitrary shell command on PreToolUse / PostToolUse / Stop / SubagentStop /
// Notification / SessionStart / etc. An attacker who controls a repo's
// .claude/settings.json gets RCE the moment a developer opens the project.
// We extend the same matcher to cover statusLine.command — same risk shape
// (config-controlled shell runs in user shell with user privileges).

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
	if hooks, ok := doc.ClaudeSettings.Hooks[""]; ok || len(doc.ClaudeSettings.Hooks) > 0 {
		_ = hooks
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
						RuleID:       "claude-hook-shell-rce",
						Severity:     finding.SeverityCritical,
						Taxonomy:     finding.TaxEnforced,
						Title:        "Claude Code hook runs shell command",
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
	}

	// statusLine.command: same risk shape, different field. The Mac scan
	// surfaced a 600-character bash blob here.
	if sl, ok := doc.ClaudeSettings.Raw["statusLine"].(map[string]any); ok {
		if cmd, _ := sl["command"].(string); looksLikeRCEShellCommand(cmd) {
			out = append(out, finding.New(finding.Args{
				RuleID:       "claude-hook-shell-rce",
				Severity:     finding.SeverityHigh, // statusLine context is per-tick not per-tool-use, slightly lower blast radius than hooks
				Taxonomy:     finding.TaxEnforced,
				Title:        "Claude Code statusLine runs complex shell command",
				Description: "`statusLine.command` runs every status update with the user's shell. A long inline pipeline (eval / pipes / `cat | jq` / multi-step) is hard to audit; an attacker who can replace the settings.json gets RCE on every status tick.",
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
// shell work, not just `pwd` or `git status`". We treat any of: pipes (|),
// command-substitution ($(/`...`), eval, multi-segment `;`, `&&`, base64 -d,
// curl|sh patterns, presence of >50 chars + at least one shell special as
// "complex enough to be worth flagging".
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
// Catches the CVE-2025-59536 consent-bypass shape: settings.json has a
// boolean field that disables the "before I run this tool, ask the user"
// prompt globally. Across Claude Code versions the field name has been:
//   - skipAutoPermissionPrompt: true
//   - skipDangerousModePermissionPrompt: true
//   - dangerouslySkipPermissionPrompt: true
// Same risk: any prompt-injected MCP tool output, skill body, or pasted
// clipboard can run a Bash command without asking the user.

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
			RuleID:       "claude-skip-permission-prompt",
			Severity:     finding.SeverityCritical,
			Taxonomy:     finding.TaxEnforced,
			Title:        "Claude Code consent prompt disabled",
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

// --- codex-approval-disabled -----------------------------------------------
//
// `approval_policy = "never"` AND `sandbox_mode = "danger-full-access"` is the
// "no approval, no sandbox" combo. Either one alone is risky; both together
// is OpenAI's documented danger configuration.

type codexApprovalDisabled struct{}

func (codexApprovalDisabled) ID() string                 { return "codex-approval-disabled" }
func (codexApprovalDisabled) Title() string              { return "Codex CLI approval and sandbox both disabled" }
func (codexApprovalDisabled) Severity() finding.Severity { return finding.SeverityCritical }
func (codexApprovalDisabled) Taxonomy() finding.Taxonomy { return finding.TaxEnforced }
func (codexApprovalDisabled) Formats() []parse.Format    { return []parse.Format{parse.FormatCodexConfig} }

func (codexApprovalDisabled) Apply(doc *parse.Document) []finding.Finding {
	if doc.CodexConfig == nil {
		return nil
	}
	c := doc.CodexConfig
	var fired []finding.Finding

	// Either alone gets a High; both together gets a Critical.
	approvalNever := c.ApprovalPolicy == "never"
	sandboxDanger := c.SandboxMode == "danger-full-access"

	if approvalNever && sandboxDanger {
		fired = append(fired, finding.New(finding.Args{
			RuleID:       "codex-approval-disabled",
			Severity:     finding.SeverityCritical,
			Taxonomy:     finding.TaxEnforced,
			Title:        "Codex: approval=never AND sandbox=danger-full-access",
			Description:  "Codex CLI is configured with no approval prompt and full host access. This is the documented danger combo: any prompt injection or compromised MCP tool output can execute arbitrary commands.",
			Path:         doc.Path,
			Line:         findLineCodex(doc.Raw, "approval_policy"),
			Match:        `approval_policy = "never" + sandbox_mode = "danger-full-access"`,
			SuggestedFix: `Set approval_policy = "on-request" or "untrusted", and sandbox_mode = "workspace-write" (the documented safe default).`,
			Tags:         []string{"codex", "consent-bypass"},
		}))
	} else if approvalNever {
		fired = append(fired, finding.New(finding.Args{
			RuleID:       "codex-approval-disabled",
			Severity:     finding.SeverityHigh,
			Taxonomy:     finding.TaxEnforced,
			Title:        "Codex: approval_policy = never",
			Description:  "Codex runs without prompting for approval before tool use. Reduces friction but eliminates the consent gate.",
			Path:         doc.Path,
			Line:         findLineCodex(doc.Raw, "approval_policy"),
			Match:        `approval_policy = "never"`,
			SuggestedFix: `Set approval_policy = "on-request" to restore prompting, or "untrusted" for tighter control.`,
			Tags:         []string{"codex", "consent-bypass"},
		}))
	} else if sandboxDanger {
		fired = append(fired, finding.New(finding.Args{
			RuleID:       "codex-approval-disabled",
			Severity:     finding.SeverityHigh,
			Taxonomy:     finding.TaxEnforced,
			Title:        "Codex: sandbox_mode = danger-full-access",
			Description:  "Codex sandbox is fully disabled — tools can read/write/exec anywhere on the host.",
			Path:         doc.Path,
			Line:         findLineCodex(doc.Raw, "sandbox_mode"),
			Match:        `sandbox_mode = "danger-full-access"`,
			SuggestedFix: `Set sandbox_mode = "workspace-write" to restrict writes to the active workspace.`,
			Tags:         []string{"codex"},
		}))
	}
	return fired
}

// --- codex-trust-home-or-broad ---------------------------------------------
//
// `[projects."<path>"] trust_level = "trusted"` for $HOME, the parent of
// all dev work, or `/` is "I trust everywhere I work". Disables sandboxing
// for all projects under that path. The Mac scan caught this on
// /Users/harshmaur (entire $HOME). Also flags trust on `/` if it ever appears.

type codexTrustHomeOrBroad struct{}

func (codexTrustHomeOrBroad) ID() string                 { return "codex-trust-home-or-broad" }
func (codexTrustHomeOrBroad) Title() string              { return "Codex: trusted project covers $HOME or broad path" }
func (codexTrustHomeOrBroad) Severity() finding.Severity { return finding.SeverityCritical }
func (codexTrustHomeOrBroad) Taxonomy() finding.Taxonomy { return finding.TaxEnforced }
func (codexTrustHomeOrBroad) Formats() []parse.Format    { return []parse.Format{parse.FormatCodexConfig} }

// homeRootShape matches paths that are $HOME or one segment short of root.
// Examples that fire: /Users/harshmaur, /home/parallels, /, /Users.
// Examples that don't: /Users/harshmaur/projects/foo, /home/u/code/x.
var homeRootShape = regexp.MustCompile(`^(?:/|/Users/[^/]+|/home/[^/]+|/Users|/home)/?$`)

func (codexTrustHomeOrBroad) Apply(doc *parse.Document) []finding.Finding {
	if doc.CodexConfig == nil {
		return nil
	}
	var out []finding.Finding
	for path, level := range doc.CodexConfig.TrustedProjects {
		if level != "trusted" {
			continue
		}
		if !homeRootShape.MatchString(path) {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:       "codex-trust-home-or-broad",
			Severity:     finding.SeverityCritical,
			Taxonomy:     finding.TaxEnforced,
			Title:        "Codex: $HOME or broader path marked trusted",
			Description: fmt.Sprintf(
				"`[projects.%q] trust_level = \"trusted\"` disables Codex's project-trust gate for everything under `%s`. Every repo cloned under that path inherits trusted status without an explicit prompt.",
				path, path,
			),
			Path:         doc.Path,
			Line:         findLineCodex(doc.Raw, fmt.Sprintf(`[projects.%q]`, path)),
			Match:        fmt.Sprintf(`[projects.%q] trust_level = "trusted"`, path),
			SuggestedFix: "Restrict trust_level=trusted to specific project paths, not $HOME or root. Codex re-prompts per-project on first use.",
			Tags:         []string{"codex", "trust-scope"},
		}))
	}
	return out
}

// codex-mcp-plaintext-header-key was removed in alpha.3 — its coverage is
// now provided by the generalized mcp-plaintext-api-key rule which fires
// across FormatMCPConfig + FormatCodexConfig + FormatWindsurfMCP. Reusing
// the existing v0.1 stable rule ID rather than shipping a per-harness rule
// per source format.

// --- helpers ---------------------------------------------------------------

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// findKeyLineRaw is a JSON-aware version: looks for `"key"` in the raw bytes.
// Used for ClaudeSettings rules. Returns 0 if not found.
func findKeyLineRaw(raw []byte, key string) int {
	needle := `"` + key + `"`
	idx := strings.Index(string(raw), needle)
	if idx < 0 {
		return 0
	}
	return strings.Count(string(raw[:idx]), "\n") + 1
}

// findLineCodex returns the 1-indexed line where marker first appears in the
// TOML source. Used for Codex rules.
func findLineCodex(raw []byte, marker string) int {
	idx := strings.Index(string(raw), marker)
	if idx < 0 {
		return 0
	}
	return strings.Count(string(raw[:idx]), "\n") + 1
}

func prettyURL(u string) string {
	if u == "" {
		return "the upstream service"
	}
	return u
}
