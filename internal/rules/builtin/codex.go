// Rules over Codex CLI's ~/.codex/config.toml. Three rules:
//   - codex-approval-disabled    (approval_policy=never AND/OR sandbox_mode=danger-full-access)
//   - codex-trust-home-or-broad  ([projects."<path>"] trust_level=trusted on $HOME or root)
//
// MCP-specific Codex risks (plaintext header keys, unpinned npx, unauth
// remote URL) live in mcp.go and fire across Codex+Cursor+Windsurf via the
// normalized MCP model.
package builtin

import (
	"fmt"
	"regexp"

	"github.com/harshmaur/agentguard/internal/finding"
	"github.com/harshmaur/agentguard/internal/parse"
)

// --- codex-approval-disabled -----------------------------------------------

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

	approvalNever := c.ApprovalPolicy == "never"
	sandboxDanger := c.SandboxMode == "danger-full-access"

	switch {
	case approvalNever && sandboxDanger:
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
	case approvalNever:
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
	case sandboxDanger:
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
// `[projects."<path>"] trust_level = "trusted"` for $HOME, `/`, or a single-
// segment-from-root parent (`/Users`, `/home`) disables Codex's
// project-trust gate for everything underneath. The Mac scan caught this on
// /Users/harshmaur (entire $HOME).

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
			RuleID:   "codex-trust-home-or-broad",
			Severity: finding.SeverityCritical,
			Taxonomy: finding.TaxEnforced,
			Title:    "Codex: $HOME or broader path marked trusted",
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
