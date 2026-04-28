// Rules over Cursor's global ~/.cursor/permissions.json. Two rules:
//   - cursor-allowlist-too-broad  (terminalAllowlist with broad/dangerous entries)
//   - cursor-mcp-wildcard         (mcpAllowlist with *:* / *:<tool> / <server>:*)
//
// Cursor's .cursor/mcp.json (project-level MCP config) is detected as
// FormatMCPConfig and covered by the generalized MCP rules in mcp.go.
package builtin

import (
	"fmt"
	"strings"

	"github.com/harshmaur/agentguard/internal/finding"
	"github.com/harshmaur/agentguard/internal/parse"
)

// --- cursor-allowlist-too-broad --------------------------------------------
//
// Cursor's terminalAllowlist controls which terminal commands auto-run
// without prompting. Reuses the dangerousBashVerbs map from helpers.go so
// the same risks fire whether they appear in Claude's allowlist or Cursor's.
// Backslash Security and Pillar Security demonstrated multiple bypass paths
// when broad shell verbs are present.

type cursorAllowlistTooBroad struct{}

func (cursorAllowlistTooBroad) ID() string                 { return "cursor-allowlist-too-broad" }
func (cursorAllowlistTooBroad) Title() string              { return "Cursor terminal allowlist permits too-broad pattern" }
func (cursorAllowlistTooBroad) Severity() finding.Severity { return finding.SeverityHigh }
func (cursorAllowlistTooBroad) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (cursorAllowlistTooBroad) Formats() []parse.Format    { return []parse.Format{parse.FormatCursorPermissions} }

func (cursorAllowlistTooBroad) Apply(doc *parse.Document) []finding.Finding {
	if doc.CursorPermissions == nil || !doc.CursorPermissions.HasTerminalAllowlist {
		return nil
	}
	var out []finding.Finding
	for _, entry := range doc.CursorPermissions.TerminalAllowlist {
		entry = strings.TrimSpace(entry)

		// Total wildcard.
		if entry == "*" {
			out = append(out, finding.New(finding.Args{
				RuleID:       "cursor-allowlist-too-broad",
				Severity:     finding.SeverityCritical,
				Taxonomy:     finding.TaxEnforced,
				Title:        "Cursor terminalAllowlist contains a total wildcard",
				Description:  "`terminalAllowlist: [\"*\"]` permits Cursor to auto-run any terminal command without prompting. Equivalent to disabling the consent gate. Multiple bypass paths exist (Backslash Security 2026, GHSA-82wg-qcm4-fp2w).",
				Path:         doc.Path,
				Match:        entry,
				SuggestedFix: "Replace with explicit, fully-specified entries (e.g. `git status`, `npm test`).",
				Tags:         []string{"cursor", "allowlist"},
			}))
			continue
		}

		// Verb (with or without :*) where the verb is in the danger list.
		// Cursor entries are `<verb>` (any args allowed) or `<verb>:<arg-glob>`
		// (args must match). A bare verb is already broad enough on its own.
		verb := entry
		if i := strings.Index(entry, ":"); i >= 0 {
			verb = strings.TrimSpace(entry[:i])
		}
		// Take the first whitespace-separated token as the actual command.
		if i := strings.IndexAny(verb, " \t"); i >= 0 {
			verb = verb[:i]
		}
		reason, ok := dangerousBashVerbs[strings.ToLower(verb)]
		if !ok {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:   "cursor-allowlist-too-broad",
			Severity: finding.SeverityHigh,
			Taxonomy: finding.TaxDetectable,
			Title:    fmt.Sprintf("Cursor terminalAllowlist permits %s", verb),
			Description: fmt.Sprintf(
				"`terminalAllowlist` contains `%s`. Risk: %s. Any prompt-injected `%s ...` command in Cursor's auto-run mode is whitelisted.",
				entry, reason, verb,
			),
			Path:         doc.Path,
			Match:        entry,
			SuggestedFix: fmt.Sprintf("Replace `%s` with explicit, fully-specified commands you actually need.", entry),
			Tags:         []string{"cursor", "allowlist", verb},
		}))
	}
	return out
}

// --- cursor-mcp-wildcard ---------------------------------------------------
//
// Three wildcard shapes from the Cursor permissions reference:
//   - `*:*`           Critical (every tool from every server)
//   - `*:<tool>`      High     (any server claims this tool name)
//   - `<server>:*`    Medium   (all current+future tools from a server)

type cursorMCPWildcard struct{}

func (cursorMCPWildcard) ID() string                 { return "cursor-mcp-wildcard" }
func (cursorMCPWildcard) Title() string              { return "Cursor mcpAllowlist contains wildcard server" }
func (cursorMCPWildcard) Severity() finding.Severity { return finding.SeverityHigh }
func (cursorMCPWildcard) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (cursorMCPWildcard) Formats() []parse.Format    { return []parse.Format{parse.FormatCursorPermissions} }

func (cursorMCPWildcard) Apply(doc *parse.Document) []finding.Finding {
	if doc.CursorPermissions == nil || !doc.CursorPermissions.HasMCPAllowlist {
		return nil
	}
	var out []finding.Finding
	for _, entry := range doc.CursorPermissions.MCPAllowlist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		// `*:*` is the most-broad: any tool from any server.
		if entry == "*:*" {
			out = append(out, finding.New(finding.Args{
				RuleID:       "cursor-mcp-wildcard",
				Severity:     finding.SeverityCritical,
				Taxonomy:     finding.TaxEnforced,
				Title:        "Cursor mcpAllowlist contains *:*",
				Description:  "`mcpAllowlist: [\"*:*\"]` auto-approves every tool from every MCP server. New servers added later (including via cloned project .mcp.json) inherit auto-approval.",
				Path:         doc.Path,
				Match:        entry,
				SuggestedFix: "Replace with explicit `<server>:<tool>` entries for the tools you actually want auto-run.",
				Tags:         []string{"cursor", "mcp", "allowlist"},
			}))
			continue
		}

		// `*:<tool>` — any server can claim that tool name.
		if strings.HasPrefix(entry, "*:") {
			out = append(out, finding.New(finding.Args{
				RuleID:   "cursor-mcp-wildcard",
				Severity: finding.SeverityHigh,
				Taxonomy: finding.TaxDetectable,
				Title:    "Cursor mcpAllowlist auto-approves tool name from any server",
				Description: fmt.Sprintf(
					"`%s` lets any MCP server claim tool name `%s` and have it auto-run. A malicious server can register the same tool name and inherit the allowlist.",
					entry, strings.TrimPrefix(entry, "*:"),
				),
				Path:         doc.Path,
				Match:        entry,
				SuggestedFix: fmt.Sprintf("Bind to a specific server: `<server-name>:%s`.", strings.TrimPrefix(entry, "*:")),
				Tags:         []string{"cursor", "mcp", "allowlist"},
			}))
			continue
		}

		// `<server>:*` — all tools from a specific server. Less broad but
		// still surface as Medium inventory.
		if strings.HasSuffix(entry, ":*") {
			server := strings.TrimSuffix(entry, ":*")
			out = append(out, finding.New(finding.Args{
				RuleID:   "cursor-mcp-wildcard",
				Severity: finding.SeverityMedium,
				Taxonomy: finding.TaxAdvisory,
				Title:    fmt.Sprintf("Cursor mcpAllowlist permits all tools from %s", server),
				Description: fmt.Sprintf(
					"`%s` auto-approves every tool from server `%s`, including tools added in future server updates. Acceptable for fully-trusted servers; surface as inventory.",
					entry, server,
				),
				Path:         doc.Path,
				Match:        entry,
				SuggestedFix: fmt.Sprintf("Replace with explicit tool names: `%s:specific_tool_name`.", server),
				Tags:         []string{"cursor", "mcp", "allowlist", server},
			}))
		}
	}
	return out
}
