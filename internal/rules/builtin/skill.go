// Rules over skill markdown files (parse.FormatSkill — anything under
// `.claude/skills/<name>/SKILL.md`).
package builtin

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

// --- skill-shell-hijack ---------------------------------------------------

type skillShellHijack struct{}

func (skillShellHijack) ID() string                 { return "skill-shell-hijack" }
func (skillShellHijack) Title() string              { return "Skill markdown contains shell-hijack pattern" }
func (skillShellHijack) Severity() finding.Severity { return finding.SeverityHigh }
func (skillShellHijack) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (skillShellHijack) Formats() []parse.Format    { return []parse.Format{parse.FormatSkill} }

var shellHijackPatterns = []*regexp.Regexp{
	regexp.MustCompile(`curl\s+[^\n|]*\s*\|\s*(bash|sh|zsh)\b`),
	regexp.MustCompile(`wget\s+[^\n|]*\s*-O\s*-\s*\|\s*(bash|sh|zsh)\b`),
	regexp.MustCompile(`(?i)\beval\s+\$\(`),
	regexp.MustCompile(`base64\s+(-d|--decode)\b`),
}

func (skillShellHijack) Apply(doc *parse.Document) []finding.Finding {
	if doc.Skill == nil {
		return nil
	}
	var out []finding.Finding
	for _, pat := range shellHijackPatterns {
		if loc := pat.FindStringIndex(doc.Skill.Body); loc != nil {
			line := strings.Count(doc.Skill.Body[:loc[0]], "\n") + 1
			out = append(out, finding.New(finding.Args{
				RuleID:       "skill-shell-hijack",
				Severity:     finding.SeverityHigh,
				Taxonomy:     finding.TaxDetectable,
				Title:        "Skill contains shell-hijack pattern",
				Description:  fmt.Sprintf("Skill %q includes a shell pattern (curl|bash, eval, base64-decode) that can run arbitrary code outside the agent's tool allowlist.", doc.Skill.Name),
				Path:         doc.Path,
				Line:         line,
				Match:        doc.Skill.Body[loc[0]:loc[1]],
				SuggestedFix: "Replace inline curl|bash with explicit binary install steps or a vetted tool reference.",
				Tags:         []string{"skill", "shell"},
			}))
			// Stop at first hit per pattern to keep output readable.
			break
		}
	}
	return out
}

// --- skill-undeclared-dangerous-tool --------------------------------------

type skillUndeclaredDangerousTool struct{}

func (skillUndeclaredDangerousTool) ID() string                 { return "skill-undeclared-dangerous-tool" }
func (skillUndeclaredDangerousTool) Title() string              { return "Skill uses Bash/WebFetch without declaring it" }
func (skillUndeclaredDangerousTool) Severity() finding.Severity { return finding.SeverityMedium }
func (skillUndeclaredDangerousTool) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (skillUndeclaredDangerousTool) Formats() []parse.Format    { return []parse.Format{parse.FormatSkill} }

func (skillUndeclaredDangerousTool) Apply(doc *parse.Document) []finding.Finding {
	if doc.Skill == nil {
		return nil
	}
	declared := map[string]bool{}
	for _, t := range frontmatterToolList(doc.Skill) {
		declared[t] = true
	}
	dangerous := []string{"Bash", "WebFetch", "WebSearch"}
	var out []finding.Finding
	for _, tool := range dangerous {
		if !contains(doc.Skill.Tools, tool) {
			continue
		}
		if declared[tool] {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:       "skill-undeclared-dangerous-tool",
			Severity:     finding.SeverityMedium,
			Taxonomy:     finding.TaxDetectable,
			Title:        "Skill uses a dangerous tool without declaring it in frontmatter",
			Description:  fmt.Sprintf("Skill %q references %s in its body but did not list it in `allowed-tools` frontmatter. Implicit tool use bypasses the review surface CISOs rely on.", doc.Skill.Name, tool),
			Path:         doc.Path,
			Match:        tool,
			SuggestedFix: fmt.Sprintf("Add `allowed-tools: [%s, ...]` to the skill frontmatter, or remove the implicit reference.", tool),
			Tags:         []string{"skill", "tools"},
		}))
	}
	return out
}

// frontmatterToolList parses `allowed-tools` / `tools` from a skill's
// frontmatter into a flat slice. Comma- or space-separated entries.
func frontmatterToolList(s *parse.Skill) []string {
	if s == nil {
		return nil
	}
	v, ok := s.Frontmatter["allowed-tools"]
	if !ok {
		v = s.Frontmatter["tools"]
	}
	if v == "" {
		return nil
	}
	parts := strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '[' || r == ']'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.Trim(p, `"' `)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
