package builtin

import (
	"fmt"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type mcpCalculateServerEvalRCE struct{}

func (mcpCalculateServerEvalRCE) ID() string { return "mcp-calculate-server-eval-rce" }
func (mcpCalculateServerEvalRCE) Title() string {
	return "MCP Calculate Server version is vulnerable to eval-based remote code execution"
}
func (mcpCalculateServerEvalRCE) Severity() finding.Severity { return finding.SeverityCritical }
func (mcpCalculateServerEvalRCE) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (mcpCalculateServerEvalRCE) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}

func (mcpCalculateServerEvalRCE) Apply(doc *parse.Document) []finding.Finding {
	if doc.DependencyManifest == nil {
		return nil
	}
	for _, dep := range doc.DependencyManifest.Dependencies {
		if isMCPCalculateServerPackage(dep.Name) && vulnerableMCPCalculateServerVersion(dep.Version) {
			return []finding.Finding{mcpCalculateServerEvalRCEFinding(doc.Path, dep.Line, fmt.Sprintf("%s@%s", dep.Name, dep.Version))}
		}
	}
	return nil
}

func isMCPCalculateServerPackage(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.ReplaceAll(n, "_", "-")
	return n == "mcp-calcualte-server" || n == "mcp-calculate-server"
}

func vulnerableMCPCalculateServerVersion(raw string) bool {
	return vulnerableVersionBefore(raw, []int{0, 1, 1})
}

func vulnerableVersionBefore(raw string, fixed []int) bool {
	v := strings.TrimSpace(raw)
	if v == "" || strings.ContainsAny(v, "*xX") || strings.HasPrefix(v, "git+") || strings.HasPrefix(v, "file:") || strings.HasPrefix(v, "workspace:") {
		return false
	}
	m := packageVersionRE.FindString(v)
	if m == "" {
		return false
	}
	cmp := compareVersionParts(m, fixed)
	if strings.HasPrefix(v, "<") {
		return cmp <= 0
	}
	return cmp < 0
}

func compareVersionParts(raw string, fixed []int) int {
	parts := strings.Split(raw, ".")
	for len(parts) < len(fixed) {
		parts = append(parts, "0")
	}
	for i := range fixed {
		got, ok := atoiSmall(parts[i])
		if !ok {
			return 1
		}
		if got < fixed[i] {
			return -1
		}
		if got > fixed[i] {
			return 1
		}
	}
	return 0
}

func atoiSmall(s string) (int, bool) {
	n := 0
	if s == "" {
		return 0, false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

func mcpCalculateServerEvalRCEFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "mcp-calculate-server-eval-rce",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "MCP Calculate Server before 0.1.1 evaluates tool input with Python eval",
		Description:  "CVE-2026-44717: MCP Calculate Server before 0.1.1 used eval() for mathematical expressions exposed through an MCP tool, allowing unauthenticated remote code execution when the server is reachable by an agent client.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Upgrade mcp-calcualte-server / mcp-calculate-server to 0.1.1 or later, then review MCP clients that exposed the calculate server to untrusted prompts or remote users.",
		Tags:         []string{"cve", "mcp", "pypi", "dependency-manifest", "code-injection"},
	})
}
