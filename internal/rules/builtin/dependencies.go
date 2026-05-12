package builtin

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type agentPackageKnownVulnerable struct{}

type dependencyAdvisory struct {
	Ecosystem      string
	Package        string
	CVE            string
	Title          string
	Severity       finding.Severity
	FixedVersion   string
	LastVulnerable string
	ExactVersion   string
	MinVersion     string
	Tags           []string
}

func (agentPackageKnownVulnerable) ID() string { return "agent-package-known-vulnerable" }
func (agentPackageKnownVulnerable) Title() string {
	return "AI-agent package manifest declares a known vulnerable version"
}
func (agentPackageKnownVulnerable) Severity() finding.Severity { return finding.SeverityHigh }
func (agentPackageKnownVulnerable) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (agentPackageKnownVulnerable) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON, parse.FormatDependencyManifest}
}

func (agentPackageKnownVulnerable) Apply(doc *parse.Document) []finding.Finding {
	manifest := doc.DependencyManifest
	if manifest == nil {
		return nil
	}
	var out []finding.Finding
	for _, dep := range manifest.Dependencies {
		for _, advisory := range dependencyAdvisories {
			if !dependencyMatchesAdvisory(manifest.Ecosystem, dep, advisory) {
				continue
			}
			out = append(out, finding.New(finding.Args{
				RuleID:       "agent-package-known-vulnerable",
				Severity:     advisory.Severity,
				Taxonomy:     finding.TaxDetectable,
				Title:        advisory.Title,
				Description:  fmt.Sprintf("%s declares %s@%s, which matches %s in Audr's built-in AI-agent package advisory corpus.", manifest.Ecosystem, dep.Name, dep.Version, advisory.CVE),
				Path:         doc.Path,
				Line:         dep.Line,
				Match:        fmt.Sprintf("%s@%s", dep.Name, dep.Version),
				SuggestedFix: dependencySuggestedFix(advisory),
				Tags:         append([]string{"cve", "package-manifest", manifest.Ecosystem}, advisory.Tags...),
			}))
		}
	}
	return out
}

var dependencyAdvisories = []dependencyAdvisory{
	{
		Ecosystem: "pypi", Package: "praisonaiagents", CVE: "CVE-2026-41496",
		Title:    "praisonaiagents version is vulnerable to multi-backend conversation store SQL injection",
		Severity: finding.SeverityCritical, FixedVersion: "1.6.9",
		Tags: []string{"praisonai", "pypi", "sql-injection"},
	},
	{
		Ecosystem: "pypi", Package: "praisonai", CVE: "CVE-2026-41496",
		Title:    "praisonai version is vulnerable to multi-backend conversation store SQL injection",
		Severity: finding.SeverityCritical, FixedVersion: "4.6.9",
		Tags: []string{"praisonai", "pypi", "sql-injection"},
	},
	{
		Ecosystem: "pypi", Package: "praisonai", CVE: "CVE-2026-44336",
		Title:    "praisonai MCP server exposes unsafe file-handling tools by default",
		Severity: finding.SeverityHigh, FixedVersion: "4.6.34",
		Tags: []string{"praisonai", "mcp", "pypi", "file-access"},
	},
	{
		Ecosystem: "npm", Package: "@anthropic-ai/sdk", CVE: "CVE-2026-41686",
		Title:    "Anthropic TypeScript SDK local filesystem memory tool uses unsafe file modes",
		Severity: finding.SeverityHigh, MinVersion: "0.79.0", FixedVersion: "0.91.1",
		Tags: []string{"anthropic", "npm", "filesystem-permissions"},
	},
	{
		Ecosystem: "npm", Package: "xhs-mcp", CVE: "CVE-2026-7417",
		Title:    "xhs-mcp media_paths validation is vulnerable to SSRF",
		Severity: finding.SeverityHigh, ExactVersion: "0.8.11",
		Tags: []string{"mcp", "npm", "ssrf"},
	},
	{
		Ecosystem: "npm", Package: "directus-mcp", CVE: "CVE-2026-7729",
		Title:    "directus-mcp fileUrl validation is vulnerable to SSRF",
		Severity: finding.SeverityHigh, ExactVersion: "1.0.0",
		Tags: []string{"mcp", "npm", "ssrf"},
	},
	{
		Ecosystem: "npm", Package: "cloudbase-mcp", CVE: "CVE-2026-7221",
		Title:    "CloudBase-MCP openUrl tool is vulnerable to SSRF",
		Severity: finding.SeverityHigh, FixedVersion: "2.17.1",
		Tags: []string{"mcp", "npm", "ssrf"},
	},
	{
		Ecosystem: "npm", Package: "mcp-chat-studio", CVE: "CVE-2026-7147",
		Title:    "mcp-chat-studio LLM Models API base_url is vulnerable to SSRF",
		Severity: finding.SeverityHigh, LastVulnerable: "1.5.0",
		Tags: []string{"mcp", "npm", "ssrf"},
	},
	{
		Ecosystem: "npm", Package: "automagik-genie", CVE: "CVE-2026-30635",
		Title:    "automagik-genie MCP server transcript reader is vulnerable to command injection",
		Severity: finding.SeverityCritical, ExactVersion: "2.5.27",
		Tags: []string{"mcp", "npm", "command-injection"},
	},
}

func dependencyMatchesAdvisory(ecosystem string, dep parse.Dependency, advisory dependencyAdvisory) bool {
	if ecosystem != advisory.Ecosystem || normalizePackageName(ecosystem, dep.Name) != normalizePackageName(ecosystem, advisory.Package) {
		return false
	}
	version, ok := dependencyVersion(dep.Version)
	if !ok {
		return false
	}
	if advisory.MinVersion != "" && compareVersion(version, mustVersion(advisory.MinVersion)) < 0 {
		return false
	}
	if advisory.FixedVersion != "" {
		return compareVersion(version, mustVersion(advisory.FixedVersion)) < 0
	}
	if advisory.ExactVersion != "" {
		return compareVersion(version, mustVersion(advisory.ExactVersion)) == 0
	}
	if advisory.LastVulnerable != "" {
		return compareVersion(version, mustVersion(advisory.LastVulnerable)) <= 0
	}
	return false
}

func dependencySuggestedFix(advisory dependencyAdvisory) string {
	if advisory.FixedVersion != "" {
		return fmt.Sprintf("Upgrade %s to %s or later, then regenerate the lockfile. Advisory: %s.", advisory.Package, advisory.FixedVersion, advisory.CVE)
	}
	if advisory.ExactVersion != "" {
		return fmt.Sprintf("Upgrade %s away from vulnerable version %s and regenerate the lockfile. Advisory: %s.", advisory.Package, advisory.ExactVersion, advisory.CVE)
	}
	return fmt.Sprintf("Upgrade %s past %s and regenerate the lockfile. Advisory: %s.", advisory.Package, advisory.LastVulnerable, advisory.CVE)
}

func normalizePackageName(ecosystem, name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if ecosystem == "pypi" {
		name = strings.ReplaceAll(name, "_", "-")
	}
	return name
}

var versionNumberRE = regexp.MustCompile(`\d+(?:\.\d+){0,3}`)

func dependencyVersion(raw string) ([]int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, ">=") || strings.HasPrefix(raw, "git+") || strings.HasPrefix(raw, "http") || strings.HasPrefix(raw, "file:") {
		return nil, false
	}
	match := versionNumberRE.FindString(raw)
	if match == "" {
		return nil, false
	}
	return mustVersion(match), true
}

func mustVersion(raw string) []int {
	parts := strings.Split(versionNumberRE.FindString(raw), ".")
	out := make([]int, 4)
	for i := range out {
		if i >= len(parts) {
			break
		}
		n, _ := strconv.Atoi(parts[i])
		out[i] = n
	}
	return out
}

func compareVersion(a, b []int) int {
	for i := 0; i < 4; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}
