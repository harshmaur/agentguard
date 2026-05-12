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
