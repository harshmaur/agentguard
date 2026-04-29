package builtin

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type openclawUnboundBootstrapSetupCode struct{}

func (openclawUnboundBootstrapSetupCode) ID() string { return "openclaw-unbound-bootstrap-setup-code" }
func (openclawUnboundBootstrapSetupCode) Title() string {
	return "OpenClaw version is vulnerable to unbound bootstrap setup codes"
}
func (openclawUnboundBootstrapSetupCode) Severity() finding.Severity { return finding.SeverityCritical }
func (openclawUnboundBootstrapSetupCode) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (openclawUnboundBootstrapSetupCode) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}

func (openclawUnboundBootstrapSetupCode) Apply(doc *parse.Document) []finding.Finding {
	if doc.PackageJSON == nil {
		return nil
	}
	pkg := doc.PackageJSON
	if pkg.Name == "openclaw" && vulnerableOpenClawVersion(pkg.Version) {
		return []finding.Finding{openclawBootstrapFinding(doc.Path, fmt.Sprintf("openclaw@%s", pkg.Version))}
	}
	for _, deps := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies, pkg.PeerDependencies} {
		if v, ok := deps["openclaw"]; ok && vulnerableOpenClawVersion(v) {
			return []finding.Finding{openclawBootstrapFinding(doc.Path, fmt.Sprintf("openclaw@%s", v))}
		}
	}
	return nil
}

func openclawBootstrapFinding(path, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "openclaw-unbound-bootstrap-setup-code",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "OpenClaw before 2026.3.22 has unbound bootstrap setup codes",
		Description:  "CVE-2026-41386: OpenClaw bootstrap setup codes before 2026.3.22 are not bound to intended device roles and scopes during pairing, letting setup codes mint broader privileges than intended.",
		Path:         path,
		Match:        match,
		SuggestedFix: "Upgrade OpenClaw to 2026.3.22 or later and rotate any bootstrap setup codes issued by vulnerable versions.",
		Tags:         []string{"cve", "openclaw", "package-json", "privilege-escalation"},
	})
}

var packageVersionRE = regexp.MustCompile(`\d+(?:\.\d+){0,2}`)

func vulnerableOpenClawVersion(raw string) bool {
	v := strings.TrimSpace(raw)
	if v == "" || strings.ContainsAny(v, "*xX") || strings.HasPrefix(v, "git+") || strings.HasPrefix(v, "file:") || strings.HasPrefix(v, "workspace:") {
		return false
	}
	m := packageVersionRE.FindString(v)
	if m == "" {
		return false
	}
	parts := strings.Split(m, ".")
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	got := make([]int, 3)
	for i := range got {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return false
		}
		got[i] = n
	}
	fixed := []int{2026, 3, 22}
	for i := range fixed {
		if got[i] < fixed[i] {
			return true
		}
		if got[i] > fixed[i] {
			return false
		}
	}
	return false
}
