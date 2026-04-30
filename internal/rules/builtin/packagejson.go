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

type openclawConfigPatchConsentBypass struct{}

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

func (openclawConfigPatchConsentBypass) ID() string { return "openclaw-config-patch-consent-bypass" }
func (openclawConfigPatchConsentBypass) Title() string {
	return "OpenClaw version is vulnerable to config.patch consent bypass"
}
func (openclawConfigPatchConsentBypass) Severity() finding.Severity { return finding.SeverityHigh }
func (openclawConfigPatchConsentBypass) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (openclawConfigPatchConsentBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}

func (openclawConfigPatchConsentBypass) Apply(doc *parse.Document) []finding.Finding {
	if doc.PackageJSON == nil {
		return nil
	}
	pkg := doc.PackageJSON
	if pkg.Name == "openclaw" && vulnerableOpenClawConfigPatchVersion(pkg.Version) {
		return []finding.Finding{openclawConfigPatchFinding(doc.Path, fmt.Sprintf("openclaw@%s", pkg.Version))}
	}
	for _, deps := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies, pkg.PeerDependencies} {
		if v, ok := deps["openclaw"]; ok && vulnerableOpenClawConfigPatchVersion(v) {
			return []finding.Finding{openclawConfigPatchFinding(doc.Path, fmt.Sprintf("openclaw@%s", v))}
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

func openclawConfigPatchFinding(path, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "openclaw-config-patch-consent-bypass",
		Severity:     finding.SeverityHigh,
		Taxonomy:     finding.TaxDetectable,
		Title:        "OpenClaw before 2026.3.28 lets config.patch disable execution approval",
		Description:  "CVE-2026-41349: OpenClaw before 2026.3.28 lets config.patch silently disable execution approval, bypassing consent before host operations run.",
		Path:         path,
		Match:        match,
		SuggestedFix: "Upgrade OpenClaw to 2026.3.28 or later and review execution approval settings on affected hosts.",
		Tags:         []string{"cve", "openclaw", "package-json", "consent-bypass"},
	})
}

var packageVersionRE = regexp.MustCompile(`\d+(?:\.\d+){0,2}`)

func vulnerableOpenClawVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 3, 22})
}

func vulnerableOpenClawConfigPatchVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 3, 28})
}

func vulnerableOpenClawVersionBefore(raw string, fixed []int) bool {
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
