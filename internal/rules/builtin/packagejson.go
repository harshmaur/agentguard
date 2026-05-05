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
type openclawWebsocketUpgradeExhaustion struct{}
type openclawNodePairApproveScopeBypass struct{}
type openclawPluginAuthOperatorWriteBypass struct{}
type openclawTeamsWebhookPreauthBodyDos struct{}
type openclawBundledHooksEnvOverride struct{}
type openclawBundledPluginsEnvOverride struct{}

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

func (openclawWebsocketUpgradeExhaustion) ID() string { return "openclaw-websocket-upgrade-exhaustion" }
func (openclawWebsocketUpgradeExhaustion) Title() string {
	return "OpenClaw version is vulnerable to unauthenticated WebSocket upgrade exhaustion"
}
func (openclawWebsocketUpgradeExhaustion) Severity() finding.Severity { return finding.SeverityHigh }
func (openclawWebsocketUpgradeExhaustion) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (openclawWebsocketUpgradeExhaustion) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}

func (openclawNodePairApproveScopeBypass) ID() string {
	return "openclaw-node-pair-approve-scope-bypass"
}
func (openclawNodePairApproveScopeBypass) Title() string {
	return "OpenClaw version is vulnerable to node pairing approval scope bypass"
}
func (openclawNodePairApproveScopeBypass) Severity() finding.Severity { return finding.SeverityHigh }
func (openclawNodePairApproveScopeBypass) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (openclawNodePairApproveScopeBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}

func (openclawPluginAuthOperatorWriteBypass) ID() string {
	return "openclaw-plugin-auth-operator-write-bypass"
}
func (openclawPluginAuthOperatorWriteBypass) Title() string {
	return "OpenClaw version is vulnerable to plugin-auth operator write bypass"
}
func (openclawPluginAuthOperatorWriteBypass) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawPluginAuthOperatorWriteBypass) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawPluginAuthOperatorWriteBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}

func (openclawTeamsWebhookPreauthBodyDos) ID() string {
	return "openclaw-teams-webhook-preauth-body-dos"
}
func (openclawTeamsWebhookPreauthBodyDos) Title() string {
	return "OpenClaw version is vulnerable to MS Teams webhook pre-auth body parsing DoS"
}
func (openclawTeamsWebhookPreauthBodyDos) Severity() finding.Severity { return finding.SeverityHigh }
func (openclawTeamsWebhookPreauthBodyDos) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (openclawTeamsWebhookPreauthBodyDos) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}

func (openclawBundledHooksEnvOverride) ID() string {
	return "openclaw-bundled-hooks-env-override"
}
func (openclawBundledHooksEnvOverride) Title() string {
	return "OpenClaw workspace .env overrides bundled hook trust root"
}
func (openclawBundledHooksEnvOverride) Severity() finding.Severity { return finding.SeverityHigh }
func (openclawBundledHooksEnvOverride) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (openclawBundledHooksEnvOverride) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON, parse.FormatEnv}
}

func (openclawBundledPluginsEnvOverride) ID() string {
	return "openclaw-bundled-plugins-env-override"
}
func (openclawBundledPluginsEnvOverride) Title() string {
	return "OpenClaw workspace .env overrides bundled plugin trust root"
}
func (openclawBundledPluginsEnvOverride) Severity() finding.Severity { return finding.SeverityHigh }
func (openclawBundledPluginsEnvOverride) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (openclawBundledPluginsEnvOverride) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON, parse.FormatEnv}
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

func (openclawWebsocketUpgradeExhaustion) Apply(doc *parse.Document) []finding.Finding {
	if doc.PackageJSON == nil {
		return nil
	}
	pkg := doc.PackageJSON
	if pkg.Name == "openclaw" && vulnerableOpenClawWebsocketUpgradeVersion(pkg.Version) {
		return []finding.Finding{openclawWebsocketUpgradeFinding(doc.Path, fmt.Sprintf("openclaw@%s", pkg.Version))}
	}
	for _, deps := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies, pkg.PeerDependencies} {
		if v, ok := deps["openclaw"]; ok && vulnerableOpenClawWebsocketUpgradeVersion(v) {
			return []finding.Finding{openclawWebsocketUpgradeFinding(doc.Path, fmt.Sprintf("openclaw@%s", v))}
		}
	}
	return nil
}

func (openclawNodePairApproveScopeBypass) Apply(doc *parse.Document) []finding.Finding {
	if doc.PackageJSON == nil {
		return nil
	}
	pkg := doc.PackageJSON
	if pkg.Name == "openclaw" && vulnerableOpenClawNodePairApproveVersion(pkg.Version) {
		return []finding.Finding{openclawNodePairApproveFinding(doc.Path, fmt.Sprintf("openclaw@%s", pkg.Version))}
	}
	for _, deps := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies, pkg.PeerDependencies} {
		if v, ok := deps["openclaw"]; ok && vulnerableOpenClawNodePairApproveVersion(v) {
			return []finding.Finding{openclawNodePairApproveFinding(doc.Path, fmt.Sprintf("openclaw@%s", v))}
		}
	}
	return nil
}

func (openclawPluginAuthOperatorWriteBypass) Apply(doc *parse.Document) []finding.Finding {
	if doc.PackageJSON == nil {
		return nil
	}
	pkg := doc.PackageJSON
	if pkg.Name == "openclaw" && vulnerableOpenClawPluginAuthVersion(pkg.Version) {
		return []finding.Finding{openclawPluginAuthFinding(doc.Path, fmt.Sprintf("openclaw@%s", pkg.Version))}
	}
	for _, deps := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies, pkg.PeerDependencies} {
		if v, ok := deps["openclaw"]; ok && vulnerableOpenClawPluginAuthVersion(v) {
			return []finding.Finding{openclawPluginAuthFinding(doc.Path, fmt.Sprintf("openclaw@%s", v))}
		}
	}
	return nil
}

func (openclawTeamsWebhookPreauthBodyDos) Apply(doc *parse.Document) []finding.Finding {
	if doc.PackageJSON == nil {
		return nil
	}
	pkg := doc.PackageJSON
	if pkg.Name == "openclaw" && vulnerableOpenClawTeamsWebhookVersion(pkg.Version) {
		return []finding.Finding{openclawTeamsWebhookFinding(doc.Path, fmt.Sprintf("openclaw@%s", pkg.Version))}
	}
	for _, deps := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies, pkg.PeerDependencies} {
		if v, ok := deps["openclaw"]; ok && vulnerableOpenClawTeamsWebhookVersion(v) {
			return []finding.Finding{openclawTeamsWebhookFinding(doc.Path, fmt.Sprintf("openclaw@%s", v))}
		}
	}
	return nil
}

func (openclawBundledHooksEnvOverride) Apply(doc *parse.Document) []finding.Finding {
	if doc.Env != nil {
		if v, ok := doc.Env.Vars["OPENCLAW_BUNDLED_HOOKS_DIR"]; ok {
			f := openclawBundledHooksFinding(doc.Path, fmt.Sprintf("OPENCLAW_BUNDLED_HOOKS_DIR=%s", v))
			if line := doc.Env.Lines["OPENCLAW_BUNDLED_HOOKS_DIR"]; line > 0 {
				f.Line = line
			}
			return []finding.Finding{f}
		}
		return nil
	}
	if doc.PackageJSON == nil {
		return nil
	}
	pkg := doc.PackageJSON
	if pkg.Name == "openclaw" && vulnerableOpenClawBundledHooksVersion(pkg.Version) {
		return []finding.Finding{openclawBundledHooksFinding(doc.Path, fmt.Sprintf("openclaw@%s", pkg.Version))}
	}
	for _, deps := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies, pkg.PeerDependencies} {
		if v, ok := deps["openclaw"]; ok && vulnerableOpenClawBundledHooksVersion(v) {
			return []finding.Finding{openclawBundledHooksFinding(doc.Path, fmt.Sprintf("openclaw@%s", v))}
		}
	}
	return nil
}

func (openclawBundledPluginsEnvOverride) Apply(doc *parse.Document) []finding.Finding {
	if doc.Env != nil {
		if v, ok := doc.Env.Vars["OPENCLAW_BUNDLED_PLUGINS_DIR"]; ok {
			f := openclawBundledPluginsFinding(doc.Path, fmt.Sprintf("OPENCLAW_BUNDLED_PLUGINS_DIR=%s", v))
			if line := doc.Env.Lines["OPENCLAW_BUNDLED_PLUGINS_DIR"]; line > 0 {
				f.Line = line
			}
			return []finding.Finding{f}
		}
		return nil
	}
	if doc.PackageJSON == nil {
		return nil
	}
	pkg := doc.PackageJSON
	if pkg.Name == "openclaw" && vulnerableOpenClawBundledPluginsVersion(pkg.Version) {
		return []finding.Finding{openclawBundledPluginsFinding(doc.Path, fmt.Sprintf("openclaw@%s", pkg.Version))}
	}
	for _, deps := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies, pkg.PeerDependencies} {
		if v, ok := deps["openclaw"]; ok && vulnerableOpenClawBundledPluginsVersion(v) {
			return []finding.Finding{openclawBundledPluginsFinding(doc.Path, fmt.Sprintf("openclaw@%s", v))}
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

func openclawWebsocketUpgradeFinding(path, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "openclaw-websocket-upgrade-exhaustion",
		Severity:     finding.SeverityHigh,
		Taxonomy:     finding.TaxDetectable,
		Title:        "OpenClaw before 2026.3.28 has unbounded unauthenticated WebSocket upgrades",
		Description:  "CVE-2026-41399: OpenClaw before 2026.3.28 accepts unbounded concurrent unauthenticated WebSocket upgrades without pre-authentication budget allocation, letting unauthenticated clients exhaust socket and worker capacity.",
		Path:         path,
		Match:        match,
		SuggestedFix: "Upgrade OpenClaw to 2026.3.28 or later and review WebSocket exposure on affected hosts.",
		Tags:         []string{"cve", "openclaw", "package-json", "resource-exhaustion"},
	})
}

func openclawNodePairApproveFinding(path, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "openclaw-node-pair-approve-scope-bypass",
		Severity:     finding.SeverityHigh,
		Taxonomy:     finding.TaxDetectable,
		Title:        "OpenClaw before 2026.4.8 lets operator.write approve node pairing",
		Description:  "CVE-2026-42426: OpenClaw before 2026.4.8 accepts broad operator.write scope for node.pair.approve instead of requiring operator.pairing, letting write-scoped operators approve exec-capable node pairing.",
		Path:         path,
		Match:        match,
		SuggestedFix: "Upgrade OpenClaw to 2026.4.8 or later and review paired node approvals issued by vulnerable versions.",
		Tags:         []string{"cve", "openclaw", "package-json", "privilege-escalation"},
	})
}

func openclawPluginAuthFinding(path, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "openclaw-plugin-auth-operator-write-bypass",
		Severity:     finding.SeverityHigh,
		Taxonomy:     finding.TaxDetectable,
		Title:        "OpenClaw before 2026.3.31 exposes plugin-auth routes with operator write scope",
		Description:  "CVE-2026-41394: OpenClaw before 2026.3.31 grants unauthenticated plugin-auth HTTP routes operator runtime write scopes, letting plugin-auth callers perform privileged runtime actions.",
		Path:         path,
		Match:        match,
		SuggestedFix: "Upgrade OpenClaw to 2026.3.31 or later and review plugin-auth route exposure on affected hosts.",
		Tags:         []string{"cve", "openclaw", "package-json", "auth-bypass"},
	})
}

func openclawTeamsWebhookFinding(path, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "openclaw-teams-webhook-preauth-body-dos",
		Severity:     finding.SeverityHigh,
		Taxonomy:     finding.TaxDetectable,
		Title:        "OpenClaw before 2026.3.31 parses MS Teams webhook bodies before JWT validation",
		Description:  "CVE-2026-41405: OpenClaw before 2026.3.31 parses MS Teams webhook request bodies before JWT validation, letting unauthenticated webhook traffic spend server CPU and memory before authentication.",
		Path:         path,
		Match:        match,
		SuggestedFix: "Upgrade OpenClaw to 2026.3.31 or later and review exposed MS Teams webhook integrations on affected hosts.",
		Tags:         []string{"cve", "openclaw", "package-json", "resource-exhaustion"},
	})
}

func openclawBundledHooksFinding(path, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "openclaw-bundled-hooks-env-override",
		Severity:     finding.SeverityHigh,
		Taxonomy:     finding.TaxDetectable,
		Title:        "OpenClaw workspace .env can override bundled hooks directory",
		Description:  "CVE-2026-41336: OpenClaw before 2026.3.31 lets workspace .env files override OPENCLAW_BUNDLED_HOOKS_DIR, replacing trusted default-on bundled hooks with attacker-controlled hook code.",
		Path:         path,
		Match:        match,
		SuggestedFix: "Upgrade OpenClaw to 2026.3.31 or later and remove OPENCLAW_BUNDLED_HOOKS_DIR from workspace .env files unless the hook trust root is explicitly intended.",
		Tags:         []string{"cve", "openclaw", "env", "untrusted-search-path"},
	})
}

func openclawBundledPluginsFinding(path, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "openclaw-bundled-plugins-env-override",
		Severity:     finding.SeverityHigh,
		Taxonomy:     finding.TaxDetectable,
		Title:        "OpenClaw before 2026.3.31 lets workspace .env redirect bundled plugins",
		Description:  "CVE-2026-41396: OpenClaw before 2026.3.31 lets workspace .env files override OPENCLAW_BUNDLED_PLUGINS_DIR, redirecting the trusted bundled plugin root to attacker-controlled plugin code.",
		Path:         path,
		Match:        match,
		SuggestedFix: "Upgrade OpenClaw to 2026.3.31 or later and remove OPENCLAW_BUNDLED_PLUGINS_DIR from workspace .env files unless the plugin trust root is explicitly intended.",
		Tags:         []string{"cve", "openclaw", "env", "untrusted-search-path"},
	})
}

var packageVersionRE = regexp.MustCompile(`\d+(?:\.\d+){0,2}`)

func vulnerableOpenClawVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 3, 22})
}

func vulnerableOpenClawConfigPatchVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 3, 28})
}

func vulnerableOpenClawWebsocketUpgradeVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 3, 28})
}

func vulnerableOpenClawNodePairApproveVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 4, 8})
}

func vulnerableOpenClawPluginAuthVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 3, 31})
}

func vulnerableOpenClawTeamsWebhookVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 3, 31})
}

func vulnerableOpenClawBundledHooksVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 3, 31})
}

func vulnerableOpenClawBundledPluginsVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 3, 31})
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
