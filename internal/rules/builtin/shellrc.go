// Rules over shell rc files (.bashrc, .zshrc, .zprofile, .profile).
package builtin

import (
	"fmt"

	"github.com/agentguard/agentguard/internal/finding"
	"github.com/agentguard/agentguard/internal/parse"
)

// --- shellrc-secret-export ------------------------------------------------
//
// Walks every `export KEY=VALUE` and tests via matchesCredential (helpers.go).
// v0.1.4 extended to catch GitLab PATs, HF tokens, npm tokens, and UUID-shaped
// values bound to credential-suggesting env names. The Mac scan caught
// KASEYA_GITHUB_REGISTRY_TOKEN, SA_GITLAB_REGISTRY_TOKEN,
// FONTAWESOME_REGISTRY_AUTHTOKEN as a result.

type shellrcSecretExport struct{}

func (shellrcSecretExport) ID() string                 { return "shellrc-secret-export" }
func (shellrcSecretExport) Title() string              { return "Shell rc exports a credential-shaped value" }
func (shellrcSecretExport) Severity() finding.Severity { return finding.SeverityHigh }
func (shellrcSecretExport) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (shellrcSecretExport) Formats() []parse.Format    { return []parse.Format{parse.FormatShellRC} }

func (shellrcSecretExport) Apply(doc *parse.Document) []finding.Finding {
	if doc.ShellRC == nil {
		return nil
	}
	var out []finding.Finding
	for k, v := range doc.ShellRC.EnvVars {
		if !matchesCredential(k, v) {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:       "shellrc-secret-export",
			Severity:     finding.SeverityHigh,
			Taxonomy:     finding.TaxDetectable,
			Title:        "Credential exported in shell rc",
			Description:  fmt.Sprintf("`%s` exports %s with a value matching a known credential pattern. Any agent or process inheriting the user's shell environment receives this credential.", doc.Path, k),
			Path:         doc.Path,
			Line:         doc.ShellRC.EnvVarLines[k],
			Match:        fmt.Sprintf("%s=%s", k, v),
			SuggestedFix: "Move the credential to a secret manager (1Password CLI, gopass, macOS Keychain) and source it on demand.",
			Tags:         []string{"shellrc", "secrets"},
		}))
	}
	return out
}
