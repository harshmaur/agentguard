// Rules over GitHub Actions workflow files (.github/workflows/*.yml).
package builtin

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/agentguard/agentguard/internal/finding"
	"github.com/agentguard/agentguard/internal/parse"
)

// --- gha-write-all-permissions --------------------------------------------

type ghaWriteAllPermissions struct{}

func (ghaWriteAllPermissions) ID() string                 { return "gha-write-all-permissions" }
func (ghaWriteAllPermissions) Title() string              { return "GitHub Actions job grants write-all permissions" }
func (ghaWriteAllPermissions) Severity() finding.Severity { return finding.SeverityHigh }
func (ghaWriteAllPermissions) Taxonomy() finding.Taxonomy { return finding.TaxEnforced }
func (ghaWriteAllPermissions) Formats() []parse.Format    { return []parse.Format{parse.FormatGHAWorkflow} }

func (ghaWriteAllPermissions) Apply(doc *parse.Document) []finding.Finding {
	if doc.Workflow == nil {
		return nil
	}
	var out []finding.Finding
	check := func(scope string, perms map[string]string) {
		if perms == nil {
			return
		}
		// "permissions: write-all" comes through stringMap as {"_": "write-all"}.
		if perms["_"] == "write-all" {
			out = append(out, finding.New(finding.Args{
				RuleID:       "gha-write-all-permissions",
				Severity:     finding.SeverityHigh,
				Taxonomy:     finding.TaxEnforced,
				Title:        fmt.Sprintf("Workflow grants write-all permissions (%s)", scope),
				Description:  fmt.Sprintf("`permissions: write-all` at %s grants the GITHUB_TOKEN maximum scope for the duration of the run. A compromised step has full repo write + secret read.", scope),
				Path:         doc.Path,
				Match:        "permissions: write-all",
				SuggestedFix: "Replace with the minimum required scopes (e.g. `permissions: { contents: read, pull-requests: write }`).",
				Tags:         []string{"gha", "least-privilege"},
			}))
		}
	}
	check("workflow level", doc.Workflow.Permissions)
	for jobName, j := range doc.Workflow.Jobs {
		check("job "+jobName, j.Permissions)
	}
	return out
}

// --- gha-secrets-in-agent-step --------------------------------------------

type ghaSecretsInAgentStep struct{}

func (ghaSecretsInAgentStep) ID() string                 { return "gha-secrets-in-agent-step" }
func (ghaSecretsInAgentStep) Title() string              { return "GHA step exposes secrets to an agent invocation" }
func (ghaSecretsInAgentStep) Severity() finding.Severity { return finding.SeverityHigh }
func (ghaSecretsInAgentStep) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (ghaSecretsInAgentStep) Formats() []parse.Format    { return []parse.Format{parse.FormatGHAWorkflow} }

var agentInvocationPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b(claude|cursor|aider|cody|codex|crush|hermes|continue)\b`),
	regexp.MustCompile(`anthropics?/claude`),
	regexp.MustCompile(`anthropic-ai/`),
}

func (ghaSecretsInAgentStep) Apply(doc *parse.Document) []finding.Finding {
	if doc.Workflow == nil {
		return nil
	}
	var out []finding.Finding
	for jobName, job := range doc.Workflow.Jobs {
		for _, step := range job.Steps {
			invokesAgent := false
			lower := strings.ToLower(step.Name + " " + step.Uses + " " + step.Run)
			for _, pat := range agentInvocationPatterns {
				if pat.MatchString(lower) {
					invokesAgent = true
					break
				}
			}
			if !invokesAgent {
				continue
			}
			// Look for secrets.* references in env.
			for k, v := range step.Env {
				if !strings.Contains(v, "secrets.") {
					continue
				}
				out = append(out, finding.New(finding.Args{
					RuleID:       "gha-secrets-in-agent-step",
					Severity:     finding.SeverityHigh,
					Taxonomy:     finding.TaxDetectable,
					Title:        "Secret passed to step that invokes an AI coding agent",
					Description:  fmt.Sprintf("Step in job %q invokes an agent (%s) and exposes %s via env. Agents with shell access plus secret access are a single misconfiguration away from leaking credentials.", jobName, strings.TrimSpace(step.Name+" "+step.Uses), k),
					Path:         doc.Path,
					Match:        fmt.Sprintf("%s: %s", k, v),
					SuggestedFix: "Pass only the minimal credential the agent needs, scoped to the operation. Avoid generic `GITHUB_TOKEN` exposure to autonomous code-changing agents.",
					Tags:         []string{"gha", "agent", "secrets"},
				}))
			}
		}
	}
	return out
}
