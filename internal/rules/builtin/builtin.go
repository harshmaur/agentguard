// Package builtin registers the v1 ruleset with the global rules registry.
//
// Import this package for side effects (`_ "...internal/rules/builtin"`)
// so init() registers every built-in rule with the registry.
package builtin

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/agentguard/agentguard/internal/finding"
	"github.com/agentguard/agentguard/internal/parse"
	"github.com/agentguard/agentguard/internal/rules"
)

func init() {
	for _, r := range builtins() {
		rules.Register(r)
	}
}

// builtins returns the v1 rule list. Rules are listed in design-doc order.
// New rules go at the bottom; do NOT renumber existing ones (rule IDs are
// the stable contract).
func builtins() []rules.Rule {
	return []rules.Rule{
		mcpUnpinnedNPX{},
		mcpProdSecretEnv{},
		mcpShellPipelineCommand{},
		mcpPlaintextAPIKey{},
		mcpDynamicConfigInjection{},
		skillShellHijack{},
		skillUndeclaredDangerousTool{},
		ghaWriteAllPermissions{},
		ghaSecretsInAgentStep{},
		shellrcSecretExport{},
		// v0.2 rules. Stable IDs added at the bottom of the list per the
		// CHANGELOG contract: existing IDs do not get renumbered.
		claudeHookShellRCE{},
		claudeSkipPermissionPrompt{},
		codexApprovalDisabled{},
		codexTrustHomeOrBroad{},
		// codex-mcp-plaintext-header-key (alpha.1) was subsumed by the
		// generalized mcp-plaintext-api-key in alpha.3. The Codex-specific
		// rule was removed; mcp-plaintext-api-key now fires across
		// FormatMCPConfig + FormatCodexConfig + FormatWindsurfMCP.
		// v0.2.0-alpha.2
		claudeMCPAutoApprove{},
		claudeBashAllowlistTooBroad{},
		claudeThirdPartyPluginEnabled{},
		// v0.2.0-alpha.3
		mcpUnauthRemoteURL{},
	}
}

// --- MCP server rules -------------------------------------------------------

type mcpUnpinnedNPX struct{}

func (mcpUnpinnedNPX) ID() string                 { return "mcp-unpinned-npx" }
func (mcpUnpinnedNPX) Title() string              { return "MCP server uses unpinned npx" }
func (mcpUnpinnedNPX) Severity() finding.Severity { return finding.SeverityHigh }
func (mcpUnpinnedNPX) Taxonomy() finding.Taxonomy { return finding.TaxEnforced }
func (mcpUnpinnedNPX) Formats() []parse.Format    { return parse.AllMCPFormats() }
func (mcpUnpinnedNPX) Apply(doc *parse.Document) []finding.Finding {
	servers := parse.NormalizeMCPServers(doc)
	if len(servers) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, s := range servers {
		if s.Command != "npx" {
			continue
		}
		// Look at args[0] (skipping "-y" / "--yes" if present) for an `@version` suffix.
		pkg := ""
		for _, a := range s.Args {
			if a == "-y" || a == "--yes" || strings.HasPrefix(a, "-") {
				continue
			}
			pkg = a
			break
		}
		if pkg == "" {
			continue
		}
		// Pinning rules:
		//   "name"                       -> unpinned (no @)
		//   "name@1.2.3"                 -> pinned (1 @, not at start)
		//   "@scope/name"                -> unpinned (scope only, no version)
		//   "@scope/name@1.2.3"          -> pinned (2 @s, starts with @)
		ats := strings.Count(pkg, "@")
		isPinned := false
		if !strings.HasPrefix(pkg, "@") && ats >= 1 {
			isPinned = true
		} else if strings.HasPrefix(pkg, "@") && ats >= 2 {
			isPinned = true
		}
		if isPinned {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:       "mcp-unpinned-npx",
			Severity:     finding.SeverityHigh,
			Taxonomy:     finding.TaxEnforced,
			Title:        "MCP server launched via unpinned npx",
			Description:  fmt.Sprintf("Server %q (in %s) runs `%s %s` without a pinned package version. The package can change between runs, exposing the agent to supply-chain risk.", s.Name, s.Source, s.Command, strings.Join(s.Args, " ")),
			Path:         doc.Path,
			Line:         s.Line,
			Match:        fmt.Sprintf("%s %s", s.Command, strings.Join(s.Args, " ")),
			SuggestedFix: "Pin the package version, e.g. `\"args\": [\"-y\", \"" + pkg + "@1.2.3\"]`.",
			Tags:         []string{"mcp", "supply-chain"},
		}))
	}
	return out
}

type mcpProdSecretEnv struct{}

func (mcpProdSecretEnv) ID() string                 { return "mcp-prod-secret-env" }
func (mcpProdSecretEnv) Title() string              { return "MCP server receives production secret env" }
func (mcpProdSecretEnv) Severity() finding.Severity { return finding.SeverityCritical }
func (mcpProdSecretEnv) Taxonomy() finding.Taxonomy { return finding.TaxEnforced }
func (mcpProdSecretEnv) Formats() []parse.Format    { return []parse.Format{parse.FormatMCPConfig} }

var prodEnvPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^PROD_`),
	regexp.MustCompile(`(?i)_PROD_`),
	regexp.MustCompile(`(?i)_PROD$`),
	regexp.MustCompile(`(?i)^AWS_PROD_`),
	regexp.MustCompile(`(?i)^STRIPE_LIVE_`),
	regexp.MustCompile(`(?i)_LIVE_`),
	regexp.MustCompile(`(?i)^PRODUCTION_`),
}

func (mcpProdSecretEnv) Apply(doc *parse.Document) []finding.Finding {
	if doc.MCPConfig == nil {
		return nil
	}
	var out []finding.Finding
	for _, s := range doc.MCPConfig.Servers {
		for k := range s.Env {
			for _, pat := range prodEnvPatterns {
				if pat.MatchString(k) {
					out = append(out, finding.New(finding.Args{
						RuleID:       "mcp-prod-secret-env",
						Severity:     finding.SeverityCritical,
						Taxonomy:     finding.TaxEnforced,
						Title:        "Production secret exposed to MCP server",
						Description:  fmt.Sprintf("Server %q receives env var %q whose name suggests a production credential. Agents with broad capability surface should never receive prod credentials.", s.Name, k),
						Path:         doc.Path,
						Line:         s.Line,
						Match:        fmt.Sprintf("%s=%s", k, s.Env[k]),
						SuggestedFix: "Use a read-only staging variant of the credential, or remove the env injection if the server doesn't need it.",
						Tags:         []string{"mcp", "secrets", "prod"},
					}))
					break
				}
			}
		}
	}
	return out
}

type mcpShellPipelineCommand struct{}

func (mcpShellPipelineCommand) ID() string                 { return "mcp-shell-pipeline-command" }
func (mcpShellPipelineCommand) Title() string              { return "MCP server uses shell pipeline as command" }
func (mcpShellPipelineCommand) Severity() finding.Severity { return finding.SeverityHigh }
func (mcpShellPipelineCommand) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (mcpShellPipelineCommand) Formats() []parse.Format    { return []parse.Format{parse.FormatMCPConfig} }
func (mcpShellPipelineCommand) Apply(doc *parse.Document) []finding.Finding {
	if doc.MCPConfig == nil {
		return nil
	}
	var out []finding.Finding
	for _, s := range doc.MCPConfig.Servers {
		joined := strings.ToLower(s.Command + " " + strings.Join(s.Args, " "))
		hit := false
		switch {
		case strings.Contains(s.Command, "bash") && containsAny(s.Args, "-c"):
			hit = true
		case strings.Contains(s.Command, "sh") && containsAny(s.Args, "-c"):
			hit = true
		case strings.Contains(joined, "|"):
			hit = true
		case strings.Contains(joined, "&&"), strings.Contains(joined, "||"):
			hit = true
		}
		if !hit {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:       "mcp-shell-pipeline-command",
			Severity:     finding.SeverityHigh,
			Taxonomy:     finding.TaxDetectable,
			Title:        "MCP server launched via shell pipeline",
			Description:  fmt.Sprintf("Server %q is launched through `bash -c` or a shell pipeline. This widens attack surface (arbitrary command injection) and bypasses argument-level review.", s.Name),
			Path:         doc.Path,
			Line:         s.Line,
			Match:        fmt.Sprintf("%s %s", s.Command, strings.Join(s.Args, " ")),
			SuggestedFix: "Invoke the server binary directly with explicit args. Avoid `bash -c` indirection.",
			Tags:         []string{"mcp", "shell", "injection"},
		}))
	}
	return out
}

type mcpPlaintextAPIKey struct{}

func (mcpPlaintextAPIKey) ID() string                 { return "mcp-plaintext-api-key" }
func (mcpPlaintextAPIKey) Title() string              { return "MCP server has plaintext API key" }
func (mcpPlaintextAPIKey) Severity() finding.Severity { return finding.SeverityCritical }
func (mcpPlaintextAPIKey) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (mcpPlaintextAPIKey) Formats() []parse.Format    { return parse.AllMCPFormats() }

var apiKeyValuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                            // AWS access key
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`),                  // GitHub token (classic, fine-grained, server-to-server)
	regexp.MustCompile(`(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}`),    // Stripe live/test, secret/restricted
	regexp.MustCompile(`sk-ant-[a-z][a-z0-9]{2,}-[A-Za-z0-9_\-]{32,}`), // Anthropic
	regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),                      // Google API
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),                // Slack
	// v0.1.4: extended set after a real Mac scan caught only 1 of 3
	// production tokens in .zprofile. Found in the wild on a CISO-style
	// dev machine but missed by the value-pattern set above.
	regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-\.]{20,}`),                // GitLab personal access token
	regexp.MustCompile(`\bglptt-[A-Za-z0-9_\-\.]{20,}`),                // GitLab project trigger token
	regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}`),                        // Hugging Face
	regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36,}`),                       // npm modern token
}

// credentialNameSuffix recognizes env var names that scream "I am a secret"
// even when the value's shape isn't a known credential prefix. The Mac scan
// surfaced FONTAWESOME_REGISTRY_AUTHTOKEN=<UUID> — the UUID alone is not a
// recognizable credential, but the env name's _AUTHTOKEN suffix makes the
// risk obvious. Trades up some false positives for catching the real prod
// secrets that don't fit a vendor prefix.
var credentialNameSuffix = regexp.MustCompile(
	`(?i)(?:^|_)(?:token|key|secret|password|passwd|auth|credential|credentials|pat|psk|apikey|authtoken)$`,
)

// valueLooksLikeSecret returns true for non-trivial values that could plausibly
// be a credential. Filters out things like "true", "info", short paths, etc.
// Requires length >= 16 AND at least 2 character classes (digits + letters,
// or mixed case). UUIDs satisfy this trivially.
func valueLooksLikeSecret(v string) bool {
	if len(v) < 16 {
		return false
	}
	hasDigit, hasLower, hasUpper := false, false, false
	for _, c := range v {
		switch {
		case '0' <= c && c <= '9':
			hasDigit = true
		case 'a' <= c && c <= 'z':
			hasLower = true
		case 'A' <= c && c <= 'Z':
			hasUpper = true
		}
	}
	classes := 0
	for _, b := range []bool{hasDigit, hasLower, hasUpper} {
		if b {
			classes++
		}
	}
	return classes >= 2
}

// matchesCredential checks both the value (against known credential prefix
// patterns) and the name (for credential-suggesting suffixes paired with a
// non-trivial value). Used by both the MCP env rule and the shellrc rule.
func matchesCredential(name, value string) bool {
	for _, pat := range apiKeyValuePatterns {
		if pat.MatchString(value) {
			return true
		}
	}
	if name != "" && credentialNameSuffix.MatchString(name) && valueLooksLikeSecret(value) {
		return true
	}
	return false
}

func (mcpPlaintextAPIKey) Apply(doc *parse.Document) []finding.Finding {
	servers := parse.NormalizeMCPServers(doc)
	if len(servers) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, s := range servers {
		// Check both Env (process env) and Headers (remote auth headers).
		// Codex uses Headers, Cursor/Windsurf historically used Env, but
		// modern Windsurf also uses Headers. The risk shape is identical.
		emit := func(loc, k, v string) {
			out = append(out, finding.New(finding.Args{
				RuleID:       "mcp-plaintext-api-key",
				Severity:     finding.SeverityCritical,
				Taxonomy:     finding.TaxDetectable,
				Title:        fmt.Sprintf("Plaintext API key in MCP server %s", loc),
				Description:  fmt.Sprintf("Server %q (in %s) has %s key %q whose value matches a known credential pattern. Plaintext credentials in version-controllable config files are a common breach vector.", s.Name, s.Source, loc, k),
				Path:         doc.Path,
				Line:         s.Line,
				Match:        fmt.Sprintf("%s=%s", k, v),
				SuggestedFix: "Reference the credential via a secret manager (e.g. `${KEYCHAIN:foo}`) or environment variable that's set at runtime, not in the JSON/TOML.",
				Tags:         []string{"mcp", "secrets"},
			}))
		}
		for k, v := range s.Env {
			if matchesCredential(k, v) {
				emit("env", k, v)
			}
		}
		for k, v := range s.Headers {
			if matchesCredential(k, v) {
				emit("headers", k, v)
			}
		}
	}
	return out
}

type mcpDynamicConfigInjection struct{}

func (mcpDynamicConfigInjection) ID() string                 { return "mcp-dynamic-config-injection" }
func (mcpDynamicConfigInjection) Title() string              { return "MCP config fetched from URL at runtime" }
func (mcpDynamicConfigInjection) Severity() finding.Severity { return finding.SeverityHigh }
func (mcpDynamicConfigInjection) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (mcpDynamicConfigInjection) Formats() []parse.Format    { return []parse.Format{parse.FormatMCPConfig} }
func (mcpDynamicConfigInjection) Apply(doc *parse.Document) []finding.Finding {
	if doc.MCPConfig == nil {
		return nil
	}
	var out []finding.Finding
	for _, s := range doc.MCPConfig.Servers {
		joined := s.Command + " " + strings.Join(s.Args, " ")
		if !strings.Contains(joined, "curl ") && !strings.Contains(joined, "wget ") {
			continue
		}
		// Heuristic: command runs `curl URL | sh` or similar.
		if strings.Contains(joined, "|") || strings.Contains(joined, "$(") {
			out = append(out, finding.New(finding.Args{
				RuleID:       "mcp-dynamic-config-injection",
				Severity:     finding.SeverityHigh,
				Taxonomy:     finding.TaxDetectable,
				Title:        "MCP server loads code from network at runtime",
				Description:  fmt.Sprintf("Server %q's command pipes a network fetch into the shell, meaning every launch may execute different code than was reviewed.", s.Name),
				Path:         doc.Path,
				Line:         s.Line,
				Match:        joined,
				SuggestedFix: "Pin the upstream artifact (commit SHA, signed tag, or vendored copy) and verify before launching.",
				Tags:         []string{"mcp", "supply-chain"},
			}))
		}
	}
	return out
}

// --- Skill rules ------------------------------------------------------------

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
				RuleID:      "skill-shell-hijack",
				Severity:    finding.SeverityHigh,
				Taxonomy:    finding.TaxDetectable,
				Title:       "Skill contains shell-hijack pattern",
				Description: fmt.Sprintf("Skill %q includes a shell pattern (curl|bash, eval, base64-decode) that can run arbitrary code outside the agent's tool allowlist.", doc.Skill.Name),
				Path:        doc.Path,
				Line:        line,
				Match:       doc.Skill.Body[loc[0]:loc[1]],
				SuggestedFix: "Replace inline curl|bash with explicit binary install steps or a vetted tool reference.",
				Tags:        []string{"skill", "shell"},
			}))
			// Stop at first hit per pattern to keep output readable.
			break
		}
	}
	return out
}

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
			RuleID:      "skill-undeclared-dangerous-tool",
			Severity:    finding.SeverityMedium,
			Taxonomy:    finding.TaxDetectable,
			Title:       "Skill uses a dangerous tool without declaring it in frontmatter",
			Description: fmt.Sprintf("Skill %q references %s in its body but did not list it in `allowed-tools` frontmatter. Implicit tool use bypasses the review surface CISOs rely on.", doc.Skill.Name, tool),
			Path:        doc.Path,
			Match:       tool,
			SuggestedFix: fmt.Sprintf("Add `allowed-tools: [%s, ...]` to the skill frontmatter, or remove the implicit reference.", tool),
			Tags:        []string{"skill", "tools"},
		}))
	}
	return out
}

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

// --- GitHub Actions rules ---------------------------------------------------

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
				RuleID:      "gha-write-all-permissions",
				Severity:    finding.SeverityHigh,
				Taxonomy:    finding.TaxEnforced,
				Title:       fmt.Sprintf("Workflow grants write-all permissions (%s)", scope),
				Description: fmt.Sprintf("`permissions: write-all` at %s grants the GITHUB_TOKEN maximum scope for the duration of the run. A compromised step has full repo write + secret read.", scope),
				Path:        doc.Path,
				Match:       "permissions: write-all",
				SuggestedFix: "Replace with the minimum required scopes (e.g. `permissions: { contents: read, pull-requests: write }`).",
				Tags:        []string{"gha", "least-privilege"},
			}))
		}
	}
	check("workflow level", doc.Workflow.Permissions)
	for jobName, j := range doc.Workflow.Jobs {
		check("job "+jobName, j.Permissions)
	}
	return out
}

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
					RuleID:      "gha-secrets-in-agent-step",
					Severity:    finding.SeverityHigh,
					Taxonomy:    finding.TaxDetectable,
					Title:       "Secret passed to step that invokes an AI coding agent",
					Description: fmt.Sprintf("Step in job %q invokes an agent (%s) and exposes %s via env. Agents with shell access plus secret access are a single misconfiguration away from leaking credentials.", jobName, strings.TrimSpace(step.Name+" "+step.Uses), k),
					Path:        doc.Path,
					Match:       fmt.Sprintf("%s: %s", k, v),
					SuggestedFix: "Pass only the minimal credential the agent needs, scoped to the operation. Avoid generic `GITHUB_TOKEN` exposure to autonomous code-changing agents.",
					Tags:        []string{"gha", "agent", "secrets"},
				}))
			}
		}
	}
	return out
}

// --- Shell rc rules ---------------------------------------------------------

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

// --- helpers ----------------------------------------------------------------

func containsAny(haystack []string, needles ...string) bool {
	for _, h := range haystack {
		for _, n := range needles {
			if h == n {
				return true
			}
		}
	}
	return false
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}
