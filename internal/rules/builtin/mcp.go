// Rules over the normalized MCP server model. Each rule returns
// parse.AllMCPFormats() so it fires across .mcp.json (Cursor, project),
// ~/.codex/config.toml, and ~/.codeium/windsurf/mcp_config.json. The
// per-format parsers populate the model via parse.NormalizeMCPServers.
package builtin

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/agentguard/agentguard/internal/finding"
	"github.com/agentguard/agentguard/internal/parse"
)

// --- mcp-unpinned-npx ------------------------------------------------------

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
		// Look at args[0] (skipping "-y" / "--yes" / other flags) for an `@version` suffix.
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

// --- mcp-prod-secret-env --------------------------------------------------

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

// --- mcp-shell-pipeline-command -------------------------------------------

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

// --- mcp-plaintext-api-key -------------------------------------------------

type mcpPlaintextAPIKey struct{}

func (mcpPlaintextAPIKey) ID() string                 { return "mcp-plaintext-api-key" }
func (mcpPlaintextAPIKey) Title() string              { return "MCP server has plaintext API key" }
func (mcpPlaintextAPIKey) Severity() finding.Severity { return finding.SeverityCritical }
func (mcpPlaintextAPIKey) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (mcpPlaintextAPIKey) Formats() []parse.Format    { return parse.AllMCPFormats() }

func (mcpPlaintextAPIKey) Apply(doc *parse.Document) []finding.Finding {
	servers := parse.NormalizeMCPServers(doc)
	if len(servers) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, s := range servers {
		// Check both Env (process env) and Headers (remote auth headers).
		// Codex uses Headers; Cursor/Windsurf historically used Env, but
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

// --- mcp-dynamic-config-injection ------------------------------------------

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

// --- mcp-unauth-remote-url -------------------------------------------------

type mcpUnauthRemoteURL struct{}

func (mcpUnauthRemoteURL) ID() string                 { return "mcp-unauth-remote-url" }
func (mcpUnauthRemoteURL) Title() string              { return "MCP server uses remote URL without auth headers" }
func (mcpUnauthRemoteURL) Severity() finding.Severity { return finding.SeverityHigh }
func (mcpUnauthRemoteURL) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (mcpUnauthRemoteURL) Formats() []parse.Format    { return parse.AllMCPFormats() }

// authHeaderNames are header keys that, if present, satisfy the "auth was
// configured" check. Case-insensitive prefix match.
var authHeaderNames = []string{
	"authorization",
	"x-api-key",
	"x-auth-token",
	"x-access-token",
	"api-key",
	"token",
	"bearer",
	"cookie",
}

func hasAuthHeader(headers map[string]string) bool {
	for k := range headers {
		lk := strings.ToLower(k)
		for _, prefix := range authHeaderNames {
			if strings.HasPrefix(lk, prefix) {
				return true
			}
		}
		// Anything ending in _api_key, _token, etc. also counts. Reuse the
		// credentialNameSuffix matcher (it already encodes "this name looks
		// like an auth credential").
		if credentialNameSuffix.MatchString(k) {
			return true
		}
	}
	return false
}

func (mcpUnauthRemoteURL) Apply(doc *parse.Document) []finding.Finding {
	servers := parse.NormalizeMCPServers(doc)
	if len(servers) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, s := range servers {
		// Only applies to remote (URL-based) servers.
		if s.URL == "" {
			continue
		}
		// Skip localhost / 127.0.0.1 — local-only, different threat model.
		// 0.0.0.0 binding is its own (deferred) rule.
		lu := strings.ToLower(s.URL)
		if strings.Contains(lu, "://localhost") ||
			strings.Contains(lu, "://127.0.0.1") ||
			strings.Contains(lu, "://[::1]") {
			continue
		}
		if hasAuthHeader(s.Headers) {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:       "mcp-unauth-remote-url",
			Severity:     finding.SeverityHigh,
			Taxonomy:     finding.TaxDetectable,
			Title:        "MCP server points at remote URL without auth headers",
			Description: fmt.Sprintf(
				"Server %q (in %s) connects to %s with no Authorization, X-API-Key, or other auth-shaped header. Any party who controls the upstream service or sits on-path between the agent and the URL can act as the server, returning attacker-controlled tool definitions and tool outputs.",
				s.Name, s.Source, s.URL,
			),
			Path:         doc.Path,
			Line:         s.Line,
			Match:        s.URL,
			SuggestedFix: "Add an Authorization or X-API-Key header (sourced from a secret manager). If the upstream really has no auth, switch to a server that supports OAuth 2.1 or self-host inside your network.",
			Tags:         []string{"mcp", "remote", "auth"},
		}))
	}
	return out
}
