// Package builtin v0.2.0-alpha.3 rules. Operate on the normalized MCP model
// so they fire across Codex, Windsurf, and Cursor (.cursor/mcp.json).
package builtin

import (
	"fmt"
	"strings"

	"github.com/agentguard/agentguard/internal/finding"
	"github.com/agentguard/agentguard/internal/parse"
)

// --- mcp-unauth-remote-url -------------------------------------------------
//
// A remote MCP server is configured via a `url` field. Such servers expose
// the host's tools/resources to whatever's on the other end of the URL.
// If the config has no auth header (Headers is empty, or has no entry whose
// name suggests auth), every request goes to the upstream service
// unauthenticated — meaning the upstream can pretend to be anyone, and a
// MITM can do the same.
//
// Severity High. Trend Micro found 492 unauthenticated MCP servers exposed
// on the public internet; this is the client-side analog: agents pointing
// at remote servers without credentials.

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
		// v0.1.4 credentialNameSuffix matcher (it already encodes "this name
		// looks like an auth credential").
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
		// Skip localhost / 127.0.0.1 / 0.0.0.0:port — those are local-only
		// and have a different threat model (network exposure rule, not
		// remote-trust rule). Note: 0.0.0.0 is NOT really localhost, but
		// the right rule for "0.0.0.0 binding" is a different one.
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
