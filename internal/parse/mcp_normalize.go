package parse

// NormalizeMCPServers returns the document's MCP server entries in a
// uniform shape regardless of source format. Rules that operate on
// "any MCP server" iterate over this slice instead of the format-specific
// typed fields.
//
// Returns nil for documents that don't contain MCP servers.
func NormalizeMCPServers(doc *Document) []NormalizedMCPServer {
	if doc == nil {
		return nil
	}
	switch doc.Format {
	case FormatMCPConfig:
		if doc.MCPConfig == nil {
			return nil
		}
		out := make([]NormalizedMCPServer, 0, len(doc.MCPConfig.Servers))
		for _, s := range doc.MCPConfig.Servers {
			out = append(out, NormalizedMCPServer{
				Name:    s.Name,
				Source:  FormatMCPConfig,
				Command: s.Command,
				Args:    s.Args,
				Env:     s.Env,
				URL:     s.URL,
				Line:    s.Line,
			})
		}
		return out
	case FormatCodexConfig:
		if doc.CodexConfig == nil {
			return nil
		}
		out := make([]NormalizedMCPServer, 0, len(doc.CodexConfig.MCPServers))
		for _, s := range doc.CodexConfig.MCPServers {
			disabled := false
			if s.Enabled != nil {
				disabled = !*s.Enabled
			}
			out = append(out, NormalizedMCPServer{
				Name:     s.Name,
				Source:   FormatCodexConfig,
				Command:  s.Command,
				Args:     s.Args,
				Env:      s.Env,
				URL:      s.URL,
				Headers:  s.HTTPHeaders,
				Disabled: disabled,
				Line:     s.Line,
			})
		}
		return out
	case FormatWindsurfMCP:
		if doc.WindsurfMCP == nil {
			return nil
		}
		out := make([]NormalizedMCPServer, 0, len(doc.WindsurfMCP.Servers))
		for _, s := range doc.WindsurfMCP.Servers {
			out = append(out, NormalizedMCPServer{
				Name:        s.Name,
				Source:      FormatWindsurfMCP,
				Command:     s.Command,
				Args:        s.Args,
				Env:         s.Env,
				URL:         s.URL,
				Headers:     s.Headers,
				AlwaysAllow: s.AlwaysAllow,
				Disabled:    s.Disabled,
				Line:        s.Line,
			})
		}
		return out
	}
	return nil
}

// AllMCPFormats returns every Format that NormalizeMCPServers knows how to
// extract servers from. Rules that target "any MCP source" use this for
// their Formats() declaration.
func AllMCPFormats() []Format {
	return []Format{FormatMCPConfig, FormatCodexConfig, FormatWindsurfMCP}
}
