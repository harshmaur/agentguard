package parse

import (
	"encoding/json"
	"fmt"
)

// parseWindsurfMCP parses ~/.codeium/windsurf/mcp_config.json. Shape is
// similar to Cursor's mcp.json but allows additional fields (`alwaysAllow`,
// `disabled`, `headers`) per the Windsurf docs.
func parseWindsurfMCP(raw []byte) (*WindsurfMCP, error) {
	var top struct {
		MCPServers map[string]struct {
			Type        string            `json:"type"`
			URL         string            `json:"url"`
			ServerURL   string            `json:"serverUrl"` // alternate spelling seen in real configs
			Command     string            `json:"command"`
			Args        []string          `json:"args"`
			Env         map[string]string `json:"env"`
			Headers     map[string]string `json:"headers"`
			AlwaysAllow []string          `json:"alwaysAllow"`
			Disabled    bool              `json:"disabled"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("windsurf-mcp parse: %w", err)
	}
	w := &WindsurfMCP{}
	rawStr := string(raw)
	for name, s := range top.MCPServers {
		url := s.URL
		if url == "" {
			url = s.ServerURL
		}
		w.Servers = append(w.Servers, WindsurfMCPServer{
			Name:        name,
			Type:        s.Type,
			URL:         url,
			Command:     s.Command,
			Args:        s.Args,
			Env:         s.Env,
			Headers:     s.Headers,
			AlwaysAllow: s.AlwaysAllow,
			Disabled:    s.Disabled,
			Line:        findKeyLine(rawStr, name),
		})
	}
	return w, nil
}
