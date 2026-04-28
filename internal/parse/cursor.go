package parse

import (
	"encoding/json"
	"fmt"
)

// parseCursorPermissions parses ~/.cursor/permissions.json. Both top-level
// fields are optional; either may be missing. We track presence (Has*) so
// rules can distinguish "user explicitly set an empty allowlist" (effectively
// disables auto-run) from "key not in file" (falls back to IDE settings).
func parseCursorPermissions(raw []byte) (*CursorPermissions, error) {
	var top struct {
		MCPAllowlist      *[]string `json:"mcpAllowlist"`
		TerminalAllowlist *[]string `json:"terminalAllowlist"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("cursor-permissions parse: %w", err)
	}
	c := &CursorPermissions{}
	if top.MCPAllowlist != nil {
		c.HasMCPAllowlist = true
		c.MCPAllowlist = *top.MCPAllowlist
	}
	if top.TerminalAllowlist != nil {
		c.HasTerminalAllowlist = true
		c.TerminalAllowlist = *top.TerminalAllowlist
	}
	return c, nil
}
