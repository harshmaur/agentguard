package parse

import (
	"strings"

	"github.com/BurntSushi/toml"
)

// parseCodexConfig parses ~/.codex/config.toml into a CodexConfig. The
// schema is documented at https://developers.openai.com/codex/config-reference.
//
// We only extract fields the v0.2 ruleset acts on:
//   - approval_policy
//   - sandbox_mode
//   - [projects."<path>"] trust_level
//   - [mcp_servers.<name>] command/args/env/url
//   - [mcp_servers.<name>.http_headers] (where plaintext API keys live)
//
// Fields like `model`, `personality`, `features.*`, `notice.*`, `plugins.*`
// are skipped — they're not security-relevant.
func parseCodexConfig(raw []byte) (*CodexConfig, error) {
	// We use the TOML metadata API to walk the parsed tree — config.toml
	// has nested table syntax (`[projects."<path>"]`, `[mcp_servers.<name>]`,
	// `[mcp_servers.<name>.http_headers]`) that doesn't map cleanly to a
	// Go struct without per-server keys.
	var top map[string]any
	if _, err := toml.Decode(string(raw), &top); err != nil {
		return nil, err
	}

	cfg := &CodexConfig{
		TrustedProjects: map[string]string{},
	}

	if v, ok := top["approval_policy"].(string); ok {
		cfg.ApprovalPolicy = v
	}
	if v, ok := top["sandbox_mode"].(string); ok {
		cfg.SandboxMode = v
	}

	// `[projects."<path>"]` tables. After decoding, they appear as a single
	// `projects` key whose value is map[string]any keyed by the path string.
	if projectsRaw, ok := top["projects"].(map[string]any); ok {
		for path, v := range projectsRaw {
			if entry, ok := v.(map[string]any); ok {
				if tl, ok := entry["trust_level"].(string); ok {
					cfg.TrustedProjects[path] = tl
				}
			}
		}
	}

	// `[mcp_servers.<name>]` tables. Same pattern.
	if mcpRaw, ok := top["mcp_servers"].(map[string]any); ok {
		for name, v := range mcpRaw {
			entry, ok := v.(map[string]any)
			if !ok {
				continue
			}
			s := CodexMCPServer{Name: name}
			if c, ok := entry["command"].(string); ok {
				s.Command = c
			}
			if argsRaw, ok := entry["args"].([]any); ok {
				for _, a := range argsRaw {
					if as, ok := a.(string); ok {
						s.Args = append(s.Args, as)
					}
				}
			}
			if u, ok := entry["url"].(string); ok {
				s.URL = u
			}
			if e, ok := entry["enabled"].(bool); ok {
				s.Enabled = &e
			}
			if envRaw, ok := entry["env"].(map[string]any); ok {
				s.Env = stringMapFromAny(envRaw)
			}
			if hRaw, ok := entry["http_headers"].(map[string]any); ok {
				s.HTTPHeaders = stringMapFromAny(hRaw)
			}
			s.Line = findLine(raw, "[mcp_servers."+name+"]")
			cfg.MCPServers = append(cfg.MCPServers, s)
		}
	}

	return cfg, nil
}

// stringMapFromAny coerces a map[string]any to map[string]string, preserving
// keys whose values aren't strings (uncommon in Codex config but possible)
// by skipping them rather than crashing.
func stringMapFromAny(in map[string]any) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// findLine returns the 1-indexed line where `marker` first appears in raw.
// Returns 0 if not found. Used to give findings a useful line number; not
// security-critical (rule decisions don't depend on it).
func findLine(raw []byte, marker string) int {
	idx := strings.Index(string(raw), marker)
	if idx < 0 {
		return 0
	}
	line := 1
	for i := 0; i < idx; i++ {
		if raw[i] == '\n' {
			line++
		}
	}
	return line
}
