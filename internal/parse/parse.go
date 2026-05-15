package parse

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Parse reads the file at path, picks a parser by Format, and returns a
// populated Document. Parse errors are recorded on Document.ParseError; they
// do not return Go errors so the scanner keeps going.
func Parse(path string, raw []byte) *Document {
	doc := &Document{
		Path:   path,
		Format: DetectFormat(path),
		Raw:    raw,
	}
	if doc.Format == FormatUnknown {
		return doc
	}

	switch doc.Format {
	case FormatMCPConfig:
		cfg, err := parseMCPConfig(raw)
		doc.MCPConfig = cfg
		doc.ParseError = err
	case FormatClaudeSettings:
		cs, err := parseClaudeSettings(raw)
		doc.ClaudeSettings = cs
		doc.ParseError = err
	case FormatSkill:
		s, err := parseSkill(path, raw)
		doc.Skill = s
		doc.ParseError = err
	case FormatAgentDoc:
		doc.AgentDoc = &AgentDoc{Lines: strings.Split(string(raw), "\n")}
	case FormatGHAWorkflow:
		w, err := parseWorkflow(raw)
		doc.Workflow = w
		doc.ParseError = err
	case FormatShellRC:
		doc.ShellRC = parseShellRC(raw)
	case FormatPowerShellProfile:
		doc.PowerShellProfile = parsePowerShellProfile(raw)
	case FormatEnv:
		doc.Env = parseEnvFile(raw)
	case FormatCodexConfig:
		c, err := parseCodexConfig(raw)
		doc.CodexConfig = c
		doc.ParseError = err
	case FormatWindsurfMCP:
		w, err := parseWindsurfMCP(raw)
		doc.WindsurfMCP = w
		doc.ParseError = err
	case FormatCursorPermissions:
		cp, err := parseCursorPermissions(raw)
		doc.CursorPermissions = cp
		doc.ParseError = err
	case FormatPackageJSON:
		pkg, err := parsePackageJSON(raw)
		doc.PackageJSON = pkg
		if err == nil {
			doc.DependencyManifest = packageJSONDependencyManifest(pkg, raw)
		}
		doc.ParseError = err
	case FormatDependencyManifest:
		deps, err := parseDependencyManifest(path, raw)
		doc.DependencyManifest = deps
		doc.ParseError = err
	}
	return doc
}

// ReadAndParse reads the file at path then calls Parse. Returns nil if the
// file can't be read (caller logs the read error separately).
func ReadAndParse(path string, sizeCap int64) (*Document, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	// Skip non-regular files (dirs, devices, FIFOs). Symlinks: caller
	// should detect them and emit a finding; we don't follow.
	if !info.Mode().IsRegular() {
		return nil, ErrSkippedNonRegular
	}
	if sizeCap > 0 && info.Size() > sizeCap {
		// Caller emits a parse-skipped:size finding.
		return nil, ErrSkippedSize
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return Parse(path, raw), nil
}

// Sentinel errors the scanner uses to differentiate skip-modes.
var (
	ErrSkippedNonRegular = fmt.Errorf("non-regular file skipped")
	ErrSkippedSize       = fmt.Errorf("file size exceeds cap")
)

// parseMCPConfig parses the `.mcp.json` / `.cursor/mcp.json` shape.
//
// Schema (loosely):
//
//	{ "mcpServers": { "name": { "command": "...", "args": [...], "env": {...}, "url": "...", "type": "..." } } }
func parseMCPConfig(raw []byte) (*MCPConfig, error) {
	var top struct {
		MCPServers map[string]struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Env     map[string]string `json:"env"`
			URL     string            `json:"url"`
			Type    string            `json:"type"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("mcp parse: %w", err)
	}
	cfg := &MCPConfig{}
	rawStr := string(raw)
	for name, s := range top.MCPServers {
		cfg.Servers = append(cfg.Servers, MCPServer{
			Name:    name,
			Command: s.Command,
			Args:    s.Args,
			Env:     s.Env,
			URL:     s.URL,
			Type:    s.Type,
			Line:    findKeyLine(rawStr, name),
		})
	}
	return cfg, nil
}

// parseClaudeSettings is intentionally permissive — Claude Code settings.json
// has many keys that change shape across versions. We capture the bits rules
// care about (permissions, allowedTools, env, hooks).
func parseClaudeSettings(raw []byte) (*ClaudeSettings, error) {
	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("claude-settings parse: %w", err)
	}
	cs := &ClaudeSettings{
		Raw:         top,
		Permissions: map[string]any{},
		Env:         map[string]string{},
		Hooks:       map[string]any{},
	}
	for k, v := range top {
		switch k {
		case "permissions":
			if m, ok := v.(map[string]any); ok {
				cs.Permissions = m
			}
		case "allowedTools":
			if arr, ok := v.([]any); ok {
				for _, x := range arr {
					if s, ok := x.(string); ok {
						cs.AllowedTools = append(cs.AllowedTools, s)
					}
				}
			}
		case "env":
			if m, ok := v.(map[string]any); ok {
				for ek, ev := range m {
					if s, ok := ev.(string); ok {
						cs.Env[ek] = s
					}
				}
			}
		case "hooks":
			if m, ok := v.(map[string]any); ok {
				cs.Hooks = m
			}
		default:
			cs.OtherKeys = append(cs.OtherKeys, k)
		}
	}
	return cs, nil
}

// findKeyLine returns the 1-indexed line number of the first occurrence of
// "key": in the source. Used so MCPServer.Line points at something useful.
// Returns 0 if not found.
func findKeyLine(raw, key string) int {
	needle := `"` + key + `"`
	idx := strings.Index(raw, needle)
	if idx < 0 {
		return 0
	}
	return strings.Count(raw[:idx], "\n") + 1
}
