// Package parse contains format-specific parsers for the file types
// Audr scans. Each parser fills in the relevant typed field on a
// Document; rules iterate over Documents and emit findings.
package parse

import (
	"path/filepath"
	"strings"
)

// Format identifies which kind of artifact a Document represents.
// Rules register for one or more formats and only run on matching docs.
type Format string

const (
	FormatMCPConfig    Format = "mcp-config"     // .mcp.json, .cursor/mcp.json
	FormatClaudeSettings Format = "claude-settings" // .claude/settings.json, settings.local.json
	FormatSkill        Format = "skill"          // .claude/skills/**/*.md
	FormatAgentDoc     Format = "agent-doc"      // AGENTS.md, CLAUDE.md, CODEX.md, GEMINI.md, .cursorrules
	FormatGHAWorkflow  Format = "gha-workflow"   // .github/workflows/*.yml
	FormatShellRC      Format = "shellrc"        // .bashrc, .zshrc, .profile, etc.
	FormatEnv          Format = "env"            // .env, .env.local, .env.example
	FormatCodexConfig  Format = "codex-config"   // ~/.codex/config.toml, .codex/config.toml (v0.2)
	FormatWindsurfMCP  Format = "windsurf-mcp"   // ~/.codeium/windsurf/mcp_config.json (v0.2.0-alpha.3)
	FormatCursorPermissions Format = "cursor-permissions" // ~/.cursor/permissions.json (v0.2.0-alpha.4)
	FormatUnknown      Format = ""
)

// Document is the generic container produced by parsers and consumed by rules.
type Document struct {
	Path   string // absolute or scan-relative path
	Format Format
	Raw    []byte // full file contents (subject to size cap)

	// Parsed forms. Exactly one is non-nil based on Format.
	MCPConfig      *MCPConfig
	ClaudeSettings *ClaudeSettings
	Skill          *Skill
	AgentDoc       *AgentDoc
	Workflow       *Workflow
	ShellRC        *ShellRC
	Env            *EnvFile
	CodexConfig    *CodexConfig // v0.2
	WindsurfMCP    *WindsurfMCP // v0.2.0-alpha.3
	CursorPermissions *CursorPermissions // v0.2.0-alpha.4

	// ParseError is set if parsing failed; rules treat this as an advisory
	// finding, the scan continues.
	ParseError error
}

// MCPServer describes one entry in the `mcpServers` section of an MCP config.
type MCPServer struct {
	Name    string            // server key from the JSON object
	Command string            // command to launch
	Args    []string          // positional args
	Env     map[string]string // env vars passed to the process
	URL     string            // for HTTP/SSE transports
	Type    string            // "stdio", "sse", "streamable-http", etc.
	// Line is the line number in the source file where this server was defined.
	Line int
}

// MCPConfig is the parsed form of a .mcp.json or similar.
type MCPConfig struct {
	Servers []MCPServer
}

// ClaudeSettings represents user/repo-level Claude Code configuration.
//
// Raw is the full top-level decoded JSON. Rules added in v0.2 (hook-shell-rce,
// skip-permission-prompt, third-party-plugin) walk Raw directly because the
// keys they need (statusLine, enabledPlugins, skipDangerousModePermissionPrompt,
// extraKnownMarketplaces) shift across Claude Code versions and don't
// warrant per-key struct fields.
type ClaudeSettings struct {
	Raw          map[string]any
	Permissions  map[string]any
	AllowedTools []string
	Env          map[string]string
	Hooks        map[string]any
	OtherKeys    []string
}

// Skill represents a parsed agent skill (Markdown with optional frontmatter).
type Skill struct {
	Name        string            // from frontmatter or filename
	Frontmatter map[string]string // top-level key/value (string-coerced)
	Body        string            // markdown body
	Tools       []string          // declared in frontmatter `allowed-tools` or detected in body
}

// AgentDoc captures content from agent-instruction documents like CLAUDE.md.
type AgentDoc struct {
	Lines []string // for line-number reporting
}

// Workflow is the parsed form of a GitHub Actions YAML.
type Workflow struct {
	Name        string
	Permissions map[string]string // top-level permissions block, if any
	Jobs        map[string]Job
}

// Job is one job in a GitHub Actions workflow.
type Job struct {
	Name        string
	Permissions map[string]string
	Steps       []Step
	RunsOn      []string
}

// Step is one step in a job.
type Step struct {
	Name string
	Uses string
	Run  string
	Env  map[string]string
	With map[string]string
	Line int
}

// ShellRC is a parsed shell rc file (.bashrc / .zshrc / .profile).
type ShellRC struct {
	// EnvVars are export statements: KEY=VALUE assignments.
	EnvVars map[string]string
	// Sources are `source` / `.` invocations of other files.
	Sources []string
	// Lines retains line numbers for each EnvVar by name.
	EnvVarLines map[string]int
}

// EnvFile is a parsed .env-style file.
type EnvFile struct {
	Vars map[string]string
	Lines map[string]int // line per key
}

// CodexConfig is the parsed form of `~/.codex/config.toml`.
//
// Captures only the fields the v0.2 ruleset needs to make a decision. Other
// fields exist in the file (model, personality, features, etc.) but are
// not security-relevant for static analysis.
type CodexConfig struct {
	// ApprovalPolicy is the top-level `approval_policy` setting.
	// Known values: "untrusted", "on-request", "never", "granular".
	ApprovalPolicy string

	// SandboxMode is the top-level `sandbox_mode` setting.
	// Known values: "read-only", "workspace-write", "danger-full-access".
	SandboxMode string

	// TrustedProjects maps a project path to its trust_level. Codex uses this
	// to decide whether to load a project's .codex/ layer (hooks, rules,
	// project-local config). `[projects."<path>"]` table with
	// `trust_level = "trusted"` is the risk shape: trust_level=trusted on
	// $HOME or a broad path disables sandboxing for everything inside it.
	TrustedProjects map[string]string

	// MCPServers are the [mcp_servers.<name>] tables. The v0.2 design treats
	// these as part of a normalized MCP model (added in a later iteration);
	// for now we keep them as a typed list specific to Codex.
	MCPServers []CodexMCPServer
}

// WindsurfMCP is the parsed form of ~/.codeium/windsurf/mcp_config.json.
//
// Shape:
//   { "mcpServers": {
//       "<name>": { "type": "http"|"stdio", "url": "...", "command": "...",
//                   "args": [...], "env": {...}, "headers": {...},
//                   "alwaysAllow": [...], "disabled": bool }
//   } }
type WindsurfMCP struct {
	Servers []WindsurfMCPServer
}

// WindsurfMCPServer is a single MCP server entry in a Windsurf config.
type WindsurfMCPServer struct {
	Name        string
	Type        string            // "http" | "stdio" | "sse"
	URL         string            // for HTTP transports
	Command     string            // for stdio transports
	Args        []string
	Env         map[string]string
	Headers     map[string]string // remote auth headers — Windsurf's analog of Codex's http_headers
	AlwaysAllow []string          // Windsurf-specific: tools auto-approved without prompt
	Disabled    bool
	Line        int
}

// NormalizedMCPServer is a uniform shape that rules iterate over regardless
// of which harness config file the server came from. Populated by the
// NormalizeMCPServers helper from MCPConfig (.mcp.json), CodexConfig, or
// WindsurfMCP. The same risk shape (plaintext credential, unpinned npx,
// unauth remote URL) shows up in all three with different serializations,
// so rules walk this slice instead of three different typed fields.
type NormalizedMCPServer struct {
	Name        string
	Source      Format            // which format produced this server
	Command     string            // stdio command
	Args        []string
	Env         map[string]string // process env
	URL         string            // remote transport URL
	Headers     map[string]string // remote auth headers
	AlwaysAllow []string          // Windsurf's per-server allowlist (empty for other sources)
	Disabled    bool
	Line        int
}

// CursorPermissions is the parsed form of ~/.cursor/permissions.json.
//
// Schema (per Cursor docs):
//   {
//     "mcpAllowlist":      ["github:*", "linear:list_issues", "*:my_tool"],
//     "terminalAllowlist": ["git", "npm:install*", "cargo build"]
//   }
//
// Both fields are optional; either can be omitted (or empty array).
// Cursor docs explicitly state these are "best-effort convenience, not
// security guarantees", but they're the most readable signal of how
// loose a user's Cursor auto-run permissions are.
type CursorPermissions struct {
	MCPAllowlist      []string
	TerminalAllowlist []string
	// Hint: when both arrays are explicitly empty, Cursor falls back to
	// no auto-run. When the file is missing, IDE settings apply.
	HasMCPAllowlist      bool // true if the key was present (vs missing)
	HasTerminalAllowlist bool
}

// CodexMCPServer is a single [mcp_servers.<name>] entry from config.toml.
type CodexMCPServer struct {
	Name        string
	Command     string            // for stdio transports
	Args        []string          // command args
	Env         map[string]string // process env (rare in Codex)
	URL         string            // for HTTP/SSE transports
	HTTPHeaders map[string]string // [mcp_servers.<name>.http_headers] table — Codex's place for plaintext API keys
	Enabled     *bool             // optional `enabled = true|false`
	// Line is the line number in the source file where this server was defined.
	Line int
}

// DetectFormat picks a Format based on the file path. Returns FormatUnknown
// for files that aren't Audr-relevant.
func DetectFormat(path string) Format {
	base := filepath.Base(path)
	dir := filepath.Dir(path)

	// MCP configs.
	switch base {
	case ".mcp.json", "mcp.json":
		return FormatMCPConfig
	}
	if strings.HasSuffix(path, "/.cursor/mcp.json") || strings.HasSuffix(path, "\\.cursor\\mcp.json") {
		return FormatMCPConfig
	}

	// Claude settings.
	if (base == "settings.json" || base == "settings.local.json") &&
		(strings.Contains(dir, ".claude") || strings.Contains(dir, "/.config/Claude")) {
		return FormatClaudeSettings
	}

	// Codex CLI config (v0.2). User config at ~/.codex/config.toml; project-local
	// override at <project>/.codex/config.toml.
	if base == "config.toml" && (strings.Contains(dir, "/.codex") || strings.HasSuffix(dir, "/.codex")) {
		return FormatCodexConfig
	}

	// Windsurf MCP config (v0.2.0-alpha.3). Lives at ~/.codeium/windsurf/mcp_config.json
	// on macOS/Linux. Same logical shape as Cursor's mcp.json, different path.
	if base == "mcp_config.json" && strings.Contains(dir, "/.codeium/windsurf") {
		return FormatWindsurfMCP
	}

	// Cursor global permissions config (v0.2.0-alpha.4). Lives at
	// ~/.cursor/permissions.json. Distinct from .cursor/mcp.json (already
	// FormatMCPConfig). Holds mcpAllowlist + terminalAllowlist arrays.
	if base == "permissions.json" && strings.Contains(dir, "/.cursor") {
		return FormatCursorPermissions
	}

	// Skill files: anything under .claude/skills/ ending in .md.
	if strings.HasSuffix(path, ".md") && strings.Contains(path, "/.claude/skills/") {
		return FormatSkill
	}

	// Agent instruction docs.
	switch base {
	case "AGENTS.md", "CLAUDE.md", "CODEX.md", "GEMINI.md", ".cursorrules":
		return FormatAgentDoc
	}

	// GitHub Actions workflows.
	if strings.Contains(path, "/.github/workflows/") &&
		(strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
		return FormatGHAWorkflow
	}

	// Shell rc.
	switch base {
	case ".bashrc", ".bash_profile", ".zshrc", ".zprofile", ".profile":
		return FormatShellRC
	}

	// Env files.
	if strings.HasPrefix(base, ".env") {
		return FormatEnv
	}

	return FormatUnknown
}
