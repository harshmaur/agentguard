// Package parse contains format-specific parsers for the file types
// AgentGuard scans. Each parser fills in the relevant typed field on a
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
	FormatClaudeSettings Format = "claude-settings" // .claude/settings.json
	FormatSkill        Format = "skill"          // .claude/skills/**/*.md
	FormatAgentDoc     Format = "agent-doc"      // AGENTS.md, CLAUDE.md, CODEX.md, GEMINI.md, .cursorrules
	FormatGHAWorkflow  Format = "gha-workflow"   // .github/workflows/*.yml
	FormatShellRC      Format = "shellrc"        // .bashrc, .zshrc, .profile, etc.
	FormatEnv          Format = "env"            // .env, .env.local, .env.example
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
type ClaudeSettings struct {
	Permissions    map[string]any
	AllowedTools   []string
	Env            map[string]string
	Hooks          map[string]any
	OtherKeys      []string
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

// DetectFormat picks a Format based on the file path. Returns FormatUnknown
// for files that aren't AgentGuard-relevant.
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
	if base == "settings.json" && (strings.Contains(dir, ".claude") || strings.Contains(dir, "/.config/Claude")) {
		return FormatClaudeSettings
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
