package parse

import (
	"strings"
	"testing"
)

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		path string
		want Format
	}{
		{"/home/user/.mcp.json", FormatMCPConfig},
		{"/home/user/projects/foo/.mcp.json", FormatMCPConfig},
		{"/home/user/.cursor/mcp.json", FormatMCPConfig},
		{"/home/user/.claude/settings.json", FormatClaudeSettings},
		{"/home/user/.config/Claude/settings.json", FormatClaudeSettings},
		{"/home/user/.claude/skills/foo/SKILL.md", FormatSkill},
		{"/home/user/AGENTS.md", FormatAgentDoc},
		{"/repo/CLAUDE.md", FormatAgentDoc},
		{"/repo/.cursorrules", FormatAgentDoc},
		{"/repo/.github/workflows/ci.yml", FormatGHAWorkflow},
		{"/repo/.github/workflows/release.yaml", FormatGHAWorkflow},
		{"/home/user/.bashrc", FormatShellRC},
		{"/home/user/.zshrc", FormatShellRC},
		{"/home/user/.profile", FormatShellRC},
		{"/repo/.env", FormatEnv},
		{"/repo/.env.local", FormatEnv},
		{"/repo/random.txt", FormatUnknown},
		{"/repo/README.md", FormatUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := DetectFormat(tt.path); got != tt.want {
				t.Errorf("DetectFormat(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestParseMCPConfig_HappyPath(t *testing.T) {
	raw := []byte(`{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
      "env": {"NODE_ENV": "production"}
    },
    "github": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-github@1.2.3"],
      "env": {"GITHUB_TOKEN": "ghp_examplexxxxxxxxxxxxxxxxxxxxxxxxxxxx"}
    }
  }
}`)
	doc := Parse("/test/.mcp.json", raw)
	if doc.Format != FormatMCPConfig {
		t.Fatalf("format = %q", doc.Format)
	}
	if doc.ParseError != nil {
		t.Fatalf("parse error: %v", doc.ParseError)
	}
	if doc.MCPConfig == nil {
		t.Fatal("MCPConfig nil")
	}
	if len(doc.MCPConfig.Servers) != 2 {
		t.Fatalf("server count = %d, want 2", len(doc.MCPConfig.Servers))
	}
	for _, s := range doc.MCPConfig.Servers {
		if s.Command != "npx" {
			t.Errorf("server %q command = %q", s.Name, s.Command)
		}
		if s.Line == 0 {
			t.Errorf("server %q has no line number", s.Name)
		}
	}
}

func TestParseMCPConfig_Malformed(t *testing.T) {
	doc := Parse("/test/.mcp.json", []byte("{ this is not json"))
	if doc.ParseError == nil {
		t.Fatal("expected ParseError on malformed JSON")
	}
}

func TestParseSkill(t *testing.T) {
	raw := []byte(`---
name: example-skill
description: A test skill
allowed-tools: Bash, WebFetch
---

This is the body of the skill. It mentions running ` + "`Bash`" + ` commands.

It also mentions WebFetch and Glob inline.
`)
	doc := Parse("/test/.claude/skills/example/SKILL.md", raw)
	if doc.Format != FormatSkill {
		t.Fatalf("format = %q", doc.Format)
	}
	if doc.Skill == nil {
		t.Fatal("Skill nil")
	}
	if doc.Skill.Name != "example-skill" {
		t.Errorf("Name = %q", doc.Skill.Name)
	}
	if doc.Skill.Frontmatter["description"] != "A test skill" {
		t.Errorf("description = %q", doc.Skill.Frontmatter["description"])
	}
	wantTools := []string{"Bash", "WebFetch"}
	for _, w := range wantTools {
		found := false
		for _, t2 := range doc.Skill.Tools {
			if t2 == w {
				found = true
			}
		}
		if !found {
			t.Errorf("Tools missing %q: %v", w, doc.Skill.Tools)
		}
	}
}

func TestParseWorkflow(t *testing.T) {
	raw := []byte(`name: ci
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
    steps:
      - name: checkout
        uses: actions/checkout@v4
      - name: build
        run: make build
        env:
          PROD_API_KEY: ${{ secrets.PROD_API_KEY }}
`)
	doc := Parse("/repo/.github/workflows/ci.yml", raw)
	if doc.Format != FormatGHAWorkflow {
		t.Fatalf("format = %q", doc.Format)
	}
	if doc.ParseError != nil {
		t.Fatalf("parse error: %v", doc.ParseError)
	}
	w := doc.Workflow
	if w == nil {
		t.Fatal("Workflow nil")
	}
	if w.Name != "ci" {
		t.Errorf("name = %q", w.Name)
	}
	if w.Permissions["contents"] != "read" {
		t.Errorf("top permissions: %v", w.Permissions)
	}
	if len(w.Jobs) != 1 {
		t.Errorf("expected 1 job, got %d", len(w.Jobs))
	}
	job := w.Jobs["build"]
	if job.Permissions["id-token"] != "write" {
		t.Errorf("job permissions: %v", job.Permissions)
	}
	if len(job.Steps) != 2 {
		t.Errorf("step count = %d", len(job.Steps))
	}
}

func TestParseShellRC(t *testing.T) {
	raw := []byte(`# my zshrc
export PATH=/usr/local/bin:$PATH
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
GITHUB_TOKEN=ghp_examplexxxxxxxxxxxxxxxxxxxxxxxxxxxx  # this is a token
source ~/.config/secrets.sh
. /tmp/another.sh
plain garbage line here
`)
	doc := Parse("/home/user/.zshrc", raw)
	if doc.Format != FormatShellRC {
		t.Fatal("wrong format")
	}
	rc := doc.ShellRC
	if rc.EnvVars["AWS_ACCESS_KEY_ID"] != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("AWS key = %q", rc.EnvVars["AWS_ACCESS_KEY_ID"])
	}
	if rc.EnvVars["GITHUB_TOKEN"] == "" {
		t.Errorf("GITHUB_TOKEN missing: %v", rc.EnvVars)
	}
	if rc.EnvVarLines["AWS_ACCESS_KEY_ID"] != 3 {
		t.Errorf("AWS key line = %d", rc.EnvVarLines["AWS_ACCESS_KEY_ID"])
	}
	if len(rc.Sources) != 2 {
		t.Errorf("sources count = %d, want 2", len(rc.Sources))
	}
	if !strings.Contains(rc.Sources[0], "secrets.sh") {
		t.Errorf("first source = %q", rc.Sources[0])
	}
}

func TestParseEnvFile(t *testing.T) {
	raw := []byte(`# .env
DATABASE_URL=postgres://user:pass@host/db
PROD_TOKEN="ghp_examplexxxxxxxxxxxxxxxxxxxxxxxxxxxx"
EMPTY=
`)
	doc := Parse("/repo/.env", raw)
	if doc.Format != FormatEnv {
		t.Fatal("wrong format")
	}
	if doc.Env.Vars["DATABASE_URL"] == "" {
		t.Error("DATABASE_URL missing")
	}
	if doc.Env.Vars["PROD_TOKEN"] == "" {
		t.Error("PROD_TOKEN missing")
	}
}

func TestParse_AgentDoc(t *testing.T) {
	raw := []byte("# CLAUDE.md\n\nLine two.\n")
	doc := Parse("/repo/CLAUDE.md", raw)
	if doc.Format != FormatAgentDoc {
		t.Fatal("wrong format")
	}
	if doc.AgentDoc == nil || len(doc.AgentDoc.Lines) < 3 {
		t.Errorf("AgentDoc lines: %v", doc.AgentDoc)
	}
}
