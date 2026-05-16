package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestMCPCalculateServerEvalRCE_FlagsVulnerableRequirements(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("mcp-calcualte-server==0.1.0\n"))
	findings := (mcpCalculateServerEvalRCE{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "mcp-calculate-server-eval-rce" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}
	if findings[0].Line != 1 {
		t.Fatalf("line = %d, want 1", findings[0].Line)
	}
}

func TestMCPCalculateServerEvalRCE_FlagsVulnerablePyproject(t *testing.T) {
	doc := parse.Parse("pyproject.toml", []byte(`[project]
dependencies = [
  "mcp-calculate-server<0.1.1",
]
`))
	findings := (mcpCalculateServerEvalRCE{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestMCPCalculateServerEvalRCE_AllowsFixedVersion(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("mcp-calcualte-server==0.1.1\n"))
	findings := (mcpCalculateServerEvalRCE{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}
