package finding

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNew_RedactsMatchAndContext(t *testing.T) {
	f := New(Args{
		RuleID:      "test-rule",
		Severity:    SeverityHigh,
		Taxonomy:    TaxEnforced,
		Title:       "test finding",
		Description: "describes the rule, not the payload",
		Path:        "/home/user/.mcp.json",
		Line:        7,
		Match:       "AKIAIOSFODNN7EXAMPLE",
		Context:     "command: foo\nenv:\n  AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE\n",
	})

	if strings.Contains(f.Match, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("Match leaked secret: %q", f.Match)
	}
	if strings.Contains(f.Context, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("Context leaked secret: %q", f.Context)
	}
	if !strings.Contains(f.Match, "<redacted:") {
		t.Errorf("Match missing redaction marker: %q", f.Match)
	}
	if !strings.Contains(f.Context, "<redacted:") {
		t.Errorf("Context missing redaction marker: %q", f.Context)
	}
}

func TestNew_PreservesNonSecretFields(t *testing.T) {
	f := New(Args{
		RuleID:       "rule-x",
		Severity:     SeverityMedium,
		Title:        "Title with normal text",
		Description:  "Description that should not be redacted even if it mentions API_KEY",
		Path:         "/path/to/file",
		Line:         42,
		SuggestedFix: "Run audr --help for fix guidance",
		Tags:         []string{"mcp", "config"},
	})
	if f.Title != "Title with normal text" {
		t.Errorf("Title was modified: %q", f.Title)
	}
	if f.Path != "/path/to/file" {
		t.Errorf("Path was modified: %q", f.Path)
	}
	if f.Line != 42 {
		t.Errorf("Line was modified: %d", f.Line)
	}
	if len(f.Tags) != 2 {
		t.Errorf("Tags changed: %v", f.Tags)
	}
}

func TestNew_DefaultsTaxonomyToDetectable(t *testing.T) {
	f := New(Args{RuleID: "x", Severity: SeverityLow, Title: "t"})
	if f.Taxonomy != TaxDetectable {
		t.Errorf("default Taxonomy = %q, want %q", f.Taxonomy, TaxDetectable)
	}
}

func TestSeverity_JSONString(t *testing.T) {
	tests := map[Severity]string{
		SeverityCritical: `"critical"`,
		SeverityHigh:     `"high"`,
		SeverityMedium:   `"medium"`,
		SeverityLow:      `"low"`,
	}
	for sev, want := range tests {
		got, err := json.Marshal(sev)
		if err != nil {
			t.Fatalf("marshal error: %v", err)
		}
		if string(got) != want {
			t.Errorf("Severity(%d) = %s, want %s", sev, got, want)
		}
	}
}

func TestLocation(t *testing.T) {
	f := Finding{Path: "/x", Line: 0}
	if f.Location() != "/x" {
		t.Errorf("Location with no line: %q", f.Location())
	}
	f.Line = 7
	if f.Location() != "/x:7" {
		t.Errorf("Location with line: %q", f.Location())
	}
}
