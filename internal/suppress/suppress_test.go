package suppress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFile_Missing(t *testing.T) {
	s, err := LoadFile(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("missing file should be a no-op, got err=%v", err)
	}
	if s == nil {
		t.Fatal("missing file returned nil Set, want empty")
	}
	if s.Suppresses("any-rule", "any/path") {
		t.Fatal("empty Set should suppress nothing")
	}
}

func TestLoadFile_Unreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, chmod 0000 has no effect")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, ".audrignore")
	if err := os.WriteFile(path, []byte("rule-x\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("permission-denied file should surface an error, got nil")
	}
}

func TestParse_TableDriven(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		probes []probe
	}{
		{
			name:  "rule id alone disables globally",
			input: "mcp-unpinned-npx\n",
			probes: []probe{
				{"mcp-unpinned-npx", "any/path.json", true},
				{"mcp-unpinned-npx", "deep/nested/x.json", true},
				{"other-rule", "any/path.json", false},
			},
		},
		{
			name:  "path glob alone suppresses all rules under path",
			input: "testdata/**\n",
			probes: []probe{
				{"any-rule", "testdata/x.json", true},
				{"any-rule", "testdata/deep/y.toml", true},
				{"any-rule", "src/main.go", false},
			},
		},
		{
			name:  "rule id plus path narrows to that rule under that path",
			input: "gha-write-all-permissions .github/workflows/release.yml\n",
			probes: []probe{
				{"gha-write-all-permissions", ".github/workflows/release.yml", true},
				{"gha-write-all-permissions", ".github/workflows/ci.yml", false},
				{"other-rule", ".github/workflows/release.yml", false},
			},
		},
		{
			name:  "comments and blank lines ignored",
			input: "# header\n\n  # indented comment\nrule-x\n\n",
			probes: []probe{
				{"rule-x", "anywhere", true},
				{"header", "anywhere", false},
			},
		},
		{
			name:  "double-star matches multi-segment paths",
			input: "vendor/**\n",
			probes: []probe{
				{"any-rule", "vendor/a.go", true},
				{"any-rule", "vendor/sub/dir/b.go", true},
				{"any-rule", "src/vendor/c.go", false},
			},
		},
		{
			name:  "multiple rules accumulate",
			input: "rule-a\nrule-b src/**\n",
			probes: []probe{
				{"rule-a", "anywhere", true},
				{"rule-b", "src/x.go", true},
				{"rule-b", "test/x.go", false},
				{"rule-c", "anywhere", false},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set, err := Parse(strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			for _, p := range tc.probes {
				got := set.Suppresses(p.ruleID, p.path)
				if got != p.want {
					t.Errorf("Suppresses(%q, %q) = %v, want %v",
						p.ruleID, p.path, got, p.want)
				}
			}
		})
	}
}

func TestSuppresses_NilSetIsSafe(t *testing.T) {
	var s *Set
	if s.Suppresses("any-rule", "any/path") {
		t.Fatal("nil *Set should never suppress anything")
	}
}

func TestParseLine_DisambiguatesIDFromGlob(t *testing.T) {
	cases := []struct {
		line     string
		wantRule string
		wantGlob string
	}{
		{"kebab-case-id", "kebab-case-id", ""},
		{"path/with/slash", "", "path/with/slash"},
		{"glob-with-star/*", "", "glob-with-star/*"},
		{"id-only-digits-123", "id-only-digits-123", ""},
		{"rule-id path/glob", "rule-id", "path/glob"},
	}
	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			r := parseLine(tc.line)
			if r.RuleID != tc.wantRule || r.Glob != tc.wantGlob {
				t.Errorf("parseLine(%q) = {RuleID: %q, Glob: %q}, want {RuleID: %q, Glob: %q}",
					tc.line, r.RuleID, r.Glob, tc.wantRule, tc.wantGlob)
			}
		})
	}
}

type probe struct {
	ruleID string
	path   string
	want   bool
}
