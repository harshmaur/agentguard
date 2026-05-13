package scanignore

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestDefaultsContainsCanonicalSkipNames(t *testing.T) {
	got := Defaults()
	// Sanity: list is non-empty and contains the load-bearing entries that
	// both the native walker and the TruffleHog shell-out need to skip.
	want := []string{
		"node_modules", "vendor", ".git", "dist", "build", "target",
		"__pycache__", ".next", ".cache",
		".venv", "venv",
		".npm/_cacache", ".cargo/registry", "go/pkg", ".gradle/caches",
		"Library/Caches", "AppData/Local/Temp",
	}
	for _, name := range want {
		if !contains(got, name) {
			t.Fatalf("Defaults() missing %q; got %v", name, got)
		}
	}
}

func TestWriteTruffleHogExcludeFileWritesAllPatterns(t *testing.T) {
	path, cleanup, err := WriteTruffleHogExcludeFile()
	if err != nil {
		t.Fatalf("WriteTruffleHogExcludeFile err: %v", err)
	}
	t.Cleanup(cleanup)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read exclude file: %v", err)
	}
	body := string(raw)

	// Every Defaults() entry must appear as a path-component regex.
	for _, segment := range Defaults() {
		want := `(?:^|/)` + regexp.QuoteMeta(segment) + `(?:/|$)`
		if !strings.Contains(body, want) {
			t.Fatalf("exclude file missing pattern %q for segment %q; body:\n%s", want, segment, body)
		}
	}

	// Line count matches the entry count: one pattern per line, no blanks.
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) != len(Defaults()) {
		t.Fatalf("exclude file has %d lines, want %d (one per Defaults() entry)", len(lines), len(Defaults()))
	}
	for i, line := range lines {
		if line == "" {
			t.Fatalf("exclude file line %d is empty", i)
		}
	}
}

func TestWriteTruffleHogExcludeFileCleanupRemovesFile(t *testing.T) {
	path, cleanup, err := WriteTruffleHogExcludeFile()
	if err != nil {
		t.Fatalf("WriteTruffleHogExcludeFile err: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected tempfile %q to exist before cleanup: %v", path, err)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected tempfile %q removed by cleanup; stat err = %v", path, err)
	}
}

func TestPatternForSegmentMatchesAsPathComponent(t *testing.T) {
	// Verify the pattern shape: matches segment as a real path component,
	// not as a substring of an unrelated name.
	tests := []struct {
		segment       string
		shouldMatch   []string
		shouldNotMatch []string
	}{
		{
			segment:        "node_modules",
			shouldMatch:    []string{"node_modules/foo", "/a/node_modules/b", "node_modules"},
			shouldNotMatch: []string{"node_modules.lock", "anode_modules", "node_modulesfoo"},
		},
		{
			segment:        ".git",
			shouldMatch:    []string{".git/HEAD", "/repo/.git/objects"},
			shouldNotMatch: []string{".gitignore", ".gitattributes"},
		},
		{
			segment:        "Library/Caches",
			shouldMatch:    []string{"Users/x/Library/Caches/foo", "Library/Caches"},
			shouldNotMatch: []string{"Library/Caches.bak", "MyLibrary/Caches/x"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.segment, func(t *testing.T) {
			re, err := regexp.Compile(patternForSegment(tt.segment))
			if err != nil {
				t.Fatalf("compile pattern: %v", err)
			}
			for _, p := range tt.shouldMatch {
				if !re.MatchString(p) {
					t.Errorf("pattern %s should match %q but did not", re, p)
				}
			}
			for _, p := range tt.shouldNotMatch {
				if re.MatchString(p) {
					t.Errorf("pattern %s should NOT match %q but did", re, p)
				}
			}
		})
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
