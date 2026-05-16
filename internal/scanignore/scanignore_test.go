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
	// both the native walker and the betterleaks shell-out need to skip.
	want := []string{
		"node_modules", "vendor", ".git", "dist", "build", "target",
		"__pycache__", ".next", ".cache",
		".venv", "venv",
		".bun", ".pnpm-store", ".yarn", ".deno", ".gem", ".m2", ".gradle", ".cargo",
		".npm/_cacache", "go/pkg", ".gradle/caches",
		"Library/Caches", "AppData/Local/Temp",
	}
	for _, name := range want {
		if !contains(got, name) {
			t.Fatalf("Defaults() missing %q; got %v", name, got)
		}
	}
}

func TestIsExcludedBaseNameSingleSegment(t *testing.T) {
	// True for single-segment entries.
	for _, name := range []string{"node_modules", ".git", ".bun", ".cargo", ".pnpm-store"} {
		t.Run(name, func(t *testing.T) {
			if !IsExcludedBaseName(name) {
				t.Errorf("IsExcludedBaseName(%q) = false, want true", name)
			}
		})
	}
	// False for multi-segment entries' first segment when that
	// segment in isolation isn't intended as a skip target.
	if IsExcludedBaseName("Library") {
		t.Error("IsExcludedBaseName(\"Library\") = true, want false (multi-seg only)")
	}
	if IsExcludedBaseName("AppData") {
		t.Error("IsExcludedBaseName(\"AppData\") = true, want false")
	}
	if IsExcludedBaseName("go") {
		t.Error("IsExcludedBaseName(\"go\") = true; want false (~/go has both pkg/mod cache and src code)")
	}
	// Substring false matches.
	if IsExcludedBaseName("node_modulesXY") {
		t.Error("IsExcludedBaseName(\"node_modulesXY\") = true, want false (whole-segment match)")
	}
}

func TestPathExcludedHandlesBothBasenameAndMultiSeg(t *testing.T) {
	cases := []struct {
		path string
		want bool
		why  string
	}{
		// Single-segment matches anywhere in the path.
		{"/home/u/code/proj/node_modules/lodash", true, "node_modules anywhere"},
		{"/home/u/.git/HEAD", true, ".git basename"},
		{"/home/u/.bun/install/cache/foo", true, ".bun root match"},
		{"/home/u/.cargo/registry/cache/foo", true, ".cargo root match"},

		// Multi-segment matches.
		{"/home/u/go/pkg/mod/example.com/foo", true, "go/pkg subseq"},
		{"/home/u/.npm/_cacache/index", true, ".npm/_cacache subseq"},
		{"/home/u/Library/Caches/Yarn", true, "macOS Library/Caches"},
		{"/c/Users/u/AppData/Local/Temp/x", true, "Windows AppData/Local/Temp"},

		// Non-matches.
		{"/home/u/code/proj/src/lodash.go", false, "code path"},
		{"/home/u/go/src/github.com/foo/bar", false, "go/src is code, not cache"},
		{"/home/u/somepkg/.gradle.bak", false, "must be whole segment"},
		{"/home/u/projects/myrepo/package.json", false, "real project"},
		{"", false, "empty path"},
	}
	for _, tt := range cases {
		t.Run(tt.path, func(t *testing.T) {
			got := PathExcluded(tt.path)
			if got != tt.want {
				t.Errorf("PathExcluded(%q) = %v, want %v (%s)", tt.path, got, tt.want, tt.why)
			}
		})
	}
}

func TestPathExcludedHandlesWindowsSeparators(t *testing.T) {
	// Backslashes get normalized to forward slashes before matching.
	if !PathExcluded(`C:\Users\foo\.cargo\registry\cache`) {
		t.Error("backslash-separated path with .cargo not detected")
	}
	if !PathExcluded(`C:\Users\foo\AppData\Local\Temp\bar`) {
		t.Error("backslash-separated AppData/Local/Temp not detected")
	}
}

func TestWriteBetterleaksConfigContainsAllPatterns(t *testing.T) {
	path, cleanup, err := WriteBetterleaksConfig()
	if err != nil {
		t.Fatalf("WriteBetterleaksConfig err: %v", err)
	}
	t.Cleanup(cleanup)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config file: %v", err)
	}
	body := string(raw)

	// File must opt into betterleaks's default rule set rather than
	// replace it — otherwise users lose every shipped detector.
	for _, want := range []string{"[extend]", "useDefault = true", "[[allowlists]]", "paths = ["} {
		if !strings.Contains(body, want) {
			t.Fatalf("config missing required section %q; body:\n%s", want, body)
		}
	}

	// Every Defaults() entry must appear as a path-component regex.
	for _, segment := range Defaults() {
		want := `(^|/)` + regexp.QuoteMeta(segment) + `(/|$)`
		if !strings.Contains(body, want) {
			t.Fatalf("config missing pattern %q for segment %q; body:\n%s", want, segment, body)
		}
	}

	// Every BinaryFileExtensions() entry must appear as an extension regex.
	for _, ext := range BinaryFileExtensions() {
		want := `\.` + regexp.QuoteMeta(ext) + `$`
		if !strings.Contains(body, want) {
			t.Fatalf("config missing pattern %q for extension %q; body:\n%s", want, ext, body)
		}
	}
}

func TestPatternForExtensionMatchesAsSuffix(t *testing.T) {
	tests := []struct {
		ext            string
		shouldMatch    []string
		shouldNotMatch []string
	}{
		{
			ext:            "apk",
			shouldMatch:    []string{"build.apk", "/a/b/c.apk", "mobile/build-12345.apk"},
			shouldNotMatch: []string{"apkthing.txt", "build.apk.bak", ".apk-config"},
		},
		{
			ext:            "so",
			shouldMatch:    []string{"libfoo.so", "/usr/lib/libssl.so"},
			shouldNotMatch: []string{"hello.source", "so-cool.txt"},
		},
		{
			ext:            "tar.gz",
			shouldMatch:    []string{"backup.tar.gz", "/tmp/build.tar.gz"},
			shouldNotMatch: []string{"backup.tar.gz.bak"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.ext, func(t *testing.T) {
			re, err := regexp.Compile(patternForExtension(tt.ext))
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

func TestWriteBetterleaksConfigCleanupRemovesFile(t *testing.T) {
	path, cleanup, err := WriteBetterleaksConfig()
	if err != nil {
		t.Fatalf("WriteBetterleaksConfig err: %v", err)
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
