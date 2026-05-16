package remediate

import (
	"strings"
	"testing"
)

func TestParseOSVDedupKey_HappyPath(t *testing.T) {
	cases := []struct {
		key  string
		want OSVKey
	}{
		{
			"osv:npm:undici:5.28.4:CVE-2025-1234",
			OSVKey{"npm", "undici", "5.28.4", "CVE-2025-1234"},
		},
		{
			"osv:go:github.com/foo/bar:1.2.3:GHSA-abcd-efgh-ijkl",
			OSVKey{"go", "github.com/foo/bar", "1.2.3", "GHSA-abcd-efgh-ijkl"},
		},
		{
			"osv:crates.io:regex:1.10.0:CVE-2024-0001",
			OSVKey{"crates.io", "regex", "1.10.0", "CVE-2024-0001"},
		},
		{
			// Unpatched advisory — FixedVersion empty is legal.
			"osv:npm:left-pad::CVE-2024-9999",
			OSVKey{"npm", "left-pad", "", "CVE-2024-9999"},
		},
		{
			// Scoped npm package with @ prefix.
			"osv:npm:@hono/node-server:1.10.0:CVE-2025-5678",
			OSVKey{"npm", "@hono/node-server", "1.10.0", "CVE-2025-5678"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			got, ok := ParseOSVDedupKey(tc.key)
			if !ok {
				t.Fatalf("expected ok=true for %q", tc.key)
			}
			if got != tc.want {
				t.Errorf("ParseOSVDedupKey(%q) = %+v, want %+v", tc.key, got, tc.want)
			}
		})
	}
}

func TestParseOSVDedupKey_Malformed(t *testing.T) {
	cases := []string{
		"",
		"not-an-osv-key",
		"osv:",
		"osv:npm",
		"osv:npm:undici",
		"osv:npm::5.28.4:CVE-x", // empty package
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			if _, ok := ParseOSVDedupKey(tc); ok {
				t.Errorf("expected ok=false for malformed %q", tc)
			}
		})
	}
}

func TestBuildOSVDedupKey_RoundTrip(t *testing.T) {
	cases := []struct {
		ecosystem    string
		pkg          string
		fixedVersion string
		advisoryID   string
	}{
		{"npm", "undici", "5.28.4", "CVE-2025-1234"},
		{"NPM", "undici", "v5.28.4", "CVE-2025-1234"},   // case + leading-v normalisation
		{"  npm  ", "undici", "5.28.4", "CVE-2025-1234"}, // whitespace trim
	}
	canonical := BuildOSVDedupKey("npm", "undici", "5.28.4", "CVE-2025-1234")
	for _, tc := range cases {
		got := BuildOSVDedupKey(tc.ecosystem, tc.pkg, tc.fixedVersion, tc.advisoryID)
		if got != canonical {
			t.Errorf("BuildOSVDedupKey did not normalise: %q != %q", got, canonical)
		}
		// Round-trip: build then parse should give back the same components.
		parsed, ok := ParseOSVDedupKey(got)
		if !ok {
			t.Errorf("BuildOSVDedupKey output failed to parse: %q", got)
		}
		if parsed.Ecosystem != "npm" || parsed.Package != "undici" ||
			parsed.FixedVersion != "5.28.4" || parsed.AdvisoryID != "CVE-2025-1234" {
			t.Errorf("round-trip lost data: %+v", parsed)
		}
	}
}

func TestSnippetForOSVFinding_HappyPath(t *testing.T) {
	got := SnippetForOSVFinding(
		"osv:npm:undici:5.28.4:CVE-2025-1234",
		"/home/alice/projects/audr/web/package-lock.json",
	)
	if !strings.Contains(got, `"undici"`) || !strings.Contains(got, `"^5.28.4"`) {
		t.Errorf("expected npm overrides snippet for undici, got:\n%s", got)
	}
	if !strings.Contains(got, `"overrides"`) {
		t.Errorf("expected 'overrides' key, got:\n%s", got)
	}
}

func TestSnippetForOSVFinding_GoPath(t *testing.T) {
	got := SnippetForOSVFinding(
		"osv:go:github.com/foo/bar:1.2.3:GHSA-x",
		"/home/alice/code/myapp/go.sum",
	)
	if !strings.Contains(got, "replace github.com/foo/bar") {
		t.Errorf("expected go replace directive, got:\n%s", got)
	}
}

func TestSnippetForOSVFinding_EcosystemMismatchReturnsEmpty(t *testing.T) {
	// OSV says "go" but the path is a JS lockfile. F6 guard: refuse to
	// render rather than emit a wrong-format snippet.
	got := SnippetForOSVFinding(
		"osv:go:github.com/foo/bar:1.2.3:CVE-x",
		"/home/alice/projects/audr/web/package-lock.json",
	)
	if got != "" {
		t.Errorf("ecosystem mismatch should suppress snippet, got:\n%s", got)
	}
}

func TestSnippetForOSVFinding_NoFixedVersionReturnsEmpty(t *testing.T) {
	got := SnippetForOSVFinding(
		"osv:npm:left-pad::CVE-2024-9999",
		"/home/alice/projects/foo/package-lock.json",
	)
	if got != "" {
		t.Errorf("missing fixed version should suppress snippet, got:\n%s", got)
	}
}

func TestSnippetForOSVFinding_UnknownLockfileReturnsEmpty(t *testing.T) {
	got := SnippetForOSVFinding(
		"osv:npm:undici:5.28.4:CVE-x",
		"/home/alice/projects/foo/requirements.txt",
	)
	if got != "" {
		t.Errorf("unknown lockfile should suppress snippet, got:\n%s", got)
	}
}

func TestSnippetForOSVFinding_MalformedKeyReturnsEmpty(t *testing.T) {
	got := SnippetForOSVFinding(
		"not-an-osv-key",
		"/home/alice/projects/foo/package-lock.json",
	)
	if got != "" {
		t.Errorf("malformed key should suppress snippet, got:\n%s", got)
	}
}
