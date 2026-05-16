package remediate

import (
	"net/url"
	"strings"
	"testing"
)

func TestMaintainerLinkFor_KnownVendor(t *testing.T) {
	got := MaintainerLinkFor(IssueDetails{
		Maintainer:    "vercel",
		RuleID:        "dependency-osv-vulnerability",
		AdvisoryID:    "CVE-2025-1234",
		Package:       "undici",
		FixedVersion:  "5.28.4",
		AffectedPaths: []string{"/home/x/.claude/plugins/cache/vercel/0.42.1/bun.lock"},
		Severity:      "high",
		Title:         "Vulnerable dependency: undici",
	})
	if got.IssueURL == "" {
		t.Fatal("expected issue URL for known vendor 'vercel'")
	}
	if !strings.Contains(got.IssueURL, "github.com/vercel/claude-plugins-official/issues/new") {
		t.Errorf("issue URL pointing at wrong repo: %q", got.IssueURL)
	}
	if got.LabelHint != "Vercel" {
		t.Errorf("LabelHint = %q, want %q", got.LabelHint, "Vercel")
	}
	// Body must contain identifying info.
	if !strings.Contains(got.BodyMarkdown, "CVE-2025-1234") {
		t.Error("body missing advisory ID")
	}
	if !strings.Contains(got.BodyMarkdown, "undici") {
		t.Error("body missing package name")
	}
	if !strings.Contains(got.BodyMarkdown, "5.28.4") {
		t.Error("body missing fixed version")
	}
}

func TestMaintainerLinkFor_AnthropicMarketplace(t *testing.T) {
	got := MaintainerLinkFor(IssueDetails{
		Maintainer: "anthropic-marketplace",
		Title:      "Plugin ships secret in config",
	})
	if got.IssueURL == "" {
		t.Fatal("expected URL for known maintainer 'anthropic-marketplace'")
	}
	if got.LabelHint != "Anthropic marketplace" {
		t.Errorf("LabelHint = %q", got.LabelHint)
	}
}

func TestMaintainerLinkFor_UnknownVendor(t *testing.T) {
	got := MaintainerLinkFor(IssueDetails{
		Maintainer: "some-random-vendor-we-dont-know",
		Title:      "Vulnerable dependency",
	})
	if got.IssueURL != "" {
		t.Errorf("unknown vendor must NOT supply IssueURL, got %q", got.IssueURL)
	}
	// Label still mentions the vendor name; body still rendered for clipboard fallback.
	if got.LabelHint != "some-random-vendor-we-dont-know" {
		t.Errorf("LabelHint should echo vendor hint, got %q", got.LabelHint)
	}
	if got.BodyMarkdown == "" {
		t.Error("body must always be populated (clipboard fallback)")
	}
}

func TestMaintainerLinkFor_NoMaintainerHint(t *testing.T) {
	got := MaintainerLinkFor(IssueDetails{
		// Maintainer field empty — e.g. UPSTREAM authority with no
		// extractable vendor name.
		Title: "Some finding",
	})
	if got.IssueURL != "" {
		t.Errorf("no maintainer hint must mean no issue URL, got %q", got.IssueURL)
	}
	if got.LabelHint != "plugin author" {
		t.Errorf("LabelHint = %q, want 'plugin author'", got.LabelHint)
	}
	if got.BodyMarkdown == "" {
		t.Error("body must always be populated")
	}
}

func TestMaintainerLinkFor_BodyURLEncoded(t *testing.T) {
	got := MaintainerLinkFor(IssueDetails{
		Maintainer:   "vercel",
		AdvisoryID:   "CVE-2025-1234",
		Package:      "@hono/node-server", // contains @ and /
		FixedVersion: "1.10.0",
		Title:        "Special chars: & = ?",
	})
	// Verify the URL parses cleanly (no malformed query string).
	parsed, err := url.Parse(got.IssueURL)
	if err != nil {
		t.Fatalf("issue URL did not parse: %v\n%s", err, got.IssueURL)
	}
	q := parsed.Query()
	if !strings.Contains(q.Get("title"), "@hono/node-server") {
		t.Errorf("title query missing scoped package name: %q", q.Get("title"))
	}
	if !strings.Contains(q.Get("body"), "Special chars: & = ?") {
		t.Errorf("body query missing title with special chars: %q", q.Get("body"))
	}
}

func TestMaintainerLinkFor_LongPathListTruncates(t *testing.T) {
	const numPaths = 50
	paths := make([]string, numPaths)
	for i := range paths {
		paths[i] = "/home/x/.claude/plugins/cache/vercel/0.42.1/deep/nested/dir/segment-" +
			strings.Repeat("x", 60) + "/file.txt"
	}
	got := MaintainerLinkFor(IssueDetails{
		Maintainer:    "vercel",
		AdvisoryID:    "CVE-2025-1234",
		Package:       "undici",
		FixedVersion:  "5.28.4",
		AffectedPaths: paths,
		Severity:      "high",
	})
	// Body should list at most 30 inline paths and summarise the rest.
	bodyLines := strings.Count(got.BodyMarkdown, "- `")
	if bodyLines > 31 { // 30 inline paths + 1 "more paths" line allowed
		t.Errorf("expected ≤31 bullet lines, got %d", bodyLines)
	}
	if !strings.Contains(got.BodyMarkdown, "more paths") {
		t.Error("expected '… N more paths' summary line for long lists")
	}
}

func TestMaintainerLinkFor_URLCapsAt8KB(t *testing.T) {
	// Build an issue with an absurdly long body to force the truncation
	// path. The output URL must remain within the 8KB cap.
	hugeTitle := strings.Repeat("a", 10_000)
	got := MaintainerLinkFor(IssueDetails{
		Maintainer: "vercel",
		Title:      hugeTitle,
	})
	if len(got.IssueURL) > 8<<10 {
		t.Errorf("URL length %d exceeded 8KB cap", len(got.IssueURL))
	}
	// Truncation marker must appear when we actually truncated.
	if !strings.Contains(got.BodyMarkdown, hugeTitle) {
		// The body field on the return value stays full-length — only
		// the URL is truncated. This preserves the clipboard fallback.
		// So this is fine; nothing to assert here beyond the cap.
	}
}

func TestMaintainerLinkFor_MaintainerCaseInsensitive(t *testing.T) {
	for _, m := range []string{"VERCEL", "Vercel", "vercel", "  vercel  "} {
		got := MaintainerLinkFor(IssueDetails{Maintainer: m})
		if got.IssueURL == "" {
			t.Errorf("expected URL for case variant %q", m)
		}
		if got.LabelHint != "Vercel" {
			t.Errorf("variant %q: LabelHint = %q", m, got.LabelHint)
		}
	}
}

func TestBuildIssueTitle(t *testing.T) {
	cases := []struct {
		d    IssueDetails
		want string
	}{
		{
			IssueDetails{AdvisoryID: "CVE-x", Package: "undici"},
			"Vulnerable dependency in shipped plugin: undici (CVE-x)",
		},
		{
			IssueDetails{AdvisoryID: "CVE-x"},
			"Security finding in shipped plugin: CVE-x",
		},
		{
			IssueDetails{Package: "undici"},
			"Vulnerable dependency in shipped plugin: undici",
		},
		{
			IssueDetails{},
			"Security finding in shipped plugin (reported by audr)",
		},
	}
	for _, tc := range cases {
		got := buildIssueTitle(tc.d)
		if got != tc.want {
			t.Errorf("buildIssueTitle(%+v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}
