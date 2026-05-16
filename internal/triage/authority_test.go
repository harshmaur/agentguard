package triage

import (
	"path/filepath"
	"testing"

	"github.com/harshmaur/audr/internal/finding"
)

func TestClassify_PathClassTable(t *testing.T) {
	const home = "/home/alice"

	cases := []struct {
		name           string
		path           string
		wantAuthority  finding.FixAuthority
		wantMaintainer string
	}{
		// Claude Code plugin marketplace — UPSTREAM (third-party plugin shipped via marketplace).
		{
			name:          "marketplace external_plugins discord bun.lock",
			path:          home + "/.claude/plugins/marketplaces/claude-plugins-official/external_plugins/discord/bun.lock",
			wantAuthority: finding.FixAuthorityUpstream,
		},
		{
			name:          "marketplace external_plugins nested node_modules",
			path:          home + "/.claude/plugins/marketplaces/marketplace-x/external_plugins/foo/node_modules/picomatch/package.json",
			wantAuthority: finding.FixAuthorityUpstream,
		},

		// Claude Code plugin cache — MAINTAINER with vendor name extracted.
		{
			name:           "claude plugin cache vercel 0.42.1 bun.lock",
			path:           home + "/.claude/plugins/cache/vercel/0.42.1/bun.lock",
			wantAuthority:  finding.FixAuthorityMaintainer,
			wantMaintainer: "vercel",
		},
		{
			name:           "claude plugin cache anthropic-marketplace some-plugin file",
			path:           home + "/.claude/plugins/cache/anthropic-marketplace/some-plugin/config.json",
			wantAuthority:  finding.FixAuthorityMaintainer,
			wantMaintainer: "anthropic-marketplace",
		},

		// Claude Code session transcripts — YOU (rotate path, even though file
		// format is Anthropic-managed).
		{
			name:          "claude projects session jsonl",
			path:          home + "/.claude/projects/audr/abc123.jsonl",
			wantAuthority: finding.FixAuthorityYou,
		},

		// Cursor extensions — MAINTAINER with hardcoded "cursor" hint.
		{
			name:           "cursor extensions vendored node_modules",
			path:           home + "/.cursor/extensions/anysphere.cursor-tools/node_modules/picomatch/package.json",
			wantAuthority:  finding.FixAuthorityMaintainer,
			wantMaintainer: "cursor",
		},

		// Codex CLI config — YOU.
		{
			name:          "codex config toml",
			path:          home + "/.codex/config.toml",
			wantAuthority: finding.FixAuthorityYou,
		},

		// Windsurf — YOU.
		{
			name:          "windsurf mcp_config.json",
			path:          home + "/.codeium/windsurf/mcp_config.json",
			wantAuthority: finding.FixAuthorityYou,
		},

		// System-installed npm — UPSTREAM.
		{
			name:          "/usr/lib/node_modules deep",
			path:          "/usr/lib/node_modules/yarn/lib/cli.js",
			wantAuthority: finding.FixAuthorityUpstream,
		},
		{
			name:          "/usr/local/lib/node_modules",
			path:          "/usr/local/lib/node_modules/pnpm/package.json",
			wantAuthority: finding.FixAuthorityUpstream,
		},
		{
			name:          "Go module cache",
			path:          home + "/go/pkg/mod/github.com/foo/bar@v1.2.3/main.go",
			wantAuthority: finding.FixAuthorityUpstream,
		},

		// User shell rc + secrets — YOU.
		{
			name:          "zshrc",
			path:          home + "/.zshrc",
			wantAuthority: finding.FixAuthorityYou,
		},
		{
			name:          "aws credentials",
			path:          home + "/.aws/credentials",
			wantAuthority: finding.FixAuthorityYou,
		},
		{
			name:          ".env at home root",
			path:          home + "/.env",
			wantAuthority: finding.FixAuthorityYou,
		},

		// User projects — YOU (fallthrough).
		{
			name:          "user project package-lock.json",
			path:          home + "/projects/audr/package-lock.json",
			wantAuthority: finding.FixAuthorityYou,
		},
		{
			name:          "user code Cargo.lock",
			path:          home + "/code/foo/Cargo.lock",
			wantAuthority: finding.FixAuthorityYou,
		},

		// Absolute paths outside home — fallthrough YOU.
		{
			name:          "absolute path outside home",
			path:          "/opt/something/file.txt",
			wantAuthority: finding.FixAuthorityYou,
		},

		// HOME itself.
		{
			name:          "HOME directory exactly",
			path:          home,
			wantAuthority: finding.FixAuthorityYou,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotAuth, gotMaint := Classify(tc.path, home)
			if gotAuth != tc.wantAuthority {
				t.Errorf("Classify(%q) authority = %q, want %q", tc.path, gotAuth, tc.wantAuthority)
			}
			if gotMaint != tc.wantMaintainer {
				t.Errorf("Classify(%q) maintainer = %q, want %q", tc.path, gotMaint, tc.wantMaintainer)
			}
		})
	}
}

func TestClassify_OverlapOrdering(t *testing.T) {
	// external_plugins MUST resolve to UPSTREAM even though it sits
	// under "marketplaces" which is also under HOME. This protects
	// against accidentally reordering the table such that the more-
	// general "**" fallthrough or a HOME-level rule swallows the
	// nested third-party tree.
	const home = "/home/alice"
	path := home + "/.claude/plugins/marketplaces/x/external_plugins/foo/node_modules/p/package.json"
	auth, _ := Classify(path, home)
	if auth != finding.FixAuthorityUpstream {
		t.Errorf("overlap test: external_plugins under marketplaces resolved to %q, want %q",
			auth, finding.FixAuthorityUpstream)
	}
}

func TestClassify_FallthroughIsYou(t *testing.T) {
	// The fallthrough must always succeed and return FixAuthorityYou.
	// This is a safety property — if the table is ever edited badly,
	// users must still see actionable items, not silent demotions.
	const home = "/home/alice"
	for _, p := range []string{
		"/some/weird/absolute/path",
		home + "/something/unclassified",
		"/tmp/scratch.txt",
	} {
		auth, _ := Classify(p, home)
		if auth != finding.FixAuthorityYou {
			t.Errorf("fallthrough Classify(%q) = %q, want %q", p, auth, finding.FixAuthorityYou)
		}
	}
}

func TestForSecret_AlwaysYouButPreservesMaintainerHint(t *testing.T) {
	cases := []struct {
		name              string
		inAuthority       finding.FixAuthority
		inMaintainer      string
		wantAuthority     finding.FixAuthority
		wantSecondaryHint string
	}{
		{
			name:          "secret in user file stays YOU, no secondary hint",
			inAuthority:   finding.FixAuthorityYou,
			inMaintainer:  "",
			wantAuthority: finding.FixAuthorityYou,
		},
		{
			name:              "secret in vendor plugin cache becomes YOU but preserves vendor hint",
			inAuthority:       finding.FixAuthorityMaintainer,
			inMaintainer:      "vercel",
			wantAuthority:     finding.FixAuthorityYou,
			wantSecondaryHint: "vercel",
		},
		{
			name:              "secret in upstream tree becomes YOU but preserves upstream hint",
			inAuthority:       finding.FixAuthorityUpstream,
			inMaintainer:      "discord-bot-author",
			wantAuthority:     finding.FixAuthorityYou,
			wantSecondaryHint: "discord-bot-author",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotAuth, gotHint := ForSecret(tc.inAuthority, tc.inMaintainer)
			if gotAuth != tc.wantAuthority {
				t.Errorf("ForSecret authority = %q, want %q", gotAuth, tc.wantAuthority)
			}
			if gotHint != tc.wantSecondaryHint {
				t.Errorf("ForSecret hint = %q, want %q", gotHint, tc.wantSecondaryHint)
			}
		})
	}
}

func TestCanonicalize(t *testing.T) {
	const home = "/home/alice"
	cases := []struct {
		path string
		want string
	}{
		{home + "/projects/audr", "~/projects/audr"},
		{home, "~"},
		{"/opt/elsewhere", "/opt/elsewhere"},
		{"", ""},
	}
	for _, tc := range cases {
		got := canonicalize(tc.path, home)
		if got != tc.want {
			t.Errorf("canonicalize(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}

	// Empty home is a defensible no-op.
	if got := canonicalize("/foo/bar", ""); got != "/foo/bar" {
		t.Errorf("canonicalize with empty home: got %q, want passthrough", got)
	}
}

func TestMatchPathPattern_DoubleStar(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"~/.claude/plugins/cache/**", "~/.claude/plugins/cache/vercel/0.42.1/x", true},
		{"~/.claude/plugins/cache/**", "~/.claude/plugins/marketplaces/x", false},
		{"**", "anything/at/all", true},
		{"**", "", false}, // empty paths shouldn't slip through
		{"a/**/c", "a/b/c", true},
		{"a/**/c", "a/c", true}, // ** matches zero segments
		{"a/**/c", "a/b/x/c", true},
		{"a/**/c", "a/b/x", false},
		{"~/.zshrc", "~/.zshrc", true},
		{"~/.zshrc", "~/.bashrc", false},
	}
	for _, tc := range cases {
		got := matchPathPattern(tc.pattern, tc.path)
		if got != tc.want {
			t.Errorf("matchPathPattern(%q, %q) = %v, want %v",
				tc.pattern, tc.path, got, tc.want)
		}
	}
}

func TestExtractClaudePluginVendor(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"~/.claude/plugins/cache/vercel/0.42.1/bun.lock", "vercel"},
		{"~/.claude/plugins/cache/anthropic-marketplace/x/y", "anthropic-marketplace"},
		{"~/.claude/plugins/cache/vendor-only", "vendor-only"},
		{"~/.claude/plugins/cache/", ""},
		{"~/.claude/plugins/marketplaces/x/y", ""},
		{"/etc/passwd", ""},
	}
	for _, tc := range cases {
		// Use real path separator to mirror the runtime call site.
		// The helper is internal so we can construct the canonical form
		// directly; OS-specific separator handling stays in
		// canonicalize().
		canon := tc.path
		// On Windows, filepath.Separator is '\'. Build with the runtime
		// separator so the strings.IndexRune slice matches the production
		// path the helper sees from canonicalize().
		if filepath.Separator != '/' {
			canon = filepath.FromSlash(tc.path)
		}
		got := extractClaudePluginVendor(canon)
		if got != tc.want {
			t.Errorf("extractClaudePluginVendor(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}
