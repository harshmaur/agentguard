// Package triage classifies findings for the v1.3 rolled-up dashboard:
// who can fix this (FixAuthority + maintainer hint), and what unique
// vulnerability does it represent (dedup key).
//
// The package is pure logic with no I/O. It runs over a slice of
// finding.Finding after rules emit and before findings are persisted —
// rules MAY pre-populate the fields, and triage fills in whatever is
// blank. Rules that pre-populate (e.g. the OSV dep rule, which knows
// the canonical (pkg, fixed, cve) tuple) always win.
package triage

import (
	"path/filepath"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
)

// pathClassEntry maps a path pattern to a (FixAuthority, maintainer hint)
// pair. Order matters: the first matching entry wins, so more-specific
// patterns must appear before more-general ones.
//
// Patterns use filepath.Match semantics on each path segment, with one
// extension: a literal "**" segment matches any number of intermediate
// segments. The match is performed against the path AFTER the user's
// HOME directory has been normalised to the literal token "~". Absolute
// paths that don't start in HOME are matched verbatim.
type pathClassEntry struct {
	pattern    string
	authority  finding.FixAuthority
	maintainer string // empty when not applicable
}

// pathClassTable is the canonical lookup. Edits to this table are the
// primary maintenance surface for v1.3 path classification. Keep entries
// roughly grouped by the harness that ships them.
//
// First match wins, so MAINTAINER-style entries (which are nested inside
// HOME) must appear BEFORE the broad ~/projects fallthrough.
var pathClassTable = []pathClassEntry{
	// Claude Code — plugin marketplace ships third-party plugins. These
	// are UPSTREAM (we cannot ask Anthropic to fix a Discord bot's deps).
	{"~/.claude/plugins/marketplaces/*/external_plugins/**", finding.FixAuthorityUpstream, ""},
	// Claude Code — plugin cache, owned by the plugin vendor. Vendor
	// hint is the directory immediately under cache/.
	{"~/.claude/plugins/cache/**", finding.FixAuthorityMaintainer, ""},
	// Claude Code — user's own session transcripts. YOU rotate, even
	// though Anthropic-managed file format. Secrets-only path; AI-agent
	// rules don't fire here.
	{"~/.claude/projects/**", finding.FixAuthorityYou, ""},

	// Cursor — vendored extensions ship under ~/.cursor/extensions/.
	{"~/.cursor/extensions/**", finding.FixAuthorityMaintainer, "cursor"},

	// Codex CLI — config is user-owned.
	{"~/.codex/**", finding.FixAuthorityYou, ""},

	// Windsurf — config is user-owned.
	{"~/.codeium/**", finding.FixAuthorityYou, ""},

	// System-installed npm + go module cache — third-party, UPSTREAM
	// (we cannot fix a globally installed package without uninstalling
	// it; report-and-track is the realistic action).
	{"/usr/lib/node_modules/**", finding.FixAuthorityUpstream, ""},
	{"/usr/local/lib/node_modules/**", finding.FixAuthorityUpstream, ""},
	{"~/go/pkg/mod/**", finding.FixAuthorityUpstream, ""},

	// User shell config and home-level secrets/state — YOU.
	{"~/.zshrc", finding.FixAuthorityYou, ""},
	{"~/.bashrc", finding.FixAuthorityYou, ""},
	{"~/.profile", finding.FixAuthorityYou, ""},
	{"~/.zprofile", finding.FixAuthorityYou, ""},
	{"~/.aws/**", finding.FixAuthorityYou, ""},
	{"~/.env", finding.FixAuthorityYou, ""},
	{"~/.env.local", finding.FixAuthorityYou, ""},

	// Anywhere else under HOME or absolute — default YOU. The fallthrough
	// is the safe default: assume the user owns the path; the dashboard
	// will surface an actionable fix rather than a "wait for vendor" hint.
	{"**", finding.FixAuthorityYou, ""},
}

// Classify returns the FixAuthority and maintainer hint for a path. The
// path is the absolute filesystem path; HOME-relative matching is
// performed by replacing the user's HOME prefix with "~" before matching
// against pathClassTable entries.
func Classify(path, home string) (finding.FixAuthority, string) {
	canon := canonicalize(path, home)
	for _, entry := range pathClassTable {
		if matchPathPattern(entry.pattern, canon) {
			maintainer := entry.maintainer
			if entry.authority == finding.FixAuthorityMaintainer && maintainer == "" {
				maintainer = extractClaudePluginVendor(canon)
			}
			return entry.authority, maintainer
		}
	}
	// Defensive — pathClassTable's last entry is "**" which always matches.
	// If somehow nothing matched, default to FixAuthorityYou so the user
	// always sees an actionable item rather than a silent demotion.
	return finding.FixAuthorityYou, ""
}

// ForSecret post-processes a (authority, maintainer) classification for a
// secret-family finding (Betterleaks, audr-native secret rules). A leaked
// key must be rotated by the user no matter where it appeared, so the
// primary authority is always FixAuthorityYou; if the path lived in a
// vendor tree, the original classification's maintainer hint is preserved
// as the secondary-notify.
func ForSecret(authority finding.FixAuthority, maintainer string) (finding.FixAuthority, string) {
	// The user rotates the key. If the path was vendor-shipped, we hold
	// onto the maintainer so the UI can say "rotate — and also notify X."
	if authority != finding.FixAuthorityYou {
		return finding.FixAuthorityYou, maintainer
	}
	return finding.FixAuthorityYou, ""
}

// canonicalize replaces the HOME prefix with "~" so the table can be
// authored without knowing the user's actual home directory. Paths
// outside HOME are returned verbatim.
func canonicalize(path, home string) string {
	if home == "" {
		return path
	}
	if path == home {
		return "~"
	}
	prefix := home
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	if strings.HasPrefix(path, prefix) {
		return "~" + string(filepath.Separator) + path[len(prefix):]
	}
	return path
}

// matchPathPattern returns true if `path` matches `pattern`. The pattern
// language is filepath.Match per segment, plus a literal "**" segment
// that matches any number of intermediate segments (zero or more).
//
// Examples:
//   "~/.claude/plugins/cache/**"          matches "~/.claude/plugins/cache/vercel/0.42.1/bun.lock"
//   "~/.cursor/extensions/**"             matches "~/.cursor/extensions/foo/node_modules/x"
//   "**"                                  matches any path
//   "~/projects/audr/web/package-lock.json" matches only that exact path
func matchPathPattern(pattern, path string) bool {
	// Empty paths never match — a degenerate empty string slipping
	// through to FixAuthorityYou via the "**" fallthrough would silently
	// classify "nothing" as actionable, which is misleading.
	if path == "" {
		return false
	}
	pSegs := splitSegments(pattern)
	tSegs := splitSegments(path)
	return matchSegs(pSegs, tSegs)
}

func splitSegments(s string) []string {
	// Strip a trailing separator so "~/a/" splits the same way as "~/a".
	s = strings.TrimSuffix(s, string(filepath.Separator))
	if s == "" {
		return nil
	}
	return strings.Split(s, string(filepath.Separator))
}

// matchSegs recursively matches pattern segments against target segments,
// with "**" wildcarding zero-or-more segments. This is the standard
// "match each segment with filepath.Match, **=any" approach.
func matchSegs(pat, tgt []string) bool {
	for len(pat) > 0 {
		head := pat[0]
		if head == "**" {
			// "**" at end matches all remaining segments.
			if len(pat) == 1 {
				return true
			}
			// "**" in middle — try matching the rest against every suffix
			// of tgt. Cost is bounded; v1.3 patterns have at most one "**".
			for i := 0; i <= len(tgt); i++ {
				if matchSegs(pat[1:], tgt[i:]) {
					return true
				}
			}
			return false
		}
		// Non-** segment requires a corresponding target segment.
		if len(tgt) == 0 {
			return false
		}
		ok, err := filepath.Match(head, tgt[0])
		if err != nil || !ok {
			return false
		}
		pat = pat[1:]
		tgt = tgt[1:]
	}
	return len(tgt) == 0
}

// extractClaudePluginVendor pulls the vendor name out of a Claude plugin
// cache path. The plugin cache directory layout is
// "~/.claude/plugins/cache/<vendor>/<version>/...". Returns empty for
// paths that don't match this layout.
func extractClaudePluginVendor(canonicalPath string) string {
	const prefix = "~/.claude/plugins/cache/"
	if !strings.HasPrefix(canonicalPath, prefix) {
		return ""
	}
	rest := canonicalPath[len(prefix):]
	if rest == "" {
		return ""
	}
	if i := strings.IndexRune(rest, filepath.Separator); i > 0 {
		return rest[:i]
	}
	return rest
}
