package policy

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/harshmaur/audr/internal/finding"
)

// Effective is the merged view a Policy presents to the rule registry.
// Built from a (Policy, time.Time) pair so suppression expiry can be
// evaluated against a single canonical clock (test-overridable).
//
// All methods on Effective are read-only and safe for concurrent use.
// Construction is cheap — O(rules + allowlists + suppressions). The
// daemon orchestrator builds one per scan cycle at the top of each
// cycle's runOnce.
type Effective struct {
	p   Policy
	now time.Time
}

// NewEffective constructs an Effective view. When now is the zero
// time.Time, time.Now() is used.
func NewEffective(p Policy, now time.Time) Effective {
	if now.IsZero() {
		now = time.Now()
	}
	return Effective{p: p, now: now}
}

// IsRuleEnabled reports whether the rule should run at all.
// Defaults to true (rule fires) when there's no override. Honoring
// false is the first precedence step in plan section B3.4.
func (e Effective) IsRuleEnabled(ruleID string) bool {
	ov, ok := e.p.Rules[ruleID]
	if !ok {
		return true
	}
	if ov.Enabled == nil {
		return true
	}
	return *ov.Enabled
}

// IsPathInScope tests whether a path passes the rule's policy-defined
// scope filter. Returns true when:
//   - No override exists (rule's natural scope applies).
//   - Override has neither Include nor Exclude (no constraint).
//   - Path matches at least one Include and no Exclude.
//
// Implements steps 3 and 4 of the precedence model from B3.4.
//
// Glob semantics: filepath.Match — supports `*`, `?`, `[abc]`.
// Does NOT support `**` (filepath.Match's known limitation). We
// document this in the user-facing dashboard tooltip — the policy
// editor surfaces a "scope glob" tooltip explaining what's
// supported.
//
// Path matching also handles `~/...` home-relative prefixes: when a
// glob starts with `~/`, we substitute the user's home directory
// before matching.
func (e Effective) IsPathInScope(ruleID, path string) bool {
	ov, ok := e.p.Rules[ruleID]
	if !ok {
		return true
	}
	if len(ov.Scope.Include) == 0 && len(ov.Scope.Exclude) == 0 {
		return true
	}

	// Exclude wins over include — a path matching both is out.
	for _, glob := range ov.Scope.Exclude {
		if matchPathGlob(glob, path) {
			return false
		}
	}

	if len(ov.Scope.Include) == 0 {
		// No include constraint set — only excludes apply.
		return true
	}
	for _, glob := range ov.Scope.Include {
		if matchPathGlob(glob, path) {
			return true
		}
	}
	return false
}

// EffectiveSeverity returns the severity the finding should be
// emitted with. Implements step 7 of B3.4 — applied AFTER the rule
// has already decided to fire, so suppression precedence still
// applies above this.
func (e Effective) EffectiveSeverity(ruleID string, natural finding.Severity) finding.Severity {
	ov, ok := e.p.Rules[ruleID]
	if !ok {
		return natural
	}
	if sev, ok := ov.ResolvedSeverity(); ok {
		return sev
	}
	return natural
}

// IsSuppressed reports whether a (rule, path) is policy-suppressed.
// Implements step 6a of B3.4. Path matching uses filepath.Match
// against the suppression's glob; the path is compared as-is. The
// caller is responsible for the union with `.audrignore`-sourced
// suppressions (handled in the rules registry wrap, not here).
//
// Expired suppressions are silently ignored — same as not-present.
// The dashboard surfaces expired entries separately so the user
// knows to prune them, but at scan time they no longer silence
// findings.
func (e Effective) IsSuppressed(ruleID, path string) bool {
	for _, s := range e.p.Suppressions {
		if s.Rule != ruleID {
			continue
		}
		if s.Expires != nil && s.Expires.Before(e.now) {
			continue // expired
		}
		if matchPathGlob(s.Path, path) {
			return true
		}
	}
	return false
}

// Allowlist returns the named allowlist's entries, or an empty
// slice when the name is unknown. Rules consume this via
// ctx.Allowlist(name) — the rule itself decides what to do with
// the match (e.g., "MCP server X is approved" → skip emission).
func (e Effective) Allowlist(name string) []string {
	al, ok := e.p.Allowlists[name]
	if !ok {
		return nil
	}
	return append([]string(nil), al.Entries...)
}

// AllowlistContains is the convenience method rules will most often
// reach for: "is this string in the named allowlist?"
func (e Effective) AllowlistContains(name, item string) bool {
	al, ok := e.p.Allowlists[name]
	if !ok {
		return false
	}
	for _, e := range al.Entries {
		if e == item {
			return true
		}
	}
	return false
}

// Policy returns the underlying Policy for diagnostics. Avoid
// modifying — the Effective view shares the same memory.
func (e Effective) Policy() Policy { return e.p }

// matchPathGlob is the path-matching primitive used across scope
// and suppression. Handles ~ prefix expansion, then delegates to
// filepath.Match. Returns false on any Match error (caller treats
// a malformed glob as "doesn't match" — Validate has already
// rejected the policy if a glob was malformed at save time, so a
// match-error here would be from a runtime path containing weird
// characters).
//
// Treats both forward + backward slashes as separators so a
// Windows-native path matches a Unix-style glob in the policy. The
// daemon scans cross-platform paths in v1.1; the policy file uses
// portable globs.
func matchPathGlob(glob, path string) bool {
	if strings.HasPrefix(glob, "~/") {
		if home, err := homeDir(); err == nil {
			glob = filepath.Join(home, strings.TrimPrefix(glob, "~/"))
		}
	}
	// Normalize separators so a `/.cursor/**`-style glob matches
	// `C:\Users\X\.cursor\foo` after walking.
	normPath := strings.ReplaceAll(path, "\\", "/")
	normGlob := strings.ReplaceAll(glob, "\\", "/")

	// filepath.Match doesn't support `**`. For v1.2 we accept this
	// limitation; the dashboard form view exposes scope as a
	// freeform string and the doc explains supported globs.
	// Substitute a single `*` for `**` so common patterns like
	// `~/.cursor/**` work as "anything under ~/.cursor". This is
	// less precise than true `**` but covers the 95% case.
	normGlob = strings.ReplaceAll(normGlob, "**", "*")

	ok, _ := filepath.Match(normGlob, normPath)
	if ok {
		return true
	}
	// Fallback: a glob like `~/.cursor/*` also matches paths
	// containing `~/.cursor/` as a prefix (broader semantics most
	// users expect). Try a prefix match against the literal portion
	// before the first wildcard.
	if i := strings.IndexAny(normGlob, "*?["); i > 0 {
		prefix := normGlob[:i]
		if strings.HasPrefix(normPath, prefix) {
			return true
		}
	}
	return false
}

// homeDir is a thin wrapper that allows tests to override home
// resolution. Currently delegates to os.UserHomeDir directly; the
// wrapper lets a future enhancement plumb a config-supplied home
// without changing every call site.
func homeDir() (string, error) {
	return userHomeDirFunc()
}

// userHomeDirFunc indirects through a var so tests can swap it.
// Production: os.UserHomeDir.
var userHomeDirFunc = os.UserHomeDir
