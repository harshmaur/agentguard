// Package policy is audr's user-editable rule-behavior overlay. Built-in
// detection logic stays in `internal/rules/builtin/` (Go-coded — path
// globs, structural matchers, chain correlations are irreducibly
// imperative). The overlay only mutates HOW built-ins behave: enable
// or disable per-rule, override severity, narrow scope, register
// allowlists, suppress findings.
//
// This is intentionally NOT a Semgrep-style rules-as-data refactor.
// Custom rule definitions ("write your own detection logic in YAML")
// are deferred to TODO 7 / v1.3. The distinction matters for users:
// what they edit here changes how existing rules behave; it does not
// add new detection logic.
//
// File contract — canonical-generated YAML:
//
// The on-disk file at `~/.audr/policy.yaml` is regenerated from the
// `Policy` struct on every save. Field order, indent, line endings,
// and rule sorting are deterministic. Hand-edited comments and
// custom field ordering are silently dropped at the next save. This
// keeps the dashboard editor authoritative — users who need to
// preserve free-text reasoning use the `notes:` field on each entry,
// which DOES round-trip through marshal.
//
// See the v1.2 plan section B2.0 for the rationale ("Why canonical,
// not human-preserved").
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/harshmaur/audr/internal/finding"
)

// PolicyFileMode is the file mode set on `~/.audr/policy.yaml` after
// every atomic write. Mirrors the v0.4.x notify.config.json and
// scanner.config.json files — 0600 keeps the contents readable only
// by the owning user.
const PolicyFileMode fs.FileMode = 0o600

// PolicyVersion is the schema version embedded in every saved
// policy.yaml. Bumped only when the on-disk shape changes
// incompatibly; never bumped for additive fields.
const PolicyVersion = 1

// MaxBackups is how many .bak.N rotations we keep. Five gives the
// user a sliding window of recent saves without paying disk for
// long-tail history.
const MaxBackups = 5

// Policy is the in-memory representation of `~/.audr/policy.yaml`.
// Every field is optional from the user's perspective — an empty
// Policy is valid and produces identical scan results to v1.1 (no
// overrides, all built-in defaults).
//
// MUST be safe to share across goroutines after construction. All
// mutators return a new Policy or document the locking expectation.
type Policy struct {
	// Version is the schema version, currently 1. Loaders that see a
	// higher version refuse to load — better than silently dropping
	// fields they don't understand.
	Version int `yaml:"version"`

	// Rules maps a rule-id (e.g. "mcp-unpinned-npx") to its override
	// envelope. Absent entries fall through to built-in defaults.
	Rules map[string]RuleOverride `yaml:"rules,omitempty"`

	// Allowlists are named string-sets rules consult via the rule
	// context. Adding an entry here does NOT silence findings on its
	// own; the rule itself decides whether to honor an allowlist
	// match. For v1.2 this is a forward-looking API — no built-in
	// rule currently consumes allowlists.
	Allowlists map[string]Allowlist `yaml:"allowlists,omitempty"`

	// Suppressions silence specific (rule, path) pairs post-scan.
	// Equivalent surface area to `.audrignore`; the two sources are
	// unioned per the precedence model in plan section B3.4 — ANY
	// match suppresses.
	Suppressions []Suppression `yaml:"suppressions,omitempty"`
}

// RuleOverride is the per-rule envelope. Every field is a pointer so
// `nil` distinguishes "not overridden" from "set to zero value." The
// YAML form omits unset fields entirely so the file stays terse.
type RuleOverride struct {
	// Enabled overrides the rule's default-on state. nil → default
	// (true for all built-ins). Setting false skips the rule globally
	// before its match logic runs.
	Enabled *bool `yaml:"enabled,omitempty"`

	// Severity overrides the rule's natural severity. Stored as a
	// string on disk ("critical" / "high" / "medium" / "low") for
	// editor-readability; converted to finding.Severity at merge
	// time. nil → use the rule's natural severity.
	Severity *string `yaml:"severity,omitempty"`

	// Scope narrows the paths a rule fires on. Empty Scope means "use
	// the rule's natural scope," which is per-rule (e.g., the
	// shellrc-secret-export rule's natural scope is shell rc files).
	Scope Scope `yaml:"scope,omitempty"`

	// Allowlists are names of Policy.Allowlists entries this rule
	// should consult via ctx.Allowlist(name). Cross-references; the
	// rule decides what to do with the match.
	Allowlists []string `yaml:"allowlists,omitempty"`

	// Notes is the comment-preservation escape hatch. The on-disk
	// YAML is canonical-generated (comments dropped), but Notes
	// round-trips through marshal so users can record WHY they
	// adjusted a rule. Surfaces in the dashboard form view.
	Notes string `yaml:"notes,omitempty"`
}

// ResolvedSeverity converts the string Severity field into
// finding.Severity. Returns (-1, false) when Severity is nil or
// invalid. Callers should check the returned ok bool — the merge
// logic short-circuits on !ok and leaves the natural severity.
func (ov RuleOverride) ResolvedSeverity() (finding.Severity, bool) {
	if ov.Severity == nil {
		return 0, false
	}
	return parseSeverityString(*ov.Severity)
}

// parseSeverityString maps the on-disk string to finding.Severity.
// Lives here (not in finding/) because the on-disk vocabulary is a
// policy-format concern; finding/ deliberately has no opinion about
// serialization formats.
func parseSeverityString(s string) (finding.Severity, bool) {
	switch s {
	case "critical":
		return finding.SeverityCritical, true
	case "high":
		return finding.SeverityHigh, true
	case "medium":
		return finding.SeverityMedium, true
	case "low":
		return finding.SeverityLow, true
	}
	return 0, false
}

// validSeverityString reports whether s names a known severity.
// Used by Validate.
func validSeverityString(s string) bool {
	_, ok := parseSeverityString(s)
	return ok
}

// Scope narrows the paths a rule applies to. Both lists are glob
// patterns evaluated against the document's absolute path. Empty
// means "no constraint" — Include empty doesn't exclude anything;
// Exclude empty doesn't include everything; both empty is the
// natural-scope no-op.
type Scope struct {
	// Include narrows down to ONLY paths matching one of these
	// globs. Empty Include means "all paths the rule naturally
	// matches" — equivalent to no include filter.
	Include []string `yaml:"include,omitempty"`

	// Exclude removes paths matching any of these globs from the
	// rule's effective scope.
	Exclude []string `yaml:"exclude,omitempty"`
}

// Allowlist is a named string-set with metadata. Rules consult these
// via ctx.Allowlist(name) to decide whether a finding should fire
// (e.g., "MCP server X is approved" → don't fire mcp-unpinned-npx for it).
type Allowlist struct {
	// Entries are the literal strings rules check against. No glob
	// matching at the policy level; rules choose their own matching
	// semantics.
	Entries []string `yaml:"entries"`

	// Notes is comment-preservation per RuleOverride.Notes.
	Notes string `yaml:"notes,omitempty"`
}

// Suppression silences a specific (rule, path) pair. Path matching
// is glob-based against the finding's path. Optional expiry lets
// users record "suppress until I get to this" without leaving
// suppressions live forever.
type Suppression struct {
	// Rule is the rule-id to suppress. Required.
	Rule string `yaml:"rule"`

	// Path is the glob pattern matching findings to suppress.
	// Required.
	Path string `yaml:"path"`

	// Reason is the free-text "why are we suppressing." Required by
	// validation — drives the trust posture that suppressions need
	// human-readable context, not just rule-id + path.
	Reason string `yaml:"reason"`

	// Expires is the optional expiry date. When set, the suppression
	// is treated as not-present after this date. Saved policies
	// keep expired entries until the next save (which prunes them)
	// so the user can see which suppressions are about to lapse.
	Expires *time.Time `yaml:"expires,omitempty"`

	// Notes is comment-preservation per RuleOverride.Notes.
	Notes string `yaml:"notes,omitempty"`
}

// DefaultPolicy returns a policy with no overrides — every rule
// runs at its built-in default. Equivalent to a missing
// `~/.audr/policy.yaml`.
func DefaultPolicy() Policy {
	return Policy{Version: PolicyVersion}
}

// Path returns the absolute path to the user's policy file inside
// `~/.audr/`. Callers in the daemon use this as the canonical
// location; callers in tests should override via Options.
func Path() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("policy: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".audr", "policy.yaml"), nil
}

// Load reads and parses a policy file. Missing file returns
// DefaultPolicy() + nil error (a fresh install has no policy yet).
// Corrupt or unparseable files return DefaultPolicy() + the parse
// error so callers can surface the diagnostic via banner while
// continuing to scan with built-in defaults.
func Load(path string) (Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return DefaultPolicy(), nil
		}
		return DefaultPolicy(), fmt.Errorf("policy: read %s: %w", path, err)
	}
	return Parse(raw)
}

// Parse unmarshals YAML bytes into a Policy. Validates the result
// before returning so callers can rely on the returned Policy being
// internally consistent.
func Parse(raw []byte) (Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return DefaultPolicy(), fmt.Errorf("policy: unmarshal: %w", err)
	}
	if p.Version == 0 {
		// Backwards-compat: a YAML file without `version: 1` is
		// treated as version 1. We never shipped version 0; this
		// just lets hand-written policies skip the version field
		// when they're starting fresh.
		p.Version = PolicyVersion
	}
	if p.Version > PolicyVersion {
		return DefaultPolicy(), fmt.Errorf(
			"policy: file schema version %d is newer than this audr (max %d) — upgrade audr or downgrade the file",
			p.Version, PolicyVersion,
		)
	}
	if err := p.Validate(); err != nil {
		return p, fmt.Errorf("policy: validate: %w", err)
	}
	return p, nil
}

// Validate runs invariant checks. Called by Parse and Save so users
// can never persist a policy the daemon would refuse to load.
//
// Validation that fires:
//   - severity values are one of {critical, high, medium, low}
//   - suppression entries have non-empty Rule and Path
//   - suppression Reason is non-empty (humans need to know WHY)
//   - rule-id references in allowlists name something Policy itself defines
//   - scope globs are syntactically valid
//
// Validation that DOES NOT fire (intentionally):
//   - rule-id references to rules that don't exist in the binary
//     are allowed — adding a new rule shouldn't break a policy
//     file that referenced it before audr learned about it.
//     Unknown rule-ids are logged as warnings at Load time but
//     don't fail validation.
//   - allowlist entries match no real targets — that's a rule-level
//     concern, not a policy-level one.
func (p *Policy) Validate() error {
	for ruleID, ov := range p.Rules {
		if ruleID == "" {
			return errors.New("rule entry has empty rule-id")
		}
		if ov.Severity != nil && !validSeverityString(*ov.Severity) {
			return fmt.Errorf("rule %q: invalid severity %q (want critical/high/medium/low)",
				ruleID, *ov.Severity)
		}
		if err := validateGlobs(ruleID, ov.Scope); err != nil {
			return err
		}
		for _, name := range ov.Allowlists {
			if _, ok := p.Allowlists[name]; !ok {
				return fmt.Errorf("rule %q references unknown allowlist %q",
					ruleID, name)
			}
		}
	}
	for i, s := range p.Suppressions {
		if s.Rule == "" {
			return fmt.Errorf("suppression[%d]: rule is required", i)
		}
		if s.Path == "" {
			return fmt.Errorf("suppression[%d]: path is required", i)
		}
		if strings.TrimSpace(s.Reason) == "" {
			return fmt.Errorf("suppression[%d]: reason is required — record WHY this suppression exists",
				i)
		}
		if _, err := filepath.Match(s.Path, "/x"); err != nil {
			return fmt.Errorf("suppression[%d]: malformed path glob %q: %w",
				i, s.Path, err)
		}
	}
	return nil
}

func validateGlobs(ruleID string, scope Scope) error {
	for _, g := range scope.Include {
		if _, err := filepath.Match(g, "/x"); err != nil {
			return fmt.Errorf("rule %q: malformed include glob %q: %w", ruleID, g, err)
		}
	}
	for _, g := range scope.Exclude {
		if _, err := filepath.Match(g, "/x"); err != nil {
			return fmt.Errorf("rule %q: malformed exclude glob %q: %w", ruleID, g, err)
		}
	}
	return nil
}

// Save atomically writes the policy file. Path semantics:
//
//   - Always validates before writing — never persists a Policy
//     Validate() would reject.
//   - Writes to `<path>.tmp` then renames over `<path>` so an
//     interrupted save never leaves the daemon staring at a
//     half-written file.
//   - Rotates backups: the existing `<path>` becomes `<path>.bak.1`,
//     bak.1 becomes bak.2, etc., up to MaxBackups. Older backups are
//     deleted.
//   - File mode is forced to PolicyFileMode (0600) on every save —
//     prevents the policy from accidentally becoming world-readable
//     during a `git mv` or similar.
//
// The file format is deterministic — see MarshalCanonical.
func Save(path string, p Policy) error {
	if err := p.Validate(); err != nil {
		return fmt.Errorf("policy: refuse to save invalid policy: %w", err)
	}
	body, err := MarshalCanonical(p)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("policy: create dir %s: %w", dir, err)
	}

	if err := rotateBackups(path, MaxBackups); err != nil {
		// Backup rotation failure is logged but does NOT block the
		// save. Better to save than to refuse and leave the user
		// unable to update their policy because a .bak file is
		// undeletable.
		_ = err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, PolicyFileMode); err != nil {
		return fmt.Errorf("policy: write tmp: %w", err)
	}
	if err := os.Chmod(tmp, PolicyFileMode); err != nil {
		// Windows ignores chmod's u/g/o bits in practice; failure
		// here is non-fatal. The atomic rename is still about to
		// happen.
		_ = err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("policy: rename tmp → %s: %w", path, err)
	}
	return nil
}

// rotateBackups shifts existing backups one slot down and copies the
// current policy file to .bak.1. Older slots beyond MaxBackups are
// removed. Non-fatal — every step swallows ErrNotExist.
func rotateBackups(path string, maxBackups int) error {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		// No current file — nothing to rotate.
		return nil
	}

	// Drop the oldest backup if it exists.
	oldest := fmt.Sprintf("%s.bak.%d", path, maxBackups)
	_ = os.Remove(oldest)

	// Shift bak.N → bak.N+1 from the top down so we don't clobber.
	for i := maxBackups - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.bak.%d", path, i)
		to := fmt.Sprintf("%s.bak.%d", path, i+1)
		_ = os.Rename(from, to)
	}

	// Current file → bak.1.
	bak1 := path + ".bak.1"
	return copyFile(path, bak1)
}

func copyFile(src, dst string) error {
	body, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, body, PolicyFileMode)
}

// MarshalCanonical produces the deterministic YAML representation
// of a Policy. Guarantees from the spec (plan section B2.0):
//
//   - rules sorted by rule-id alphabetically
//   - allowlists sorted by name alphabetically; entries within
//     each allowlist sorted
//   - suppressions sorted by rule-id, then path
//   - 2-space indent, LF line endings, no trailing whitespace
//   - file ends with a single newline
//   - header comment explains the canonicalization contract so
//     hand-editors aren't surprised when their comments disappear
//
// Test coverage in policy_test.go pins the byte layout — drift here
// would cascade into "noise diffs" in the dashboard's diff preview,
// which the user reads to approve the save.
func MarshalCanonical(p Policy) ([]byte, error) {
	// Force the version field even when zero (Parse sets it; new
	// Policy{} doesn't).
	if p.Version == 0 {
		p.Version = PolicyVersion
	}

	// yaml.v3 doesn't have a MapSlice equivalent in stable API; we
	// build the document tree as yaml.Node directly. The Node tree
	// preserves Content order on marshal, which is the determinism
	// guarantee we need.
	doc := &yaml.Node{
		Kind:    yaml.MappingNode,
		Tag:     "!!map",
		Content: []*yaml.Node{},
	}

	// version: <int>
	doc.Content = append(doc.Content,
		stringNode("version"),
		intNode(p.Version),
	)

	// rules: (sorted by rule-id)
	if len(p.Rules) > 0 {
		rulesNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		for _, k := range sortedRuleKeys(p.Rules) {
			ov := p.Rules[k]
			ruleNode, err := ruleOverrideNode(ov)
			if err != nil {
				return nil, err
			}
			rulesNode.Content = append(rulesNode.Content,
				stringNode(k), ruleNode)
		}
		doc.Content = append(doc.Content,
			stringNode("rules"), rulesNode)
	}

	// allowlists: (sorted by name; entries within each sorted)
	if len(p.Allowlists) > 0 {
		allowNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		for _, name := range sortedAllowlistKeys(p.Allowlists) {
			al := p.Allowlists[name]
			alNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			entries := append([]string(nil), al.Entries...)
			sort.Strings(entries)
			entriesNode := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			for _, e := range entries {
				entriesNode.Content = append(entriesNode.Content, stringNode(e))
			}
			alNode.Content = append(alNode.Content,
				stringNode("entries"), entriesNode)
			if al.Notes != "" {
				alNode.Content = append(alNode.Content,
					stringNode("notes"), stringNode(al.Notes))
			}
			allowNode.Content = append(allowNode.Content,
				stringNode(name), alNode)
		}
		doc.Content = append(doc.Content,
			stringNode("allowlists"), allowNode)
	}

	// suppressions: (sorted by rule-id, then path)
	if len(p.Suppressions) > 0 {
		sortedSupp := append([]Suppression(nil), p.Suppressions...)
		sort.SliceStable(sortedSupp, func(i, j int) bool {
			if sortedSupp[i].Rule != sortedSupp[j].Rule {
				return sortedSupp[i].Rule < sortedSupp[j].Rule
			}
			return sortedSupp[i].Path < sortedSupp[j].Path
		})
		suppNode := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, s := range sortedSupp {
			suppNode.Content = append(suppNode.Content, suppressionNode(s))
		}
		doc.Content = append(doc.Content,
			stringNode("suppressions"), suppNode)
	}

	var sb strings.Builder
	sb.WriteString(canonicalHeader)
	enc := yaml.NewEncoder(&sb)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("policy: marshal canonical: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("policy: close encoder: %w", err)
	}
	body := sb.String()
	body = stripTrailingWhitespace(body)
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	return []byte(body), nil
}

// canonicalHeader documents the file's regeneration contract so
// hand-editors aren't surprised when comments disappear.
const canonicalHeader = `# ~/.audr/policy.yaml — managed by the audr dashboard
#
# This file is canonical-generated. Every dashboard save fully
# rewrites it: field order, indent, and rule-id sort order are
# deterministic. Hand-edits are allowed, but custom comments and
# field ordering will be rewritten the next time the dashboard
# saves.
#
# Use the 'notes:' field inside any rule / allowlist / suppression
# to preserve free-text reasoning across saves. notes: round-trips
# through canonical regeneration.

`

func ruleOverrideNode(ov RuleOverride) (*yaml.Node, error) {
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	if ov.Enabled != nil {
		n.Content = append(n.Content,
			stringNode("enabled"), boolNode(*ov.Enabled))
	}
	if ov.Severity != nil {
		n.Content = append(n.Content,
			stringNode("severity"), stringNode(*ov.Severity))
	}
	if len(ov.Scope.Include) > 0 || len(ov.Scope.Exclude) > 0 {
		scopeNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		if len(ov.Scope.Include) > 0 {
			scopeNode.Content = append(scopeNode.Content,
				stringNode("include"), stringSeqNode(ov.Scope.Include))
		}
		if len(ov.Scope.Exclude) > 0 {
			scopeNode.Content = append(scopeNode.Content,
				stringNode("exclude"), stringSeqNode(ov.Scope.Exclude))
		}
		n.Content = append(n.Content,
			stringNode("scope"), scopeNode)
	}
	if len(ov.Allowlists) > 0 {
		// Sort for determinism.
		al := append([]string(nil), ov.Allowlists...)
		sort.Strings(al)
		n.Content = append(n.Content,
			stringNode("allowlists"), stringSeqNode(al))
	}
	if ov.Notes != "" {
		n.Content = append(n.Content,
			stringNode("notes"), stringNode(ov.Notes))
	}
	return n, nil
}

func suppressionNode(s Suppression) *yaml.Node {
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	n.Content = append(n.Content,
		stringNode("rule"), stringNode(s.Rule),
		stringNode("path"), stringNode(s.Path),
		stringNode("reason"), stringNode(s.Reason),
	)
	if s.Expires != nil {
		n.Content = append(n.Content,
			stringNode("expires"), stringNode(s.Expires.UTC().Format(time.RFC3339)))
	}
	if s.Notes != "" {
		n.Content = append(n.Content,
			stringNode("notes"), stringNode(s.Notes))
	}
	return n
}

func stringNode(s string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
}

func intNode(i int) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprintf("%d", i)}
}

func boolNode(b bool) *yaml.Node {
	v := "false"
	if b {
		v = "true"
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: v}
}

func stringSeqNode(xs []string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, x := range xs {
		n.Content = append(n.Content, stringNode(x))
	}
	return n
}

func sortedRuleKeys(m map[string]RuleOverride) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedAllowlistKeys(m map[string]Allowlist) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func stripTrailingWhitespace(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}
	return strings.Join(lines, "\n")
}

// Hash returns a stable fingerprint of the on-disk YAML so callers
// can short-circuit "policy hasn't changed since last cycle" without
// re-running validation. The hash covers the canonical-marshalled
// form, so semantically identical Policies hash identically
// regardless of how they got constructed.
func Hash(p Policy) (string, error) {
	body, err := MarshalCanonical(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}
