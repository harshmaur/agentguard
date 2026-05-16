// Package finding defines the Finding type emitted by parsers and rules.
//
// Findings are constructed via New, which applies redaction to all
// secret-containing fields BEFORE the value is stored. After construction,
// no field of a Finding contains an unredacted secret. This is the defense-
// in-depth boundary referenced in the design doc — every output formatter,
// every log, every panic stack trace sees only redacted strings.
package finding

import (
	"encoding/json"
	"fmt"

	"github.com/harshmaur/audr/internal/redact"
)

// Severity ranks findings P0 (release-blocking) through P3 (informational).
type Severity int

const (
	SeverityCritical Severity = iota // P0 — secret exposed, tampered binary, etc.
	SeverityHigh                     // P1 — high-risk capability combo
	SeverityMedium                   // P2 — should be reviewed
	SeverityLow                      // P3 — informational / advisory
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	}
	return "unknown"
}

// MarshalJSON renders Severity as its string form.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// Taxonomy is the enforced/detectable/advisory classification from the design
// doc. Every finding carries one — buyers depend on this label being honest.
type Taxonomy string

const (
	TaxEnforced   Taxonomy = "enforced"
	TaxDetectable Taxonomy = "detectable"
	TaxAdvisory   Taxonomy = "advisory"
)

// FixAuthority answers "who can actually fix this?" — the v1.3 partition
// that lets the dashboard surface the user's own actions ahead of "wait for
// upstream." See parallels-main-design-loveable-audr-20260515-171437.md.
type FixAuthority string

const (
	// FixAuthorityYou — the user can pin the dep, rotate the key, or edit
	// the config from their own seat. Default for any path that isn't
	// explicitly classified as vendor-shipped.
	FixAuthorityYou FixAuthority = "you"
	// FixAuthorityMaintainer — finding lives in a vendored plugin / extension
	// cache. The plugin maintainer must publish a fix; the user can uninstall
	// the plugin or file an upstream issue. SecondaryNotify carries the
	// maintainer hint (e.g. "vercel", "cursor").
	FixAuthorityMaintainer FixAuthority = "maintainer"
	// FixAuthorityUpstream — finding lives in a third-party package bundled
	// inside a marketplace / external-plugins tree. Only the original
	// maintainer can fix; the user can only track upstream.
	FixAuthorityUpstream FixAuthority = "upstream"
)

// Finding is the unit emitted by every rule + parse-error path. After
// construction via New, no string field contains a raw secret.
type Finding struct {
	RuleID       string   `json:"rule_id"`
	Severity     Severity `json:"severity"`
	Taxonomy     Taxonomy `json:"taxonomy"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Path         string   `json:"path,omitempty"`
	Line         int      `json:"line,omitempty"`
	Match        string   `json:"match,omitempty"`   // already redacted
	Context      string   `json:"context,omitempty"` // already redacted
	SuggestedFix string   `json:"suggested_fix,omitempty"`
	Tags         []string `json:"tags,omitempty"`

	// DedupGroupKey groups findings that represent the same underlying
	// vulnerability across multiple paths. Rules SHOULD set this when they
	// can identify the same threat across files (e.g. OSV emits
	// "osv:<pkg>:<fixed>:<cve>"). If empty, internal/triage will compute
	// a stable default from (rule_id, normalized signature).
	DedupGroupKey string `json:"dedup_group_key,omitempty"`

	// FixAuthority partitions a rolled-up finding by who can actually act
	// on it. If empty, internal/triage classifies from Path against the
	// path-class table. Rules normally leave this unset; secret-family
	// rules force FixAuthorityYou regardless of path.
	FixAuthority FixAuthority `json:"fix_authority,omitempty"`

	// SecondaryNotify carries a maintainer hint (e.g. "vercel") when the
	// finding's path lives in a vendor tree. Used to render a
	// "report to <vendor>" link alongside the primary action.
	// Always populated for FixAuthorityMaintainer; optionally populated
	// for FixAuthorityYou when a secret leaked into a vendor dir.
	SecondaryNotify string `json:"secondary_notify,omitempty"`
}

// Args describes the not-yet-redacted inputs to New. Fields that may contain
// secrets are redacted before being stored on the Finding.
type Args struct {
	RuleID       string
	Severity     Severity
	Taxonomy     Taxonomy
	Title        string
	Description  string
	Path         string
	Line         int
	Match        string // raw — will be redacted
	Context      string // raw — will be redacted
	SuggestedFix string
	Tags         []string

	// Optional v1.3 fields — empty zero-values are safe, internal/triage
	// fills them in if the rule leaves them blank.
	DedupGroupKey   string
	FixAuthority    FixAuthority
	SecondaryNotify string
}

// New constructs a Finding, applying redaction to Match and Context fields
// before they are stored. Title/Description are NOT redacted because they
// describe the rule, not the matched payload. Path is not redacted because
// file paths on a developer machine are not secrets — and redacting them
// would make findings unactionable.
func New(a Args) Finding {
	if a.Taxonomy == "" {
		a.Taxonomy = TaxDetectable
	}
	return Finding{
		RuleID:          a.RuleID,
		Severity:        a.Severity,
		Taxonomy:        a.Taxonomy,
		Title:           a.Title,
		Description:     a.Description,
		Path:            a.Path,
		Line:            a.Line,
		Match:           redact.String(a.Match),
		Context:         redact.Lines(a.Context),
		SuggestedFix:    a.SuggestedFix,
		Tags:            append([]string(nil), a.Tags...),
		DedupGroupKey:   a.DedupGroupKey,
		FixAuthority:    a.FixAuthority,
		SecondaryNotify: a.SecondaryNotify,
	}
}

// Location returns "path:line" or just "path" when line is unset.
// Useful for log lines and the [SEVERITY] (confidence) line:N format.
func (f Finding) Location() string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d", f.Path, f.Line)
	}
	return f.Path
}

// Less provides a total, stable ordering for output. Severity sorts from most
// severe to least severe (SeverityCritical=0), followed by location and then
// finding content so duplicate findings on the same line cannot inherit
// nondeterministic rule/map iteration order.
func Less(a, b Finding) bool {
	if a.Severity != b.Severity {
		return a.Severity < b.Severity
	}
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	if a.RuleID != b.RuleID {
		return a.RuleID < b.RuleID
	}
	if a.Title != b.Title {
		return a.Title < b.Title
	}
	if a.Description != b.Description {
		return a.Description < b.Description
	}
	if a.Match != b.Match {
		return a.Match < b.Match
	}
	return a.Context < b.Context
}

// SortKey provides the primary ordering components for callers that need to
// display or group findings. Use Less when a total ordering is required.
func (f Finding) SortKey() (int, string, int) {
	return int(f.Severity), f.Path, f.Line
}
