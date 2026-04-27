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

	"github.com/agentguard/agentguard/internal/redact"
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
	Match        string   `json:"match,omitempty"`        // already redacted
	Context      string   `json:"context,omitempty"`      // already redacted
	SuggestedFix string   `json:"suggested_fix,omitempty"`
	Tags         []string `json:"tags,omitempty"`
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
		RuleID:       a.RuleID,
		Severity:     a.Severity,
		Taxonomy:     a.Taxonomy,
		Title:        a.Title,
		Description:  a.Description,
		Path:         a.Path,
		Line:         a.Line,
		Match:        redact.String(a.Match),
		Context:      redact.Lines(a.Context),
		SuggestedFix: a.SuggestedFix,
		Tags:         append([]string(nil), a.Tags...),
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

// SortKey provides a stable ordering for output: severity desc, then path,
// then line. Used by the collector before formatters serialize.
func (f Finding) SortKey() (int, string, int) {
	return int(f.Severity), f.Path, f.Line
}
