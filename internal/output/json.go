package output

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/harshmaur/audr/internal/finding"
)

// JSONReport is the wire shape of `audr scan -f json` (and the same shape
// produced by `audr findings ls --format json`). The `schema:` field
// points at the published JSON Schema (audr.dev/schema/report.v1.json)
// and the same schema document is embedded in the binary via T13's
// --print-schema flag.
//
// The shape is intentionally additive: new optional fields can land in a
// minor release without changing the schema URL, and consumers that
// don't know about them must ignore them. Required fields are listed at
// the top of this struct; everything `omitempty` is optional.
type JSONReport struct {
	Schema      string            `json:"schema"`
	Version     string            `json:"version"`
	GeneratedAt time.Time         `json:"generated_at"`
	Stats       JSONStats         `json:"stats"`
	Findings    []finding.Finding `json:"findings"`

	Roots        []string      `json:"roots,omitempty"`
	SelfAudit    string        `json:"self_audit,omitempty"`
	Warnings     []string      `json:"warnings,omitempty"`
	AttackChains []AttackChain `json:"attack_chains,omitempty"`

	// AppliedFilters is non-nil when this JSONReport was produced by
	// `audr findings ls` with one or more filter flags set. Lets the
	// agent know the findings list is a filtered view rather than the
	// full scan. Always nil on direct `audr scan -f json` output.
	AppliedFilters *AppliedFilters `json:"applied_filters,omitempty"`

	// BaselineDiff is non-nil when `audr scan --baseline=<path>` was
	// invoked. Carries the three lists (resolved, still_present,
	// newly_introduced) plus the suppressions_off invariant flag.
	// The diff truth is computed against the unsuppressed scanner
	// result so agents cannot fake "resolved" by adding the rule to
	// .audrignore.
	BaselineDiff *BaselineDiff `json:"baseline_diff,omitempty"`
}

// JSONStats are the per-scan counts. Fields are non-omitempty (zero is a
// real, meaningful value — "no findings at all" is not the same as
// "field absent").
type JSONStats struct {
	FilesSeen   int `json:"files_seen"`
	FilesParsed int `json:"files_parsed"`
	Suppressed  int `json:"suppressed"`
	Skipped     int `json:"skipped"`
	Total       int `json:"total"`
	Critical    int `json:"critical"`
	High        int `json:"high"`
	Medium      int `json:"medium"`
	Low         int `json:"low"`
}

// AppliedFilters records which `audr findings ls` filter expressions
// were applied. Empty fields mean "no filter on that axis."
type AppliedFilters struct {
	Severity     string `json:"severity,omitempty"`      // "ge:high", "eq:critical", etc.
	FixAuthority string `json:"fix_authority,omitempty"` // "you", "maintainer", "upstream"
	RuleID       string `json:"rule_id,omitempty"`       // glob pattern
}

// BaselineDiff is the structured result of `audr scan --baseline=<path>`.
// Each *Fingerprints field is a list of 12-char StableID prefixes (the
// same ids `audr findings show <id>` consumes).
//
// SuppressionsOff is always true in v1.1 — it documents the invariant
// that the diff truth is computed against the raw scanner result, not
// the user's filtered view. Future versions may add a permissive
// "honor suppressions in diff" mode behind a flag; the field is here
// so consumers can detect that mode if it ever ships.
type BaselineDiff struct {
	BaselinePath       string   `json:"baseline_path"`
	BaselineScannedAt  string   `json:"baseline_scanned_at,omitempty"`
	Resolved           []string `json:"resolved"`
	StillPresent       []string `json:"still_present"`
	NewlyIntroduced    []string `json:"newly_introduced"`
	SuppressionsOff    bool     `json:"suppressions_off"`
}

// SchemaURL is the canonical JSON Schema URL embedded in every Report.
// Both `audr scan -f json` and `audr findings ls --format json` emit
// this value, so a consumer can fetch the schema once and validate
// every audr output against it.
const SchemaURL = "https://audr.dev/schema/report.v1.json"

// JSON writes the report as pretty-printed JSON. This is the
// scan-side entry point; it builds a JSONReport from the in-memory
// Report shape and serializes via WriteJSON.
func JSON(w io.Writer, r Report) error {
	findings := r.Findings
	if findings == nil {
		findings = []finding.Finding{}
	}
	jr := JSONReport{
		Schema:       SchemaURL,
		Version:      nonEmpty(r.Version, "0.0.0-dev"),
		GeneratedAt:  r.FinishedAt,
		Roots:        r.Roots,
		SelfAudit:    r.SelfAudit,
		Warnings:     r.Warnings,
		AttackChains: r.AttackChains,
		Findings:     findings,
		BaselineDiff: r.BaselineDiff,
	}
	jr.Stats = ComputeStats(findings, r.FilesSeen, r.FilesParsed, r.Suppressed, r.Skipped)
	return WriteJSON(w, jr)
}

// DiffBaseline computes the baseline_diff struct from a prior scan's
// findings and a current scan's findings. ids are derived via
// StableID() — the 12-char prefix used everywhere else in the AI fix
// loop.
//
// Set semantics: each id is counted at most once per list. Duplicates
// within either input collapse.
//
// The caller is responsible for passing the UNSUPPRESSED current
// findings (i.e., the raw scanner result before .audrignore filtering)
// — otherwise the diff truth lies about resolution. SuppressionsOff is
// always true in v1.1 to document this invariant.
func DiffBaseline(prior, current []finding.Finding, baselinePath, baselineScannedAt string) BaselineDiff {
	priorIDs := idSet(prior)
	currentIDs := idSet(current)

	out := BaselineDiff{
		BaselinePath:      baselinePath,
		BaselineScannedAt: baselineScannedAt,
		Resolved:          []string{},
		StillPresent:      []string{},
		NewlyIntroduced:   []string{},
		SuppressionsOff:   true,
	}
	for id := range priorIDs {
		if _, ok := currentIDs[id]; ok {
			out.StillPresent = append(out.StillPresent, id)
		} else {
			out.Resolved = append(out.Resolved, id)
		}
	}
	for id := range currentIDs {
		if _, ok := priorIDs[id]; !ok {
			out.NewlyIntroduced = append(out.NewlyIntroduced, id)
		}
	}
	// Deterministic ordering for byte-stable test golden files.
	sortStrings(out.Resolved)
	sortStrings(out.StillPresent)
	sortStrings(out.NewlyIntroduced)
	return out
}

func idSet(fs []finding.Finding) map[string]struct{} {
	m := make(map[string]struct{}, len(fs))
	for _, f := range fs {
		id := f.StableID()
		if id == "" {
			continue
		}
		m[id] = struct{}{}
	}
	return m
}

func sortStrings(s []string) {
	// Inline sort to avoid pulling in sort just for two helpers.
	// findings counts are small enough that O(n^2) is fine.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// WriteJSON serializes a JSONReport as pretty-printed JSON. Use this
// when you already have a JSONReport in hand (e.g., `findings ls`
// emits a filtered JSONReport built from a prior scan's bytes).
func WriteJSON(w io.Writer, jr JSONReport) error {
	if jr.Findings == nil {
		jr.Findings = []finding.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(jr); err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}
	return nil
}

// LoadJSON parses a Report from the wire JSON shape. Used by
// `audr findings ls / show` to consume a prior `audr scan -f json`
// output via --from or stdin, and by `audr scan --baseline` to read
// the baseline file.
//
// Unknown fields are accepted, not rejected — the schema contract is
// additive across minor versions, so a v1.1 binary reading a v1.2-
// produced Report must succeed even if v1.2 added new top-level keys.
// Strict shape validation belongs to external JSON Schema tooling
// (audr scan --print-schema | jq --schema...), not the runtime parser.
//
// Returns an error with a clear message if the input is empty or
// malformed — agents reading the error must see why their input was
// rejected.
func LoadJSON(r io.Reader) (JSONReport, error) {
	dec := json.NewDecoder(r)
	var jr JSONReport
	if err := dec.Decode(&jr); err != nil {
		return JSONReport{}, fmt.Errorf("parse audr report JSON: %w", err)
	}
	// Defensive normalization: nil findings becomes empty slice so
	// downstream filter logic doesn't have to nil-check.
	if jr.Findings == nil {
		jr.Findings = []finding.Finding{}
	}
	return jr, nil
}

// ComputeStats derives a JSONStats from a findings slice plus the
// scan-cycle counters. Exposed for `findings ls` which recomputes stats
// against the filtered findings slice (the original Stats from the
// unfiltered report no longer matches the visible findings).
func ComputeStats(findings []finding.Finding, filesSeen, filesParsed, suppressed, skipped int) JSONStats {
	out := JSONStats{
		FilesSeen:   filesSeen,
		FilesParsed: filesParsed,
		Suppressed:  suppressed,
		Skipped:     skipped,
	}
	for _, f := range findings {
		out.Total++
		switch f.Severity {
		case finding.SeverityCritical:
			out.Critical++
		case finding.SeverityHigh:
			out.High++
		case finding.SeverityMedium:
			out.Medium++
		case finding.SeverityLow:
			out.Low++
		}
	}
	return out
}
