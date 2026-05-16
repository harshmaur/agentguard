package triage

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
)

// DefaultDedupKey computes a stable dedup key for a finding whose rule
// did not pre-populate Finding.DedupGroupKey. The key collapses findings
// that represent the SAME underlying vulnerability across multiple paths
// while keeping findings from DIFFERENT rules distinct (rule_id is the
// first key component, so cross-rule collisions are impossible by
// construction).
//
// Signature inputs are kept narrow on purpose:
//
//   - RuleID — different rule, different vulnerability, period.
//   - A normalised match signature (lowercase, leading/trailing
//     whitespace trimmed) so two findings of the same rule that match
//     the same payload collapse, even when one was found inside a
//     vendored copy and one in user code.
//   - Title (as fallback) so rules whose match field is empty still get
//     a distinct key when their titles differ.
//
// Path is INTENTIONALLY excluded — the whole point of the v1.3 dedup
// design is collapsing the same finding across paths.
func DefaultDedupKey(f finding.Finding) string {
	sig := normalizeSignature(f.Match)
	if sig == "" {
		sig = normalizeSignature(f.Title)
	}
	h := sha256.New()
	h.Write([]byte(f.RuleID))
	h.Write([]byte{0x00})
	h.Write([]byte(sig))
	return f.RuleID + ":" + hex.EncodeToString(h.Sum(nil))[:16]
}

// FillTriageFields populates the v1.3 fields on a finding when the rule
// did not supply them:
//
//   - DedupGroupKey defaults from DefaultDedupKey.
//   - FixAuthority defaults from path-class classification.
//   - SecondaryNotify defaults from the same path-class lookup.
//
// Rules that pre-populate any of these fields always win — triage only
// fills blanks.
//
// `home` is the user's HOME directory; pass os.UserHomeDir() at the
// call site. Empty `home` is safe (path-class matching skips the
// HOME-canonicalisation step).
func FillTriageFields(f finding.Finding, home string) finding.Finding {
	if f.DedupGroupKey == "" {
		f.DedupGroupKey = DefaultDedupKey(f)
	}
	if f.FixAuthority == "" {
		auth, maintainer := Classify(f.Path, home)
		f.FixAuthority = auth
		if f.SecondaryNotify == "" {
			f.SecondaryNotify = maintainer
		}
	}
	return f
}

// normalizeSignature lowercases + trims a match payload so casing /
// whitespace variation across detected occurrences doesn't fragment the
// dedup group. The output is opaque — it's only used as a hash input.
func normalizeSignature(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
