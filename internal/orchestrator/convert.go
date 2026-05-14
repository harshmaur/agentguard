// Package orchestrator owns audr's daemon-mode scan loop: schedule
// scans, drive the existing scan/depscan/secretscan engines, convert
// their findings to the kind+locator state schema (D17), persist via
// the state store, detect resolutions, and report per-category scanner
// status (D4).
//
// Phase 4 ships this as the subsystem that replaces SeedDemoFindings.
// Phase 3 will replace the periodic timer trigger with the smart
// watch+poll engine; the orchestrator API (RunOnce, scope, persistence)
// doesn't change — only the producer of scan invocations does.
package orchestrator

import (
	"encoding/json"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/state"
)

// findingToStateFinding lifts the legacy file-overfit finding shape
// into the state-store's kind+locator row (eng-review D17). Every
// current rule produces file-shaped findings — Path + Line are
// always present — so kind="file" is the only conversion. Future
// scanners (ospkg, dep) emit state.Finding directly without going
// through this converter.
//
// scanID is the FK that ties this finding to the scan cycle that
// produced it (first_seen + last_seen). The store decides whether
// this is a brand-new finding or a re-detection based on the
// fingerprint.
func findingToStateFinding(f finding.Finding, scanID int64, category string) (state.Finding, error) {
	locatorBytes, err := json.Marshal(map[string]any{
		"path": f.Path,
		"line": f.Line,
	})
	if err != nil {
		return state.Finding{}, err
	}

	fp, err := state.Fingerprint(f.RuleID, "file", locatorBytes, f.Match)
	if err != nil {
		return state.Finding{}, err
	}

	return state.Finding{
		Fingerprint:   fp,
		RuleID:        f.RuleID,
		Severity:      f.Severity.String(), // typed Severity → "critical"/"high"/...
		Category:      category,
		Kind:          "file",
		Locator:       locatorBytes,
		Title:         f.Title,
		Description:   f.Description,
		MatchRedacted: f.Match,
		FirstSeenScan: scanID,
		LastSeenScan:  scanID,
	}, nil
}

// categorizeRuleID maps a rule-ID to one of the four dashboard
// categories. Defaults to "ai-agent" because v0.2's 20 built-in rules
// are all AI-agent-shaped; secret findings (which we ingest from
// TruffleHog separately) override this to "secrets" at the orchestrator
// callsite.
//
// The mapping is intentionally explicit: an unknown new rule that gets
// added without a category mapping lands in "ai-agent" by default,
// which is the safest bucket for v0.2's surface area.
func categorizeRuleID(ruleID string) string {
	switch {
	case strings.HasPrefix(ruleID, "secret-"):
		return "secrets"
	case strings.HasPrefix(ruleID, "osv-"),
		strings.HasPrefix(ruleID, "dep-"):
		return "deps"
	case strings.HasPrefix(ruleID, "ospkg-"):
		return "os-pkg"
	default:
		return "ai-agent"
	}
}
