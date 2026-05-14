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

// depscanFindingToState lifts a depscan-emitted finding into the
// kind="dep-package" state-store row shape. depscan packs the
// ecosystem + package + version into the Match field as
// "<ecosystem> <name>@<version>" and the advisory ID + fixed version
// into Context as "advisory=<id> fixed=<ver>". We parse those back
// out so the locator + fingerprint are correctly structured.
//
// On parse failure we fall back to file-kind treatment (path/line)
// so the finding still reaches the dashboard, just under the wrong
// kind. Better than dropping it silently.
func depscanFindingToState(f finding.Finding, scanID int64) (state.Finding, error) {
	ecosystem, name, version, ok := parseDepscanMatch(f.Match)
	if !ok {
		// Couldn't parse Match — fall back to file kind via the
		// shared converter so the finding still surfaces.
		return findingToStateFinding(f, scanID, "deps")
	}
	advisoryID, _ := parseDepscanContext(f.Context)

	locator := map[string]any{
		"ecosystem":     ecosystem,
		"name":          name,
		"version":       version,
		"manifest_path": f.Path,
	}
	locatorBytes, err := json.Marshal(locator)
	if err != nil {
		return state.Finding{}, err
	}

	fpInput := advisoryID
	if fpInput == "" {
		fpInput = f.RuleID
	}
	fp, err := state.Fingerprint(f.RuleID, "dep-package", locatorBytes, fpInput)
	if err != nil {
		return state.Finding{}, err
	}

	return state.Finding{
		Fingerprint:   fp,
		RuleID:        ruleIDForDepEcosystem(ecosystem),
		Severity:      f.Severity.String(),
		Category:      "deps",
		Kind:          "dep-package",
		Locator:       locatorBytes,
		Title:         f.Title,
		Description:   f.Description,
		MatchRedacted: advisoryID,
		FirstSeenScan: scanID,
		LastSeenScan:  scanID,
	}, nil
}

// parseDepscanMatch parses depscan's Match field, which is built as
// `fmt.Sprintf("%s %s@%s", ecosystem, name, version)`.
//
// Returns ok=false when the shape doesn't match — caller falls back
// to file-kind treatment so the finding still surfaces.
func parseDepscanMatch(match string) (ecosystem, name, version string, ok bool) {
	// First token = ecosystem (no spaces allowed).
	space := strings.IndexByte(match, ' ')
	if space < 0 {
		return "", "", "", false
	}
	ecosystem = match[:space]
	rest := match[space+1:]

	// Split name@version on the LAST '@' so scoped packages like
	// @types/node@1.0.0 still split correctly (the leading @ is
	// part of the name).
	at := strings.LastIndexByte(rest, '@')
	if at <= 0 {
		return "", "", "", false
	}
	name = rest[:at]
	version = rest[at+1:]
	if name == "" || version == "" {
		return "", "", "", false
	}
	return ecosystem, name, version, true
}

// parseDepscanContext extracts advisory + fixed_in from depscan's
// Context field, formatted as `advisory=<id> fixed=<ver>`.
func parseDepscanContext(ctx string) (advisoryID, fixedIn string) {
	for _, part := range strings.Fields(ctx) {
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		switch part[:eq] {
		case "advisory":
			advisoryID = part[eq+1:]
		case "fixed":
			fixedIn = part[eq+1:]
		}
	}
	return advisoryID, fixedIn
}

// ruleIDForDepEcosystem mints a rule_id that the templates library can
// dispatch on. Format: `osv-<ecosystem>-package`. We don't include the
// package name in the rule_id (would explode the template surface).
func ruleIDForDepEcosystem(ecosystem string) string {
	return "osv-" + strings.ToLower(strings.ReplaceAll(ecosystem, ".", "-")) + "-package"
}
