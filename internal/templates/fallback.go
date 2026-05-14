package templates

import (
	"fmt"

	"github.com/harshmaur/audr/internal/state"
)

// fallbackHandler is the last-resort dispatch: any finding that no
// per-rule or per-prefix handler claimed lands here. Rather than 404
// the dashboard's Copy AI Prompt button (the Phase 4 demo failure
// mode), we emit a generic but useful prompt parameterized by category.
//
// The prompt is intentionally honest: it tells the agent "audr
// doesn't have a hand-authored template for this rule yet" so the
// agent doesn't pretend to follow specific instructions it doesn't
// have.
func fallbackHandler(f state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	if path == "" {
		path = "(see locator)"
	}

	human := fmt.Sprintf(`Finding: %s

%s

Path: %s

Suggested approach:
1. Read the description carefully — it usually contains the specific change to make.
2. If a "SuggestedFix" was attached to this finding by audr's rule definition, follow it literally.
3. After the change, rerun audr (or wait for the next scan cycle) to confirm the finding cleared.`,
		f.Title, f.Description, path)

	ai := fmt.Sprintf(`audr flagged the following %s finding (rule: %s):

Title: %s
Description: %s
Locator: %s

NOTE: audr does not have a hand-authored remediation template for this rule yet (it's not one of the v0.2 built-ins or a known OSV ecosystem). Please:

1. Read the title + description above carefully.
2. Find the offending content in the file/package identified by the locator.
3. Propose the smallest possible fix consistent with the description.
4. Show me the diff before applying — I want to review since this is following an audr-generated generic prompt rather than a specific template.
5. Do not modify any file other than the one named by the locator.`,
		f.Category, f.RuleID, f.Title, f.Description, summarizeLocator(loc))

	return human, ai, true
}

// summarizeLocator renders a one-line locator summary for the AI
// prompt, since the full JSON isn't readable. Falls back to a key:value
// dump when the kind isn't recognized.
func summarizeLocator(loc Locator) string {
	if path := loc.String("path"); path != "" {
		if line := loc.Int("line"); line > 0 {
			return fmt.Sprintf("%s:%d", path, line)
		}
		return path
	}
	if mgr := loc.String("manager"); mgr != "" {
		return fmt.Sprintf("%s package %s %s", mgr, loc.String("name"), loc.String("version"))
	}
	if eco := loc.String("ecosystem"); eco != "" {
		return fmt.Sprintf("%s package %s@%s in %s", eco, loc.String("name"), loc.String("version"), loc.String("manifest_path"))
	}
	return "(unrecognized locator shape)"
}
