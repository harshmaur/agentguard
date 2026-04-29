package builtin

import (
	"github.com/harshmaur/audr/internal/parse"
	"github.com/harshmaur/audr/internal/rules"
)

// applyRule runs every rule applicable to doc.Format and returns the IDs
// that fired (one ID entry per finding produced).
func applyRule(doc *parse.Document) []string {
	out := []string{}
	for _, r := range rules.All() {
		formats := r.Formats()
		matched := false
		for _, f := range formats {
			if f == doc.Format {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		findings := r.Apply(doc)
		for range findings {
			out = append(out, r.ID())
		}
	}
	return out
}

// fired returns true if the named rule fired at least once on doc.
func fired(doc *parse.Document, ruleID string) bool {
	for _, id := range applyRule(doc) {
		if id == ruleID {
			return true
		}
	}
	return false
}
