// Package rules holds the rule registry. Rules implement Rule and register
// themselves via Register; the scanner asks the registry for all rules
// applicable to a given Document.Format.
package rules

import (
	"sort"
	"sync"

	"github.com/harshmaur/agentguard/internal/finding"
	"github.com/harshmaur/agentguard/internal/parse"
)

// Rule is the unit of policy. One Rule may inspect many file formats and emit
// zero or more findings per Document.
type Rule interface {
	// ID is a stable kebab-case identifier (e.g. "mcp-unpinned-npx").
	ID() string
	// Title is a short human-readable description.
	Title() string
	// Severity reports the rule's default severity.
	Severity() finding.Severity
	// Taxonomy reports whether this rule is enforced/detectable/advisory.
	Taxonomy() finding.Taxonomy
	// Formats lists the parse.Format values this rule examines.
	Formats() []parse.Format
	// Apply runs the rule against a parsed Document, returning zero or more
	// findings. It must NOT mutate the Document.
	Apply(doc *parse.Document) []finding.Finding
}

// Registry holds all rules available to the scanner.
type Registry struct {
	mu      sync.RWMutex
	byID    map[string]Rule
	enabled map[string]bool
}

// global is the package-wide default registry, populated at init() time.
// Tests can construct their own via NewRegistry().
var global = NewRegistry()

// NewRegistry constructs an empty rule registry.
func NewRegistry() *Registry {
	return &Registry{
		byID:    map[string]Rule{},
		enabled: map[string]bool{},
	}
}

// Register adds a rule to the global registry. Panics on duplicate ID.
// Intended to be called from init() in rule packages.
func Register(r Rule) {
	global.Add(r)
}

// All returns all rules in the global registry, sorted by ID for stable
// output.
func All() []Rule {
	return global.All()
}

// Add adds a rule. Panics on duplicate ID.
func (r *Registry) Add(rule Rule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byID[rule.ID()]; exists {
		panic("rules: duplicate rule ID: " + rule.ID())
	}
	r.byID[rule.ID()] = rule
	r.enabled[rule.ID()] = true
}

// All returns all rules sorted by ID.
func (r *Registry) All() []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Rule, 0, len(r.byID))
	for _, rule := range r.byID {
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// ForFormat returns rules that target a given Document Format.
func (r *Registry) ForFormat(f parse.Format) []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Rule
	for _, rule := range r.byID {
		if !r.enabled[rule.ID()] {
			continue
		}
		for _, rf := range rule.Formats() {
			if rf == f {
				out = append(out, rule)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// ForFormat is the package-level shortcut for global.ForFormat.
func ForFormat(f parse.Format) []Rule {
	return global.ForFormat(f)
}

// Apply runs every applicable rule on the document and returns all findings.
// Used by the scanner per-document.
func Apply(doc *parse.Document) []finding.Finding {
	if doc == nil {
		return nil
	}
	var out []finding.Finding
	for _, rule := range ForFormat(doc.Format) {
		out = append(out, rule.Apply(doc)...)
	}
	return out
}
