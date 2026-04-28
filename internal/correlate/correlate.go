// Package correlate runs after the per-document rule pipeline. It walks
// the full set of findings + parsed documents and produces "Attack Chains"
// — attacker-POV narratives that fire when specific finding combinations
// are present. The chains render at the top of the HTML report and in the
// JSON output.
//
// Design choice: scenarios are hand-written Go functions rather than a
// templating engine. Three reasons.
//
//  1. The total set is small (5-15 chains in v0.2). Templating buys
//     nothing at this scale; it just adds complexity.
//  2. Each chain has its own logic for which findings count and how to
//     render the narrative. Forcing them into a uniform template costs
//     readability without saving code.
//  3. Plain Go functions are easy to test. A templated DSL is not.
package correlate

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/agentguard/agentguard/internal/finding"
	"github.com/agentguard/agentguard/internal/output"
	"github.com/agentguard/agentguard/internal/parse"
)

// Run produces attack chains given the full scan output. It does not modify
// the findings list — chains are independent and reference findings by
// rule ID + path.
func Run(findings []finding.Finding, docs []*parse.Document) []output.AttackChain {
	idx := newFindingIndex(findings, docs)
	var chains []output.AttackChain
	for _, scenario := range scenarios {
		if chain, ok := scenario(idx); ok {
			chains = append(chains, chain)
		}
	}
	// Stable order: by severity (worst first), then by ID.
	sort.SliceStable(chains, func(i, j int) bool {
		if chains[i].Severity != chains[j].Severity {
			return chains[i].Severity < chains[j].Severity // Critical=0 < High=1 < ...
		}
		return chains[i].ID < chains[j].ID
	})
	return chains
}

// findingIndex is a lookup helper passed to each scenario. Pre-builds the
// indices each scenario uses, so individual scenarios stay terse.
type findingIndex struct {
	all     []finding.Finding
	byRule  map[string][]finding.Finding
	docs    []*parse.Document
	docByPath map[string]*parse.Document
}

func newFindingIndex(findings []finding.Finding, docs []*parse.Document) *findingIndex {
	idx := &findingIndex{
		all:       findings,
		byRule:    map[string][]finding.Finding{},
		docs:      docs,
		docByPath: map[string]*parse.Document{},
	}
	for _, f := range findings {
		idx.byRule[f.RuleID] = append(idx.byRule[f.RuleID], f)
	}
	for _, d := range docs {
		if d != nil {
			idx.docByPath[d.Path] = d
		}
	}
	return idx
}

func (idx *findingIndex) has(ruleID string) bool {
	return len(idx.byRule[ruleID]) > 0
}

func (idx *findingIndex) hasAny(ruleIDs ...string) bool {
	for _, id := range ruleIDs {
		if idx.has(id) {
			return true
		}
	}
	return false
}

func (idx *findingIndex) findings(ruleID string) []finding.Finding {
	return idx.byRule[ruleID]
}

func (idx *findingIndex) paths(ruleID string) []string {
	out := make([]string, 0, len(idx.byRule[ruleID]))
	seen := map[string]bool{}
	for _, f := range idx.byRule[ruleID] {
		if !seen[f.Path] {
			seen[f.Path] = true
			out = append(out, f.Path)
		}
	}
	return out
}

// hasReadablePrivateKey returns true if any scanned root contains an SSH
// private key. The scanner doesn't currently flag bare files, so we
// approximate via the parsed-document set: if a document at <root>/.ssh/id_*
// (non-.pub) was attempted, the file existed.
func (idx *findingIndex) hasReadablePrivateKey() bool {
	for path := range idx.docByPath {
		base := filepath.Base(path)
		dir := filepath.Base(filepath.Dir(path))
		if dir == ".ssh" && strings.HasPrefix(base, "id_") && !strings.HasSuffix(base, ".pub") {
			return true
		}
	}
	return false
}

// dedupeSorted returns input slice with duplicates removed, sorted.
func dedupeSorted(s []string) []string {
	seen := map[string]bool{}
	for _, v := range s {
		seen[v] = true
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// firstOf returns the first non-empty string from values.
func firstOf(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
