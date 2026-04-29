// Package suppress reads .audrignore files and matches finding paths
// against the configured rules.
//
// Syntax (kept intentionally simple):
//   - One pattern per line.
//   - Lines starting with `#` are comments.
//   - `rule-id` alone disables that rule globally.
//   - `path/glob` (supports * and **) suppresses ALL findings under that path.
//   - `rule-id path/glob` suppresses that rule under that path.
//   - Inline form for source files: `# audr:disable=rule-id` (handled
//     elsewhere — this package handles only .audrignore).
package suppress

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Rule is one parsed line from a .audrignore.
type Rule struct {
	RuleID  string // empty = applies to all rules
	Glob    string // empty = applies everywhere
	rawLine string
}

// Set is a parsed .audrignore.
type Set struct {
	rules []Rule
}

// LoadFile reads a .audrignore from disk. Returns an empty Set if the
// file does not exist (suppression is opt-in).
func LoadFile(path string) (*Set, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Set{}, nil
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	return Parse(f)
}

// Parse reads suppression rules from any io.Reader-like source.
func Parse(r interface {
	Read(p []byte) (n int, err error)
}) (*Set, error) {
	s := &Set{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s.rules = append(s.rules, parseLine(line))
	}
	return s, scanner.Err()
}

// parseLine parses one suppression line.
//   "rule-id"               -> {RuleID: "rule-id"}
//   "path/**"               -> {Glob: "path/**"}
//   "rule-id path/**"       -> {RuleID: "rule-id", Glob: "path/**"}
func parseLine(line string) Rule {
	r := Rule{rawLine: line}
	parts := strings.Fields(line)
	switch len(parts) {
	case 1:
		// Either a rule-id (kebab-case identifier) or a path glob.
		if isIdentifier(parts[0]) {
			r.RuleID = parts[0]
		} else {
			r.Glob = parts[0]
		}
	default:
		r.RuleID = parts[0]
		r.Glob = parts[1]
	}
	return r
}

// isIdentifier is heuristic: kebab-case identifier with no path separators or
// glob metacharacters.
func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= '0' && ch <= '9':
		case ch == '-':
		default:
			return false
		}
	}
	return true
}

// Suppresses returns true if the (ruleID, path) pair is suppressed by any
// configured rule.
func (s *Set) Suppresses(ruleID, path string) bool {
	if s == nil {
		return false
	}
	for _, r := range s.rules {
		if r.RuleID != "" && r.RuleID != ruleID {
			continue
		}
		if r.Glob != "" {
			if matched, _ := matchGlob(r.Glob, path); !matched {
				continue
			}
		}
		return true
	}
	return false
}

// matchGlob returns true if path matches glob.
// Supports `*` for single-segment wildcard and `**` for multi-segment.
func matchGlob(glob, path string) (bool, error) {
	// Convert ** to a placeholder filepath.Match doesn't understand, then
	// degrade to a simpler split-and-match approach.
	if strings.Contains(glob, "**") {
		// Match by splitting on "**" and ensuring each component appears in order.
		parts := strings.Split(glob, "**")
		idx := 0
		for i, p := range parts {
			if p == "" {
				continue
			}
			j := strings.Index(path[idx:], strings.TrimPrefix(strings.TrimSuffix(p, "/"), "/"))
			if j < 0 {
				return false, nil
			}
			if i == 0 && j != 0 && !strings.HasPrefix(p, "/") {
				return false, nil
			}
			idx += j + len(p)
		}
		return true, nil
	}
	return filepath.Match(glob, path)
}
