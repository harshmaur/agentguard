package parse

import (
	"path/filepath"
	"regexp"
	"strings"
)

// parseSkill extracts the YAML frontmatter (if present) and body from a skill
// markdown file. The frontmatter parser is intentionally simple — we don't
// pull in a full YAML parser for this format because skill frontmatter is
// flat (top-level key: value). Lists like `allowed-tools:` get split.
func parseSkill(path string, raw []byte) (*Skill, error) {
	s := &Skill{
		Frontmatter: map[string]string{},
		Name:        strings.TrimSuffix(filepath.Base(path), ".md"),
	}
	body := string(raw)

	if strings.HasPrefix(body, "---\n") {
		if end := strings.Index(body[4:], "\n---"); end > 0 {
			fm := body[4 : 4+end]
			body = strings.TrimSpace(body[4+end+4:])
			parseSimpleFrontmatter(fm, s)
		}
	}
	s.Body = body

	// Detect tools referenced via tool-INVOCATION patterns in the body.
	// Plain prose mentions ("uses Bash to run X") are NOT counted as tool
	// use — that produces hundreds of false positives on real skills that
	// document tools without invoking them. Real invocations look like:
	//   - backtick-quoted: `Bash`
	//   - code-block-fenced with the tool name on a leading line
	//   - structured: `Tool: Bash` or `Tools:\n  - Bash`
	//   - JSON/YAML tool references: `"tool": "Bash"`
	for _, tool := range knownToolNames {
		if toolInvocationPatterns[tool].MatchString(s.Body) {
			if !contains(s.Tools, tool) {
				s.Tools = append(s.Tools, tool)
			}
		}
	}

	return s, nil
}

func parseSimpleFrontmatter(fm string, s *Skill) {
	for _, line := range strings.Split(fm, "\n") {
		line = strings.TrimRight(line, " \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		val = strings.Trim(val, `"' `)
		if key == "name" || key == "description" || key == "version" || key == "author" || key == "license" {
			s.Frontmatter[key] = val
			if key == "name" && val != "" {
				s.Name = val
			}
			continue
		}
		// Lists in YAML look like "key:" with bullets below.
		// We capture the *header* value only here; lists across lines
		// would need a real YAML parser.
		s.Frontmatter[key] = val

		if key == "allowed-tools" || key == "tools" {
			// Single-line CSV/space-separated list.
			parts := splitToolList(val)
			s.Tools = append(s.Tools, parts...)
		}
	}
}

func splitToolList(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.Trim(s, "[] ")
	parts := regexp.MustCompile(`[,\s]+`).Split(s, -1)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.Trim(p, `"'`)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

// knownToolNames is a small list of agent tool identifiers we track. Picking
// these up in the skill body lets a rule flag a skill that uses Bash/WebFetch
// without declaring it in `allowed-tools`.
var knownToolNames = []string{
	"Bash", "WebFetch", "WebSearch", "Edit", "Write", "Read",
	"NotebookEdit", "Task", "Agent", "Glob", "Grep",
}

// toolInvocationPatterns is built once at init time. The runtime parse path
// reads it concurrently from many goroutines; building it lazily inside
// parseSkill caused a "concurrent map writes" panic when two workers parsed
// skills at the same time.
var toolInvocationPatterns = func() map[string]*regexp.Regexp {
	m := make(map[string]*regexp.Regexp, len(knownToolNames))
	for _, tool := range knownToolNames {
		pat := regexp.QuoteMeta(tool)
		m[tool] = regexp.MustCompile(
			"(?m)" +
				"(?:^\\s*-\\s*" + pat + "\\b)" + // YAML list bullet
				"|(?:`" + pat + "`)" + // inline code
				"|(?:\"" + pat + "\")" + // JSON/YAML string
				"|(?:\\bTool:\\s*" + pat + "\\b)" + // explicit Tool: label
				"|(?:\\bTools?:\\s*\\[[^\\]]*\\b" + pat + "\\b)", // tools: [Bash]
		)
	}
	return m
}()
