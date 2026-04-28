// Package output renders Findings into HTML / SARIF / JSON.
//
// Output formatters are pure: they consume already-redacted Findings and
// produce serialized bytes. Redaction happened at finding-construction time;
// formatters never see raw secrets.
package output

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/agentguard/agentguard/internal/finding"
)

//go:embed report.html.tmpl
var htmlTemplate string

// Report is the input to all formatters.
type Report struct {
	Findings     []finding.Finding
	AttackChains []AttackChain // v0.2.0-alpha.5 — narrative scenarios across multiple findings
	Roots        []string
	StartedAt    time.Time
	FinishedAt   time.Time
	FilesSeen    int
	FilesParsed  int
	Suppressed   int
	Skipped      int
	Version      string
	SelfAudit    string // "clean (cosign-verified)" / "clean (unverified)" / "TAMPERED" / "skipped"
}

// AttackChain is an attacker-POV narrative that fires when a specific
// combination of findings is present. Renders at the top of the HTML
// report and in the JSON output. SARIF skips it (no narrative concept).
//
// Severity is the chain's own severity, NOT the max of its underlying
// findings: some chains take 3 Highs and combine into a Critical because
// the combination is qualitatively worse than any single finding.
type AttackChain struct {
	ID         string           // stable ID, e.g. "repo-clone-hook-rce"
	Title      string           // one-line title
	Severity   finding.Severity // chain severity
	Narrative  string           // attacker-POV story, plain prose (multi-paragraph allowed)
	Citations  []string         // CVE IDs, research firm refs
	FindingIDs []string         // rule IDs of the underlying findings that triggered this chain
	Paths      []string         // file paths involved
}

// HTML renders an HTML report optimized for screenshots and offline viewing.
// All CSS, fonts, and SVG icons are inlined: no external requests.
func HTML(w io.Writer, r Report) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"sevLabel": func(s finding.Severity) string {
			switch s {
			case finding.SeverityCritical:
				return "Critical"
			case finding.SeverityHigh:
				return "High"
			case finding.SeverityMedium:
				return "Medium"
			case finding.SeverityLow:
				return "Low"
			}
			return "Unknown"
		},
		"sevClass": func(s finding.Severity) string {
			switch s {
			case finding.SeverityCritical:
				return "critical"
			case finding.SeverityHigh:
				return "high"
			case finding.SeverityMedium:
				return "medium"
			case finding.SeverityLow:
				return "low"
			}
			return "unknown"
		},
		"taxClass": func(t finding.Taxonomy) string { return string(t) },
		"counts": func(findings []finding.Finding) map[string]int {
			c := map[string]int{}
			for _, f := range findings {
				c[f.Severity.String()]++
			}
			c["total"] = len(findings)
			return c
		},
		"shortPath": func(p string) string {
			parts := strings.Split(p, "/")
			if len(parts) <= 4 {
				return p
			}
			return ".../" + strings.Join(parts[len(parts)-3:], "/")
		},
		"join": strings.Join,
		"duration": func(start, end time.Time) string {
			return end.Sub(start).Round(time.Millisecond).String()
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("html template: %w", err)
	}
	return tmpl.Execute(w, r)
}
