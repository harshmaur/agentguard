// Package output renders Findings into HTML / SARIF / JSON.
//
// Output formatters are pure: they consume already-redacted Findings and
// produce serialized bytes. Redaction happened at finding-construction time;
// formatters never see raw secrets.
//
// All resources used by the HTML report — CSS, woff2 font files, SVG marks —
// are embedded into the binary via go:embed and inlined as data URIs at render
// time. The rendered HTML makes zero external network requests, preserving the
// "single static binary, no cloud" guarantee from the v0.1 design doc.
package output

import (
	"encoding/base64"
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/harshmaur/agentguard/internal/finding"
)

//go:embed report.html.tmpl
var htmlTemplate string

//go:embed fonts/instrument_serif.woff2
var fontInstrumentSerif []byte

//go:embed fonts/geist.woff2
var fontGeist []byte

//go:embed fonts/geist_mono.woff2
var fontGeistMono []byte

// Pre-computed base64 data URIs for the three embedded fonts. Done once at
// package init time — render-hot path stays string-substitution only.
var (
	uriInstrumentSerif template.URL
	uriGeist           template.URL
	uriGeistMono       template.URL
)

func init() {
	uriInstrumentSerif = template.URL("data:font/woff2;base64," + base64.StdEncoding.EncodeToString(fontInstrumentSerif))
	uriGeist = template.URL("data:font/woff2;base64," + base64.StdEncoding.EncodeToString(fontGeist))
	uriGeistMono = template.URL("data:font/woff2;base64," + base64.StdEncoding.EncodeToString(fontGeistMono))
}

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
	Outcome    string           // one-line "what an attacker gets" — rendered as a forensic call-out above the narrative
	Severity   finding.Severity // chain severity
	Narrative  string           // attacker-POV story, plain prose (multi-paragraph allowed)
	Citations  []string         // CVE IDs, research firm refs
	FindingIDs []string         // rule IDs of the underlying findings that triggered this chain
	Paths      []string         // file paths involved
}

// PathGroup is a per-file bucket of findings rendered as one section in the
// HTML report. The ordering is severity-weighted so the most-affected files
// surface at the top of the Findings section.
type PathGroup struct {
	Path     string
	Findings []finding.Finding
	Crit     int
	High     int
	Med      int
	Low      int
}

// Verdict is the lead sentence rendered above the metric pills. The lead
// captures the worst thing on this machine in plain prose; the supporting
// clause says how many chains and findings back it up.
type Verdict struct {
	Lead       string // headline sentence (serif display)
	Supporting string // smaller follow-on clause
	Severity   string // sev class for the lead colour bar
}

var (
	slugStripRE  = regexp.MustCompile(`[^a-zA-Z0-9]+`)
	mdBoldRE     = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	mdInlineCode = regexp.MustCompile("`([^`]+)`")
)

// narrativeParts splits a chain narrative into a lede (first paragraph,
// always visible) and the rest (collapsible). Both halves get inline
// markdown processing for **bold** and `code` so the prose reads cleanly.
func narrativeParts(s string) (template.HTML, template.HTML) {
	parts := strings.SplitN(strings.TrimSpace(s), "\n\n", 2)
	lede := mdInline(parts[0])
	var rest string
	if len(parts) == 2 {
		rest = mdInline(parts[1])
	}
	return template.HTML(lede), template.HTML(rest)
}

func mdInline(s string) string {
	s = template.HTMLEscapeString(s)
	s = mdBoldRE.ReplaceAllString(s, "<strong>$1</strong>")
	s = mdInlineCode.ReplaceAllString(s, "<code>$1</code>")
	s = strings.ReplaceAll(s, "\n", "<br>")
	return s
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
		"basename": filepath.Base,
		"slug": func(s string) string {
			return strings.Trim(strings.ToLower(slugStripRE.ReplaceAllString(s, "-")), "-")
		},
		"join":            strings.Join,
		"duration":        func(start, end time.Time) string { return end.Sub(start).Round(time.Millisecond).String() },
		"verdict":         func(r Report) Verdict { return r.Verdict() },
		"narrativeLede":   func(s string) template.HTML { l, _ := narrativeParts(s); return l },
		"narrativeRest":   func(s string) template.HTML { _, r := narrativeParts(s); return r },
		"md":              func(s string) template.HTML { return template.HTML(mdInline(s)) },
		"fontURI": func(name string) template.URL {
			switch name {
			case "instrument_serif":
				return uriInstrumentSerif
			case "geist":
				return uriGeist
			case "geist_mono":
				return uriGeistMono
			}
			return ""
		},
		"groupByPath": func(findings []finding.Finding) []PathGroup {
			byPath := map[string]*PathGroup{}
			for _, f := range findings {
				g, ok := byPath[f.Path]
				if !ok {
					g = &PathGroup{Path: f.Path}
					byPath[f.Path] = g
				}
				g.Findings = append(g.Findings, f)
				switch f.Severity {
				case finding.SeverityCritical:
					g.Crit++
				case finding.SeverityHigh:
					g.High++
				case finding.SeverityMedium:
					g.Med++
				case finding.SeverityLow:
					g.Low++
				}
			}
			groups := make([]PathGroup, 0, len(byPath))
			for _, g := range byPath {
				sort.SliceStable(g.Findings, func(i, j int) bool {
					if g.Findings[i].Severity != g.Findings[j].Severity {
						return g.Findings[i].Severity < g.Findings[j].Severity
					}
					if g.Findings[i].Line != g.Findings[j].Line {
						return g.Findings[i].Line < g.Findings[j].Line
					}
					return g.Findings[i].RuleID < g.Findings[j].RuleID
				})
				groups = append(groups, *g)
			}
			sort.SliceStable(groups, func(i, j int) bool {
				gi, gj := groups[i], groups[j]
				if gi.Crit != gj.Crit {
					return gi.Crit > gj.Crit
				}
				if gi.High != gj.High {
					return gi.High > gj.High
				}
				if gi.Med != gj.Med {
					return gi.Med > gj.Med
				}
				return gi.Path < gj.Path
			})
			return groups
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("html template: %w", err)
	}
	return tmpl.Execute(w, r)
}

// Verdict returns the headline sentence for this Report. Used by both the
// HTML renderer (verdict block above the metric strip) and the CLI text
// renderer (the one-line summary printed under the scan-stats header).
func (r Report) Verdict() Verdict {
	c := map[finding.Severity]int{}
	for _, f := range r.Findings {
		c[f.Severity]++
	}
	chainBySev := map[finding.Severity]int{}
	for _, ch := range r.AttackChains {
		chainBySev[ch.Severity]++
	}
	totalFindings := len(r.Findings)
	totalChains := len(r.AttackChains)

	if totalFindings == 0 {
		return Verdict{
			Lead:       "Clean. No agent-config violations found on this scan.",
			Supporting: fmt.Sprintf("Scanned %d files across %d roots.", r.FilesParsed, len(r.Roots)),
			Severity:   "clean",
		}
	}

	var leadSev string
	switch {
	case c[finding.SeverityCritical] > 0:
		leadSev = "critical"
	case c[finding.SeverityHigh] > 0:
		leadSev = "high"
	case c[finding.SeverityMedium] > 0:
		leadSev = "medium"
	default:
		leadSev = "low"
	}

	// If a Critical chain fires, lead with the chain's outcome — that's the
	// most CISO-actionable sentence in the document. Otherwise lead with the
	// raw severity counts.
	if totalChains > 0 {
		var critChain *AttackChain
		for i, ch := range r.AttackChains {
			if ch.Severity == finding.SeverityCritical {
				critChain = &r.AttackChains[i]
				break
			}
		}
		if critChain != nil {
			lead := critChain.Title + "."
			supporting := fmt.Sprintf("%d attack chain%s, %d finding%s across %d file%s.",
				totalChains, pluralS(totalChains),
				totalFindings, pluralS(totalFindings),
				distinctPaths(r.Findings), pluralS(distinctPaths(r.Findings)))
			return Verdict{Lead: lead, Supporting: supporting, Severity: "critical"}
		}
	}

	switch {
	case totalChains > 0:
		return Verdict{
			Lead: fmt.Sprintf("%d attack chain%s fire on this machine.",
				totalChains, pluralS(totalChains)),
			Supporting: fmt.Sprintf("%d finding%s across %d file%s.",
				totalFindings, pluralS(totalFindings),
				distinctPaths(r.Findings), pluralS(distinctPaths(r.Findings))),
			Severity: leadSev,
		}
	default:
		return Verdict{
			Lead: fmt.Sprintf("%d finding%s across %d file%s.",
				totalFindings, pluralS(totalFindings),
				distinctPaths(r.Findings), pluralS(distinctPaths(r.Findings))),
			Supporting: fmt.Sprintf("No multi-finding attack chains correlated."),
			Severity:   leadSev,
		}
	}
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func distinctPaths(findings []finding.Finding) int {
	seen := map[string]struct{}{}
	for _, f := range findings {
		seen[f.Path] = struct{}{}
	}
	return len(seen)
}
