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
	_ "embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/runtimeenv"
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
	Warnings     []string      // scanner coverage warnings that must be visible in every report
	Roots        []string
	StartedAt    time.Time
	FinishedAt   time.Time
	FilesSeen    int
	FilesParsed  int
	Suppressed   int
	Skipped      int
	Version      string
	SelfAudit    string // "clean (cosign-verified)" / "clean (unverified)" / "TAMPERED" / "skipped"

	// Environment captures whether audr ran on bare metal, in a
	// container, in a VM, or under WSL — answers "is this report
	// about the developer machine or about a throwaway container
	// fs?" Optional; nil when detection wasn't run (one-shot CLI
	// without runtimeenv wired in). Originally contributed by
	// Alex Umrysh in PR #10, incorporated alongside the daemon
	// surface from v0.5.6.
	Environment *runtimeenv.Info `json:"environment,omitempty"`

	// BaselineDiff is non-nil when `audr scan --baseline=<path>` was
	// used. Carries the resolved / still-present / newly-introduced
	// id lists computed against the unsuppressed scanner result so
	// agents cannot fake "resolved" by adding the rule to .audrignore.
	BaselineDiff *BaselineDiff `json:"baseline_diff,omitempty"`

	// ScanMounts classifies each scan root as host-bound (bind-
	// mounted from outside the container) or container-local. The
	// report renders host-bound paths so an auditor reading the
	// report inside a container knows which findings reflect the
	// host vs the ephemeral container fs. Linux-only; on macOS/
	// Windows this stays empty (we don't parse mountinfo there).
	ScanMounts []runtimeenv.Mount `json:"scan_mounts,omitempty"`
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

// SeverityGroup is the primary grouping in the HTML report's findings
// view: one bucket per severity (Critical, High, Medium, Low),
// findings within sorted by the standard finding.Less ordering. This
// mirrors the dashboard's severity-section layout — opening a report
// should feel like looking at the dashboard at the moment of scan.
//
// Inside each bucket, findings carry a Kind tag ("package", "secret",
// "agent-rule", "other") so the report's filter chips can hide them
// by category without re-grouping the document.
type SeverityGroup struct {
	Severity finding.Severity
	Label    string // "Critical" / "High" / "Medium" / "Low"
	Class    string // "critical" / "high" / "medium" / "low"
	Findings []finding.Finding
	Total    int // alias for len(Findings) — eases template arithmetic
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
		"packageVulns":   packageVulnerabilityFindings,
		"secretFindings": secretExposureFindings,
		"otherFindings":  otherCategoryFindings,
		"findingKind":    findingKind,
		"searchText": func(parts ...string) string {
			return strings.ToLower(strings.Join(parts, " "))
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
		"join":          strings.Join,
		"duration":      func(start, end time.Time) string { return end.Sub(start).Round(time.Millisecond).String() },
		// Runtime-info helpers (PR #10) — render the Mounts row only
		// when at least one scan root is host-bound, and summarize
		// the host-bound mounts as a "path (fstype) · path (fstype)"
		// string for inline display.
		"hasHostBoundMount": func(mounts []runtimeenv.Mount) bool {
			for _, m := range mounts {
				if m.HostBound {
					return true
				}
			}
			return false
		},
		"hostBoundMountSummary": func(mounts []runtimeenv.Mount) string {
			var parts []string
			for _, m := range mounts {
				if !m.HostBound {
					continue
				}
				if m.FSType != "" {
					parts = append(parts, fmt.Sprintf("%s (%s)", m.Path, m.FSType))
				} else {
					parts = append(parts, m.Path)
				}
			}
			return strings.Join(parts, " · ")
		},
		"verdict":       func(r Report) Verdict { return r.Verdict() },
		"narrativeLede": func(s string) template.HTML { l, _ := narrativeParts(s); return l },
		"narrativeRest": func(s string) template.HTML { _, r := narrativeParts(s); return r },
		"md":            func(s string) template.HTML { return template.HTML(mdInline(s)) },
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
		"groupBySeverity": func(findings []finding.Finding) []SeverityGroup {
			// Order: Critical → High → Medium → Low. Severities have
			// matching numeric values where lower == worse (Critical=0,
			// Low=3), but we want render-order with Critical first, so
			// we iterate explicitly.
			order := []finding.Severity{
				finding.SeverityCritical,
				finding.SeverityHigh,
				finding.SeverityMedium,
				finding.SeverityLow,
			}
			byBucket := map[finding.Severity][]finding.Finding{}
			for _, f := range findings {
				byBucket[f.Severity] = append(byBucket[f.Severity], f)
			}
			groups := make([]SeverityGroup, 0, len(order))
			for _, sev := range order {
				bucket := byBucket[sev]
				if len(bucket) == 0 {
					continue
				}
				sort.SliceStable(bucket, func(i, j int) bool {
					return finding.Less(bucket[i], bucket[j])
				})
				groups = append(groups, SeverityGroup{
					Severity: sev,
					Label:    sevLabelFor(sev),
					Class:    sevClassFor(sev),
					Findings: bucket,
					Total:    len(bucket),
				})
			}
			return groups
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
					return finding.Less(g.Findings[i], g.Findings[j])
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

func sevLabelFor(s finding.Severity) string {
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
}

func sevClassFor(s finding.Severity) string {
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
}

const osvVulnerabilityRuleID = "dependency-osv-vulnerability"

const (
	betterleaksValidRuleID      = "secret-betterleaks-valid"
	betterleaksUnverifiedRuleID = "secret-betterleaks-unverified"
)

func packageVulnerabilityFindings(findings []finding.Finding) []finding.Finding {
	packageFindings := make([]finding.Finding, 0)
	for _, f := range findings {
		if f.RuleID == osvVulnerabilityRuleID {
			packageFindings = append(packageFindings, f)
		}
	}
	sort.SliceStable(packageFindings, func(i, j int) bool {
		return finding.Less(packageFindings[i], packageFindings[j])
	})
	return packageFindings
}

// findingKind tags a finding with the same kind as its dedicated section
// (if any) so the HTML filter chips can hide it everywhere — including
// the "Findings by file" grouping where mixed kinds are interleaved.
func findingKind(f finding.Finding) string {
	switch f.RuleID {
	case osvVulnerabilityRuleID:
		return "package"
	case betterleaksValidRuleID, betterleaksUnverifiedRuleID:
		return "secret"
	}
	return "other"
}

func otherCategoryFindings(findings []finding.Finding) []finding.Finding {
	other := make([]finding.Finding, 0)
	for _, f := range findings {
		if findingKind(f) == "other" {
			other = append(other, f)
		}
	}
	return other
}

func secretExposureFindings(findings []finding.Finding) []finding.Finding {
	secretFindings := make([]finding.Finding, 0)
	for _, f := range findings {
		if f.RuleID == betterleaksValidRuleID || f.RuleID == betterleaksUnverifiedRuleID {
			secretFindings = append(secretFindings, f)
		}
	}
	sort.SliceStable(secretFindings, func(i, j int) bool {
		return finding.Less(secretFindings[i], secretFindings[j])
	})
	return secretFindings
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
		if len(r.Warnings) > 0 {
			return Verdict{
				Lead:       "Scan incomplete. No findings in the checks that completed.",
				Supporting: fmt.Sprintf("%d coverage warning%s require attention before treating this report as clean.", len(r.Warnings), pluralS(len(r.Warnings))),
				Severity:   "medium",
			}
		}
		return Verdict{
			Lead:       "Clean. No developer-machine security findings on this scan.",
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
