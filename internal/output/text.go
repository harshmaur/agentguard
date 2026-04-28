package output

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/agentguard/agentguard/internal/finding"
)

// Text prints a human-readable summary of the report. Used for terminal
// output: counts by severity, top findings grouped by severity, and the
// path to the full HTML report (if one was written).
//
// Output is plain ASCII; no color codes (terminals without color support
// shouldn't see escape junk, and CI logs stay grep-friendly). Real terminals
// can color via shell wrappers if they want.
func Text(w io.Writer, r Report, htmlPath string) error {
	bw := &bufErrWriter{w: w}
	bw.printf("AgentGuard %s\n", r.Version)
	bw.printf("scanned %d files (parsed %d, skipped %d) in %s\n",
		r.FilesSeen, r.FilesParsed, r.Skipped,
		r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond))

	if r.SelfAudit != "" && r.SelfAudit != "skipped" {
		bw.printf("self-audit: %s\n", r.SelfAudit)
	}

	counts := map[finding.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}

	bw.printf("\n")
	if len(r.Findings) == 0 {
		bw.printf("✓ No findings. Your AI-agent configs look clean.\n")
		if htmlPath != "" {
			bw.printf("\n  Report: %s\n", htmlPath)
		}
		return bw.err
	}

	bw.printf("Findings: %d total  ─  %d critical / %d high / %d medium / %d low\n",
		len(r.Findings),
		counts[finding.SeverityCritical],
		counts[finding.SeverityHigh],
		counts[finding.SeverityMedium],
		counts[finding.SeverityLow],
	)
	if r.Suppressed > 0 {
		bw.printf("  (%d suppressed by .agentguardignore)\n", r.Suppressed)
	}

	// Group printable findings: show all critical + high + medium, cap at 12 per
	// severity tier so we don't flood the terminal. Lows are summarized only.
	bySev := map[finding.Severity][]finding.Finding{}
	for _, f := range r.Findings {
		bySev[f.Severity] = append(bySev[f.Severity], f)
	}

	for _, sev := range []finding.Severity{
		finding.SeverityCritical,
		finding.SeverityHigh,
		finding.SeverityMedium,
	} {
		findings := bySev[sev]
		if len(findings) == 0 {
			continue
		}
		bw.printf("\n%s (%d):\n", strings.ToUpper(sev.String()), len(findings))
		max := 12
		shown := findings
		if len(findings) > max {
			shown = findings[:max]
		}
		for _, f := range shown {
			loc := f.Path
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
			}
			bw.printf("  - [%s] %s\n", f.RuleID, f.Title)
			bw.printf("    %s\n", loc)
		}
		if len(findings) > max {
			bw.printf("  ... and %d more (see HTML for full list)\n", len(findings)-max)
		}
	}

	if counts[finding.SeverityLow] > 0 {
		bw.printf("\nLOW (%d): see HTML for details\n", counts[finding.SeverityLow])
	}

	if htmlPath != "" {
		bw.printf("\n  Report: %s\n", htmlPath)
	}
	return bw.err
}

// bufErrWriter is a tiny io.Writer wrapper that captures the first write
// error, so we don't have to check err on every printf in Text().
type bufErrWriter struct {
	w   io.Writer
	err error
}

func (b *bufErrWriter) printf(format string, args ...any) {
	if b.err != nil {
		return
	}
	_, b.err = fmt.Fprintf(b.w, format, args...)
}
