package output

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/harshmaur/audr/internal/finding"
)

// Text prints a human-readable summary of the report. Used for terminal
// output: a one-line verdict, severity counts, attack-chain summaries,
// top findings grouped by severity, and the path to the full HTML report.
//
// Output is plain ASCII; no color codes (terminals without color support
// shouldn't see escape junk, and CI logs stay grep-friendly). Real terminals
// can color via shell wrappers if they want.
func Text(w io.Writer, r Report, htmlPath string) error {
	bw := &bufErrWriter{w: w}
	bw.printf("Audr %s\n", r.Version)
	bw.printf("scanned %d files (parsed %d, skipped %d) in %s\n",
		r.FilesSeen, r.FilesParsed, r.Skipped,
		r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond))

	// Verdict line — same one-sentence headline shown at the top of the HTML
	// report. Reads as forensic summary; CISO can paste straight into Slack.
	v := r.Verdict()
	bw.printf("\n==> %s\n", v.Lead)
	if v.Supporting != "" {
		bw.printf("    %s\n", v.Supporting)
	}

	if r.SelfAudit != "" && r.SelfAudit != "skipped" {
		bw.printf("self-audit: %s\n", r.SelfAudit)
	}
	if len(r.Warnings) > 0 {
		bw.printf("\nWarnings:\n")
		for _, warning := range r.Warnings {
			bw.printf("  - %s\n", warning)
		}
	}

	counts := map[finding.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}

	if len(r.Findings) == 0 {
		if len(r.Warnings) > 0 {
			bw.printf("\n! No findings in completed checks, but scanner coverage was incomplete. Do not treat this as a clean package-vulnerability report yet.\n")
		} else {
			bw.printf("\n✓ No findings. Your developer-machine posture looks clean.\n")
		}
		if htmlPath != "" {
			bw.printf("\n  Report: %s\n", htmlPath)
		}
		return bw.err
	}

	// Attack-chain summary block: one line per chain with severity tag and
	// the chain's "Attacker gets" outcome (or title fallback). This is what
	// makes the CLI output read as forensic instead of as a row count.
	if len(r.AttackChains) > 0 {
		bw.printf("\nAttack chains (%d):\n", len(r.AttackChains))
		for _, ch := range r.AttackChains {
			outcome := ch.Outcome
			if outcome == "" {
				outcome = ch.Title
			}
			bw.printf("  - [%s] %s\n", strings.ToUpper(ch.Severity.String()), ch.Title)
			bw.printf("    Attacker gets: %s\n", outcome)
		}
	}

	bw.printf("\nFindings: %d total  ─  %d critical / %d high / %d medium / %d low\n",
		len(r.Findings),
		counts[finding.SeverityCritical],
		counts[finding.SeverityHigh],
		counts[finding.SeverityMedium],
		counts[finding.SeverityLow],
	)
	if r.Suppressed > 0 {
		bw.printf("  (%d suppressed by .audrignore)\n", r.Suppressed)
	}

	secretFindings := secretExposureFindings(r.Findings)
	if len(secretFindings) > 0 {
		bw.printf("\nSecrets (%d):\n", len(secretFindings))
		max := 8
		shown := secretFindings
		if len(secretFindings) > max {
			shown = secretFindings[:max]
		}
		for _, f := range shown {
			loc := f.Path
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
			}
			bw.printf("  - [%s] %s\n", strings.ToUpper(f.Severity.String()), f.Title)
			bw.printf("    %s\n", loc)
			if f.Match != "" {
				bw.printf("    Evidence: %s\n", f.Match)
			}
			if f.SuggestedFix != "" {
				bw.printf("    Fix: %s\n", f.SuggestedFix)
			}
		}
		if len(secretFindings) > max {
			bw.printf("  ... and %d more secret findings (see HTML for full list)\n", len(secretFindings)-max)
		}
	}

	packageFindings := packageVulnerabilityFindings(r.Findings)
	if len(packageFindings) > 0 {
		bw.printf("\nPackage vulnerabilities (%d):\n", len(packageFindings))
		max := 8
		shown := packageFindings
		if len(packageFindings) > max {
			shown = packageFindings[:max]
		}
		for _, f := range shown {
			loc := f.Path
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
			}
			bw.printf("  - [%s] %s\n", strings.ToUpper(f.Severity.String()), f.Title)
			bw.printf("    %s\n", loc)
			if f.Match != "" {
				bw.printf("    Installed: %s\n", f.Match)
			}
			if f.SuggestedFix != "" {
				bw.printf("    Fix: %s\n", f.SuggestedFix)
			}
		}
		if len(packageFindings) > max {
			bw.printf("  ... and %d more package vulnerabilities (see HTML for full list)\n", len(packageFindings)-max)
		}
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
