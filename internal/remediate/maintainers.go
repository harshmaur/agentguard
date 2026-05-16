package remediate

import (
	"fmt"
	"net/url"
	"strings"
)

// MaintainerLink describes how a user can notify a plugin maintainer
// about a finding they own.
type MaintainerLink struct {
	// IssueURL is a pre-filled "new issue" URL on the maintainer's GitHub
	// repo. Opens in a new tab. Empty when no known issue tracker is
	// configured for this maintainer.
	IssueURL string
	// BodyMarkdown is the pre-filled issue body the user can copy to
	// the clipboard when the IssueURL is empty (unknown maintainer
	// fallback). Always populated so the UI never shows an empty state.
	BodyMarkdown string
	// LabelHint is a short noun the UI uses to address the maintainer
	// in copy ("File issue with <label>"). For known vendors it's the
	// vendor name; for unknown it's "plugin author".
	LabelHint string
}

// IssueDetails carries the inputs needed to render a maintainer
// notification. Filled by the dashboard server from the rolled-up
// finding row.
type IssueDetails struct {
	Maintainer    string // the SecondaryNotify field on the finding, lower-case
	RuleID        string // e.g. "dependency-osv-vulnerability"
	AdvisoryID    string // CVE-xxxx or GHSA-xxxx; empty for non-OSV findings
	Package       string // package name when applicable; empty otherwise
	FixedVersion  string // upstream-patched version when known; empty otherwise
	AffectedPaths []string
	Severity      string // "critical" / "high" / "medium" / "low"
	Title         string
}

// maintainerRegistry maps a normalised maintainer key (lower-cased,
// trimmed) to the canonical GitHub repo new-issue endpoint. v1.3 ships
// hardcoded entries for the maintainers we encounter most in dogfood;
// TODO 10 captures user-extensible entries via policy.yaml.
//
// New maintainer entries land here when audr starts seeing their files
// in real scans. Keep entries lower-cased.
var maintainerRegistry = map[string]struct {
	Label     string // human label for the UI button
	NewIssue  string // GitHub new-issue endpoint
}{
	"vercel": {
		Label:    "Vercel",
		NewIssue: "https://github.com/vercel/claude-plugins-official/issues/new",
	},
	"anthropic-marketplace": {
		Label:    "Anthropic marketplace",
		NewIssue: "https://github.com/anthropics/claude-plugins/issues/new",
	},
	"cursor": {
		Label:    "Cursor",
		NewIssue: "https://github.com/getcursor/cursor/issues/new",
	},
}

// MaintainerLinkFor renders the maintainer-notification view for a
// finding. Unknown maintainers get an empty IssueURL but a still-useful
// BodyMarkdown that the UI surfaces as a clipboard-copy fallback.
//
// The body is always Markdown — most issue trackers render it; even
// when pasted into Slack or email the structure stays readable.
//
// The URL length is capped at 8KB (GitHub's limit before pre-fill
// silently truncates). For long affected-paths lists, the body keeps
// the first 30 paths inline and the rest are summarised as
// "(... N more paths)". F4 mitigation.
func MaintainerLinkFor(d IssueDetails) MaintainerLink {
	body := renderIssueBody(d)
	label := "plugin author"
	if d.Maintainer != "" {
		if reg, ok := maintainerRegistry[strings.ToLower(strings.TrimSpace(d.Maintainer))]; ok {
			label = reg.Label
			issueURL := buildGitHubNewIssueURL(reg.NewIssue, d, body)
			return MaintainerLink{
				IssueURL:     issueURL,
				BodyMarkdown: body,
				LabelHint:    label,
			}
		}
		// Known SecondaryNotify hint but unknown registry entry — the
		// label can still mention the vendor name, even though we have
		// no canonical issue URL.
		label = d.Maintainer
	}
	return MaintainerLink{
		IssueURL:     "",
		BodyMarkdown: body,
		LabelHint:    label,
	}
}

// buildGitHubNewIssueURL composes the `?title=&body=&labels=` query
// string GitHub honours for /issues/new pre-filling. Caps total length
// at 8KB; if exceeded, the body is truncated with a "see full report
// in audr dashboard" footer note rather than silently dropping data.
func buildGitHubNewIssueURL(base string, d IssueDetails, body string) string {
	const maxURLLen = 8 << 10 // 8 KiB
	title := buildIssueTitle(d)
	q := url.Values{}
	q.Set("title", title)
	q.Set("body", body)
	full := base + "?" + q.Encode()
	if len(full) <= maxURLLen {
		return full
	}
	// Truncate body, preserve the URL. Leave headroom for the title
	// and the truncation marker itself.
	overflow := len(full) - maxURLLen
	bodyTrunc := body
	if len(bodyTrunc) > overflow+200 {
		marker := "\n\n_… body truncated to fit GitHub's URL pre-fill limit; see the full report in your audr dashboard._\n"
		cut := len(bodyTrunc) - overflow - len(marker)
		if cut < 0 {
			cut = 0
		}
		bodyTrunc = bodyTrunc[:cut] + marker
	}
	q.Set("body", bodyTrunc)
	return base + "?" + q.Encode()
}

func buildIssueTitle(d IssueDetails) string {
	switch {
	case d.AdvisoryID != "" && d.Package != "":
		return fmt.Sprintf("Vulnerable dependency in shipped plugin: %s (%s)", d.Package, d.AdvisoryID)
	case d.AdvisoryID != "":
		return fmt.Sprintf("Security finding in shipped plugin: %s", d.AdvisoryID)
	case d.Package != "":
		return fmt.Sprintf("Vulnerable dependency in shipped plugin: %s", d.Package)
	default:
		return "Security finding in shipped plugin (reported by audr)"
	}
}

func renderIssueBody(d IssueDetails) string {
	var sb strings.Builder
	sb.WriteString("Hello — `audr` (a developer-machine security scanner) flagged a vulnerability in the plugin you ship.\n\n")
	if d.Title != "" {
		sb.WriteString("**Finding:** " + d.Title + "\n")
	}
	if d.Severity != "" {
		sb.WriteString("**Severity:** " + d.Severity + "\n")
	}
	if d.RuleID != "" {
		sb.WriteString("**Rule:** `" + d.RuleID + "`\n")
	}
	if d.AdvisoryID != "" {
		sb.WriteString("**Advisory:** " + d.AdvisoryID + "\n")
	}
	if d.Package != "" {
		sb.WriteString("**Package:** `" + d.Package + "`\n")
	}
	if d.FixedVersion != "" {
		sb.WriteString("**Patched version:** `" + d.FixedVersion + "` or later\n")
	}
	sb.WriteString("\n")

	if len(d.AffectedPaths) > 0 {
		sb.WriteString("**Affected paths in shipped plugin:**\n")
		const maxPathsInline = 30
		for i, p := range d.AffectedPaths {
			if i >= maxPathsInline {
				remaining := len(d.AffectedPaths) - maxPathsInline
				sb.WriteString(fmt.Sprintf("- _(… %d more paths)_\n", remaining))
				break
			}
			sb.WriteString("- `" + p + "`\n")
		}
		sb.WriteString("\n")
	}

	sb.WriteString("**Requested action:**\n")
	if d.FixedVersion != "" && d.Package != "" {
		sb.WriteString(fmt.Sprintf("Bump `%s` to `%s` or later in the plugin's lockfile and publish a new release.\n",
			d.Package, d.FixedVersion))
	} else {
		sb.WriteString("Please investigate and publish a patched release.\n")
	}
	sb.WriteString("\n_This issue was opened from the audr dashboard. audr runs entirely offline; no scan data was sent to a third party._\n")
	return sb.String()
}
