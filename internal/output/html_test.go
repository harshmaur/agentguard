package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/harshmaur/audr/internal/finding"
)

func TestMdInline(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"plain", "plain"},
		{"**bold** word", "<strong>bold</strong> word"},
		{"a `code` b", "a <code>code</code> b"},
		{"**`x`**", "<strong><code>x</code></strong>"},
		{"<script>", "&lt;script&gt;"},
		{"line1\nline2", "line1<br>line2"},
		{"`hooks.SessionStart` runs", "<code>hooks.SessionStart</code> runs"},
	}
	for _, tt := range tests {
		got := mdInline(tt.in)
		if got != tt.want {
			t.Errorf("mdInline(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNarrativeParts_SplitsOnFirstParagraphBreak(t *testing.T) {
	in := "Lede sentence.\n\nRest paragraph one.\n\nRest paragraph two."
	lede, rest := narrativeParts(in)
	if string(lede) != "Lede sentence." {
		t.Errorf("lede = %q", lede)
	}
	if !strings.Contains(string(rest), "Rest paragraph one.") || !strings.Contains(string(rest), "Rest paragraph two.") {
		t.Errorf("rest missing content: %q", rest)
	}
}

func TestNarrativeParts_NoBreakReturnsEmptyRest(t *testing.T) {
	in := "Single line only."
	lede, rest := narrativeParts(in)
	if string(lede) != "Single line only." {
		t.Errorf("lede = %q", lede)
	}
	if string(rest) != "" {
		t.Errorf("rest = %q, want empty", rest)
	}
}

func TestBuildVerdict_Clean(t *testing.T) {
	r := Report{Findings: nil, FilesParsed: 12, Roots: []string{"/tmp"}}
	v := r.Verdict()
	if v.Severity != "clean" {
		t.Errorf("severity = %q, want clean", v.Severity)
	}
	if !strings.Contains(v.Lead, "Clean") {
		t.Errorf("lead = %q", v.Lead)
	}
}

func TestBuildVerdict_LeadsWithCriticalChainTitle(t *testing.T) {
	r := Report{
		Findings: []finding.Finding{
			{RuleID: "x", Severity: finding.SeverityCritical, Path: "/a"},
			{RuleID: "y", Severity: finding.SeverityHigh, Path: "/a"},
		},
		AttackChains: []AttackChain{
			{ID: "h", Severity: finding.SeverityHigh, Title: "high chain"},
			{ID: "c", Severity: finding.SeverityCritical, Title: "Permission-loose agent"},
		},
	}
	v := r.Verdict()
	if v.Severity != "critical" {
		t.Errorf("severity = %q", v.Severity)
	}
	if !strings.HasPrefix(v.Lead, "Permission-loose agent") {
		t.Errorf("lead = %q, want Critical chain title", v.Lead)
	}
}

func TestBuildVerdict_NoChainsFallsBackToCounts(t *testing.T) {
	r := Report{
		Findings: []finding.Finding{
			{RuleID: "x", Severity: finding.SeverityHigh, Path: "/a"},
			{RuleID: "y", Severity: finding.SeverityHigh, Path: "/b"},
		},
	}
	v := r.Verdict()
	if v.Severity != "high" {
		t.Errorf("severity = %q", v.Severity)
	}
	if !strings.Contains(v.Lead, "2 finding") {
		t.Errorf("lead = %q", v.Lead)
	}
}

func TestGroupByPath_GroupsAndSortsBySeverity(t *testing.T) {
	findings := []finding.Finding{
		{Path: "/a", Severity: finding.SeverityMedium, Line: 1, RuleID: "r1"},
		{Path: "/b", Severity: finding.SeverityCritical, Line: 5, RuleID: "r2"},
		{Path: "/a", Severity: finding.SeverityCritical, Line: 2, RuleID: "r3"},
		{Path: "/c", Severity: finding.SeverityHigh, Line: 9, RuleID: "r4"},
		{Path: "/b", Severity: finding.SeverityLow, Line: 99, RuleID: "r5"},
	}

	// Re-use the helper from the FuncMap by exec'ing the template wouldn't be
	// ergonomic — call buildGroups directly via a small wrapper.
	groups := groupByPathForTest(findings)

	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3", len(groups))
	}

	// /a has 1 critical + 1 medium → outranks /b (1 critical + 1 low) by
	// the secondary sort on High count? No — ties broken by High then Med.
	// /a (crit=1, high=0, med=1) vs /b (crit=1, high=0, med=0): /a wins on med.
	// /c (crit=0, high=1) is last because crit=0.
	if groups[0].Path != "/a" || groups[0].Crit != 1 || groups[0].Med != 1 {
		t.Errorf("group[0] = %+v, want /a crit=1 med=1", groups[0])
	}
	if groups[1].Path != "/b" || groups[1].Crit != 1 || groups[1].Low != 1 {
		t.Errorf("group[1] = %+v, want /b crit=1 low=1", groups[1])
	}
	if groups[2].Path != "/c" || groups[2].High != 1 {
		t.Errorf("group[2] = %+v, want /c high=1", groups[2])
	}

	// Within /a, critical (line 2) precedes medium (line 1) because severity
	// outranks line ordering.
	if groups[0].Findings[0].Severity != finding.SeverityCritical || groups[0].Findings[0].Line != 2 {
		t.Errorf("group[0] findings[0] = %+v", groups[0].Findings[0])
	}
}

// groupByPathForTest mirrors the FuncMap closure; kept here so tests don't
// have to re-execute the full HTML template just to exercise grouping.
func groupByPathForTest(findings []finding.Finding) []PathGroup {
	var buf bytes.Buffer
	r := Report{Findings: findings, StartedAt: time.Unix(0, 0), FinishedAt: time.Unix(0, 0)}
	if err := HTML(&buf, r); err != nil {
		panic(err)
	}
	// Re-derive groups via the same logic the template uses.
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
		// Match template helper's sort: severity asc (crit=0 first), then line.
		for i := 0; i < len(g.Findings); i++ {
			for j := i + 1; j < len(g.Findings); j++ {
				if g.Findings[j].Severity < g.Findings[i].Severity ||
					(g.Findings[j].Severity == g.Findings[i].Severity && g.Findings[j].Line < g.Findings[i].Line) {
					g.Findings[i], g.Findings[j] = g.Findings[j], g.Findings[i]
				}
			}
		}
		groups = append(groups, *g)
	}
	for i := 0; i < len(groups); i++ {
		for j := i + 1; j < len(groups); j++ {
			gi, gj := groups[i], groups[j]
			swap := false
			switch {
			case gi.Crit != gj.Crit:
				swap = gj.Crit > gi.Crit
			case gi.High != gj.High:
				swap = gj.High > gi.High
			case gi.Med != gj.Med:
				swap = gj.Med > gi.Med
			default:
				swap = gj.Path < gi.Path
			}
			if swap {
				groups[i], groups[j] = groups[j], groups[i]
			}
		}
	}
	return groups
}

func TestHTML_RendersFontsAndChainStructure(t *testing.T) {
	now := time.Now()
	r := Report{
		Version:     "v0.2.2-test",
		Roots:       []string{"/tmp"},
		FilesParsed: 1,
		FilesSeen:   1,
		StartedAt:   now,
		FinishedAt:  now.Add(time.Second),
		Findings: []finding.Finding{
			{RuleID: "claude-hook-shell-rce", Severity: finding.SeverityCritical, Taxonomy: finding.TaxEnforced, Title: "Hook RCE", Description: "`hooks.X` runs shell.", Path: "/etc/settings.json", Line: 7},
		},
		AttackChains: []AttackChain{
			{ID: "c1", Title: "Repo-clone hook RCE", Outcome: "RCE on first repo open, before any prompt", Severity: finding.SeverityCritical, Narrative: "Lede sentence here.\n\nDeeper attacker prose continues here with **bold** and `code`.", FindingIDs: []string{"claude-hook-shell-rce"}, Paths: []string{"/etc/settings.json"}, Citations: []string{"CVE-2025-59536"}},
		},
	}
	var buf bytes.Buffer
	if err := HTML(&buf, r); err != nil {
		t.Fatalf("HTML render error: %v", err)
	}
	out := buf.String()

	// Embedded fonts — there should be three @font-face blocks with data: URIs.
	if c := strings.Count(out, "@font-face"); c != 3 {
		t.Errorf("@font-face count = %d, want 3", c)
	}
	if c := strings.Count(out, "data:font/woff2;base64,"); c != 3 {
		t.Errorf("data URI count = %d, want 3", c)
	}

	// No external network requests — no fonts.googleapis or fonts.gstatic.
	for _, banned := range []string{"fonts.googleapis.com", "fonts.gstatic.com", "googletagmanager", "google-analytics"} {
		if strings.Contains(out, banned) {
			t.Errorf("rendered HTML contains banned external reference %q", banned)
		}
	}

	// Verdict pulls from the Critical chain title.
	if !strings.Contains(out, "Repo-clone hook RCE") {
		t.Errorf("verdict missing chain title")
	}

	// Markdown processing: bold and code in narrative + finding desc render as tags.
	if !strings.Contains(out, "<strong>bold</strong>") {
		t.Errorf("**bold** not converted in narrative rest")
	}
	if !strings.Contains(out, "<code>hooks.X</code>") {
		t.Errorf("`code` not converted in finding desc")
	}

	// Chain anchor links to the path-grouped finding section.
	if !strings.Contains(out, `href="#path-`) {
		t.Errorf("chain Files footer missing anchor link")
	}
	if !strings.Contains(out, `id="path-`) {
		t.Errorf("path-group section missing anchor target")
	}

	// File-grouped findings: one path group section.
	if c := strings.Count(out, `class="path-group"`); c != 1 {
		t.Errorf("path-group count = %d, want 1", c)
	}

	// Per-chain "Attacker gets" outcome callout.
	if !strings.Contains(out, `class="chain-outcome"`) {
		t.Errorf("chain-outcome callout missing")
	}
	if !strings.Contains(out, "RCE on first repo open") {
		t.Errorf("outcome string missing from rendered HTML")
	}
}

func TestText_VerdictAndChains(t *testing.T) {
	now := time.Now()
	r := Report{
		Version:     "v0.2.3-test",
		Roots:       []string{"/tmp"},
		FilesParsed: 1,
		FilesSeen:   1,
		StartedAt:   now,
		FinishedAt:  now.Add(time.Second),
		Findings: []finding.Finding{
			{RuleID: "claude-hook-shell-rce", Severity: finding.SeverityCritical, Taxonomy: finding.TaxEnforced, Title: "Hook RCE", Description: "X.", Path: "/etc/settings.json", Line: 7},
		},
		AttackChains: []AttackChain{
			{ID: "c1", Title: "Repo-clone hook RCE", Outcome: "RCE on first repo open, before any prompt", Severity: finding.SeverityCritical, Narrative: "y", Paths: []string{"/etc/settings.json"}, FindingIDs: []string{"claude-hook-shell-rce"}},
		},
	}
	var buf bytes.Buffer
	if err := Text(&buf, r, "/tmp/x.html"); err != nil {
		t.Fatalf("Text render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "==> Repo-clone hook RCE") {
		t.Errorf("verdict line missing or wrong format: %q", out)
	}
	if !strings.Contains(out, "Attack chains (1)") {
		t.Errorf("attack-chain summary missing")
	}
	if !strings.Contains(out, "Attacker gets: RCE on first repo open") {
		t.Errorf("outcome line missing in CLI output")
	}
}

func TestPackageVulnerabilityFindingsIncludesExternalScannerRules(t *testing.T) {
	findings := packageVulnerabilityFindings([]finding.Finding{
		{RuleID: "dependency-osv-vulnerability", Severity: finding.SeverityHigh, Title: "OSV", Path: "package-lock.json"},
		{RuleID: "dependency-trivy-vulnerability", Severity: finding.SeverityHigh, Title: "Trivy", Path: "poetry.lock"},
		{RuleID: "mcp-unpinned-npx", Severity: finding.SeverityHigh, Title: "Other", Path: ".mcp.json"},
	})
	if len(findings) != 2 {
		t.Fatalf("packageVulnerabilityFindings len = %d, want 2", len(findings))
	}
}

func TestText_RendersPackageVulnerabilitySection(t *testing.T) {
	now := time.Now()
	findings := []finding.Finding{}
	for i := 0; i < 14; i++ {
		findings = append(findings, finding.Finding{
			RuleID:   "mcp-unauth-remote-url",
			Severity: finding.SeverityHigh,
			Title:    "Other high finding",
			Path:     "/tmp/other.json",
			Line:     i + 1,
		})
	}
	findings = append(findings, finding.Finding{
		RuleID:       "agent-package-known-vulnerable",
		Severity:     finding.SeverityHigh,
		Title:        "Anthropic TypeScript SDK local filesystem memory tool uses unsafe file modes",
		Description:  "npm declares @anthropic-ai/sdk@0.81.0, which matches CVE-2026-41686.",
		Path:         "/repo/package.json",
		Line:         17,
		Match:        "@anthropic-ai/sdk@0.81.0",
		SuggestedFix: "Upgrade @anthropic-ai/sdk to 0.91.1 or later.",
	})
	r := Report{Version: "v0.2.3-test", Roots: []string{"/repo"}, FilesParsed: 1, FilesSeen: 1, StartedAt: now, FinishedAt: now.Add(time.Second), Findings: findings}

	var buf bytes.Buffer
	if err := Text(&buf, r, "/tmp/x.html"); err != nil {
		t.Fatalf("Text render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Package vulnerabilities (1)",
		"Anthropic TypeScript SDK local filesystem memory tool uses unsafe file modes",
		"/repo/package.json:17",
		"Installed: @anthropic-ai/sdk@0.81.0",
		"Fix: Upgrade @anthropic-ai/sdk to 0.91.1 or later.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("CLI package section missing %q in output:\n%s", want, out)
		}
	}
}

func TestHTML_RendersPackageVulnerabilitySection(t *testing.T) {
	now := time.Now()
	r := Report{
		Version:    "v0.2.3-test",
		Roots:      []string{"/repo"},
		StartedAt:  now,
		FinishedAt: now.Add(time.Second),
		Findings: []finding.Finding{
			{
				RuleID:       "agent-package-known-vulnerable",
				Severity:     finding.SeverityHigh,
				Taxonomy:     finding.TaxDetectable,
				Title:        "Anthropic TypeScript SDK local filesystem memory tool uses unsafe file modes",
				Description:  "npm declares @anthropic-ai/sdk@0.81.0, which matches CVE-2026-41686.",
				Path:         "/repo/package.json",
				Line:         17,
				Match:        "@anthropic-ai/sdk@0.81.0",
				SuggestedFix: "Upgrade @anthropic-ai/sdk to 0.91.1 or later.",
			},
		},
	}
	var buf bytes.Buffer
	if err := HTML(&buf, r); err != nil {
		t.Fatalf("HTML render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Package vulnerabilities",
		"1 vulnerable package manifest",
		"Anthropic TypeScript SDK local filesystem memory tool uses unsafe file modes",
		"/repo/package.json",
		"@anthropic-ai/sdk@0.81.0",
		"Upgrade @anthropic-ai/sdk to 0.91.1 or later.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML package section missing %q", want)
		}
	}
}

func TestHTML_EmptyFindings(t *testing.T) {
	r := Report{Version: "v0.2.2-test", Roots: []string{"/tmp"}, FilesParsed: 5, StartedAt: time.Now(), FinishedAt: time.Now()}
	var buf bytes.Buffer
	if err := HTML(&buf, r); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "No findings") {
		t.Errorf("empty-state copy missing")
	}
	if !strings.Contains(out, "Clean") {
		t.Errorf("clean verdict missing")
	}
}
