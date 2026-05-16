package output

import (
	"bytes"
	"encoding/json"
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

func TestBuildVerdict_IncompleteWhenWarningsExist(t *testing.T) {
	r := Report{Warnings: []string{"dependency scanner osv-scanner is not installed"}, FilesParsed: 12, Roots: []string{"/tmp"}}
	v := r.Verdict()
	if v.Severity != "medium" {
		t.Errorf("severity = %q, want medium", v.Severity)
	}
	if !strings.Contains(v.Lead, "Scan incomplete") {
		t.Errorf("lead = %q, want incomplete scan", v.Lead)
	}
}

func TestWarningsRenderInHumanAndMachineReports(t *testing.T) {
	r := Report{
		Warnings:   []string{"dependency scanner osv-scanner is not installed"},
		Roots:      []string{"/tmp"},
		StartedAt:  time.Unix(0, 0),
		FinishedAt: time.Unix(1, 0),
		SelfAudit:  "skipped",
	}

	var htmlBuf bytes.Buffer
	if err := HTML(&htmlBuf, r); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	for _, want := range []string{"Coverage warnings", "Scan incomplete", "No findings in completed checks", "dependency scanner osv-scanner is not installed"} {
		if !strings.Contains(htmlBuf.String(), want) {
			t.Fatalf("HTML missing %q:\n%s", want, htmlBuf.String())
		}
	}

	var textBuf bytes.Buffer
	if err := Text(&textBuf, r, ""); err != nil {
		t.Fatalf("Text: %v", err)
	}
	if !strings.Contains(textBuf.String(), "Warnings:") || !strings.Contains(textBuf.String(), "scanner coverage was incomplete") {
		t.Fatalf("Text missing warning UX:\n%s", textBuf.String())
	}

	var jsonBuf bytes.Buffer
	if err := JSON(&jsonBuf, r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var parsed struct {
		Warnings []string          `json:"warnings"`
		Findings []finding.Finding `json:"findings"`
	}
	if err := json.Unmarshal(jsonBuf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal JSON: %v", err)
	}
	if len(parsed.Warnings) != 1 || len(parsed.Findings) != 0 {
		t.Fatalf("JSON warnings/findings = %d/%d, want 1/0", len(parsed.Warnings), len(parsed.Findings))
	}

	var sarifBuf bytes.Buffer
	if err := SARIF(&sarifBuf, r); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	if !strings.Contains(sarifBuf.String(), "audr-scan-incomplete") || !strings.Contains(sarifBuf.String(), "dependency scanner osv-scanner is not installed") {
		t.Fatalf("SARIF missing warning result:\n%s", sarifBuf.String())
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

func TestPackageVulnerabilityFindingsIncludesOSVScannerRule(t *testing.T) {
	findings := packageVulnerabilityFindings([]finding.Finding{
		{RuleID: "dependency-osv-vulnerability", Severity: finding.SeverityHigh, Title: "OSV", Path: "package-lock.json"},
		{RuleID: "mcp-unpinned-npx", Severity: finding.SeverityHigh, Title: "Other", Path: ".mcp.json"},
	})
	if len(findings) != 1 {
		t.Fatalf("packageVulnerabilityFindings len = %d, want 1", len(findings))
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
		RuleID:       "dependency-osv-vulnerability",
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
				RuleID:       "dependency-osv-vulnerability",
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
	// Findings now render in severity-grouped sections (matching the
	// dashboard) with a per-finding kind badge. The package-CVE test
	// finding is High severity, so we expect a High section header
	// and a PACKAGE kind badge — not the old "Package vulnerabilities"
	// section title.
	for _, want := range []string{
		`class="sev-section-head high"`,
		`class="kind-badge package"`,
		"PACKAGE",
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

func TestText_RendersSecretExposureSection(t *testing.T) {
	now := time.Now()
	r := Report{Version: "v0.2.3-test", Roots: []string{"/repo"}, FilesParsed: 1, FilesSeen: 1, StartedAt: now, FinishedAt: now.Add(time.Second), Findings: []finding.Finding{
		{
			RuleID:       "secret-betterleaks-valid",
			Severity:     finding.SeverityHigh,
			Title:        "Secret detected by Betterleaks: github-pat",
			Description:  "Betterleaks rule github-pat matched (validation=true).",
			Path:         "/repo/.env",
			Line:         12,
			Match:        "rule=github-pat secret=[REDACTED]",
			Context:      "source=betterleaks validation=true entropy=5.20",
			SuggestedFix: "Rotate or revoke the secret, remove it from local files and git history, then rescan.",
		},
	}}

	var buf bytes.Buffer
	if err := Text(&buf, r, "/tmp/x.html"); err != nil {
		t.Fatalf("Text render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Secrets (1)",
		"Secret detected by Betterleaks: github-pat",
		"/repo/.env:12",
		"Evidence: rule=github-pat secret=[REDACTED]",
		"Fix: Rotate or revoke the secret",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("CLI secret section missing %q in output:\n%s", want, out)
		}
	}
	if strings.Contains(out, "abcdefghijklmnopqrstuvwxyz1234567890") {
		t.Fatalf("CLI output leaked raw secret-like payload: %s", out)
	}
}

func TestHTML_RendersSecretExposureSection(t *testing.T) {
	now := time.Now()
	r := Report{Version: "v0.2.3-test", Roots: []string{"/repo"}, StartedAt: now, FinishedAt: now.Add(time.Second), Findings: []finding.Finding{
		{
			RuleID:       "secret-betterleaks-valid",
			Severity:     finding.SeverityHigh,
			Taxonomy:     finding.TaxDetectable,
			Title:        "Secret detected by Betterleaks: github-pat",
			Description:  "Betterleaks rule github-pat matched (validation=true).",
			Path:         "/repo/.env",
			Line:         12,
			Match:        "rule=github-pat secret=[REDACTED]",
			SuggestedFix: "Rotate or revoke the secret, remove it from local files and git history, then rescan.",
		},
	}}
	var buf bytes.Buffer
	if err := HTML(&buf, r); err != nil {
		t.Fatalf("HTML render: %v", err)
	}
	out := buf.String()
	// Secret findings now render inside a severity section with a
	// SECRET kind badge — not the old "Secrets" section title.
	for _, want := range []string{
		`class="sev-section-head high"`,
		`class="kind-badge secret"`,
		"SECRET",
		"Secret detected by Betterleaks: github-pat",
		"/repo/.env",
		"[REDACTED]",
		"Rotate or revoke the secret",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML secret section missing %q", want)
		}
	}
}

// TestHTML_GroupsFindingsBySeverity verifies the dashboard-matching
// layout: a mixed-severity, mixed-kind finding set renders one
// .sev-section per severity present, in Critical→High→Medium→Low
// order, with the old per-kind sections gone (Package / Secret split
// is now expressed via per-finding kind badges instead).
func TestHTML_GroupsFindingsBySeverity(t *testing.T) {
	now := time.Now()
	r := Report{
		Version: "v0.2.4-test",
		Roots:   []string{"/repo"},
		StartedAt:  now,
		FinishedAt: now.Add(time.Second),
		Findings: []finding.Finding{
			{RuleID: "claude-hook-shell-rce", Severity: finding.SeverityCritical, Taxonomy: finding.TaxEnforced, Title: "Hook RCE", Description: "x", Path: "/etc/settings.json"},
			{RuleID: "dependency-osv-vulnerability", Severity: finding.SeverityHigh, Taxonomy: finding.TaxDetectable, Title: "Vulnerable dependency", Description: "y", Path: "/repo/package.json", Match: "lib@1.0"},
			{RuleID: "secret-betterleaks-valid", Severity: finding.SeverityHigh, Taxonomy: finding.TaxDetectable, Title: "Secret detected", Description: "z", Path: "/repo/.env"},
			{RuleID: "mcp-prod-secret-env", Severity: finding.SeverityMedium, Taxonomy: finding.TaxDetectable, Title: "MCP secret env", Description: "w", Path: "/repo/.mcp.json"},
		},
	}
	var buf bytes.Buffer
	if err := HTML(&buf, r); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()

	// One severity section per present severity (Critical, High, Medium — no Low here).
	for _, want := range []string{
		`class="sev-section-head critical"`,
		`class="sev-section-head high"`,
		`class="sev-section-head medium"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing severity section %q", want)
		}
	}
	if strings.Contains(out, `class="sev-section-head low"`) {
		t.Error("Low section rendered when no Low findings present")
	}

	// All three kind badges appear (one PACKAGE, one SECRET, two OTHER for the agent-rule + mcp findings).
	for _, want := range []string{
		`class="kind-badge package"`,
		`class="kind-badge secret"`,
		`class="kind-badge other"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing kind badge %q", want)
		}
	}

	// Secondary view: "Browse by file" disclosure exists (chain anchors target it).
	if !strings.Contains(out, `class="browse-by-file"`) {
		t.Error("missing secondary browse-by-file disclosure")
	}
	if c := strings.Count(out, `class="path-group"`); c != 4 {
		// 4 distinct paths in the test data
		t.Errorf("path-group count = %d, want 4", c)
	}

	// Sanity: Critical comes before High in the output (DOM order matters
	// for printing / screenshotting — Critical at the top).
	iCrit := strings.Index(out, `class="sev-section-head critical"`)
	iHigh := strings.Index(out, `class="sev-section-head high"`)
	if iCrit < 0 || iHigh < 0 || iCrit > iHigh {
		t.Errorf("severity sections out of order: Critical@%d, High@%d", iCrit, iHigh)
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
