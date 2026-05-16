package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/output"
)

// fixture builds a minimal JSONReport with two findings the tests can
// filter against. Both are file-kind so their StableIDs are derived from
// (rule_id, path, line, match).
func fixture(t *testing.T) output.JSONReport {
	t.Helper()
	high := finding.New(finding.Args{
		RuleID:       "secret-anthropic-api-key",
		Severity:     finding.SeverityCritical,
		Title:        "API key in source",
		Description:  "Anthropic API key found.",
		Path:         "src/config.ts",
		Line:         47,
		Match:        "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SuggestedFix: "Move to env var.",
		FixAuthority: finding.FixAuthorityYou,
	})
	low := finding.New(finding.Args{
		RuleID:       "claude-hook-overuse",
		Severity:     finding.SeverityLow,
		Title:        "Many Claude hooks",
		Description:  "Advisory.",
		Path:         "/home/u/.claude/claude.json",
		Line:         12,
		Match:        "hooks: 17",
		SuggestedFix: "Audit hook count.",
		FixAuthority: finding.FixAuthorityMaintainer,
	})
	return output.JSONReport{
		Schema:   output.SchemaURL,
		Version:  "0.0.0-test",
		Findings: []finding.Finding{high, low},
		Stats:    output.ComputeStats([]finding.Finding{high, low}, 2, 2, 0, 0),
	}
}

// writeFixtureFile dumps a JSONReport to a temp file and returns the path.
func writeFixtureFile(t *testing.T, jr output.JSONReport) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "report.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	defer f.Close()
	if err := output.WriteJSON(f, jr); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return p
}

// runCmd executes the audr root command with the given args + stdin, and
// returns stdout + stderr + error. The cobra cmd's I/O is rewired so
// nothing leaks to the real os.Stdout.
func runCmd(t *testing.T, args []string, stdin string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := newRootCmd()
	var outBuf, errBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err = cmd.Execute()
	return outBuf.String(), errBuf.String(), err
}

func TestFindingsLs_AllFormatsHappyPath(t *testing.T) {
	path := writeFixtureFile(t, fixture(t))

	out, _, err := runCmd(t, []string{"findings", "ls", "--from", path}, "")
	if err != nil {
		t.Fatalf("ls text: %v", err)
	}
	if !strings.Contains(out, "[critical]") || !strings.Contains(out, "[low]") {
		t.Errorf("text format missing severities.\nOUTPUT:\n%s", out)
	}

	out, _, err = runCmd(t, []string{"findings", "ls", "--from", path, "--format", "md"}, "")
	if err != nil {
		t.Fatalf("ls md: %v", err)
	}
	if !strings.HasPrefix(out, "| id |") {
		t.Errorf("md format missing table header.\nOUTPUT:\n%s", out)
	}

	out, _, err = runCmd(t, []string{"findings", "ls", "--from", path, "--format", "json"}, "")
	if err != nil {
		t.Fatalf("ls json: %v", err)
	}
	var got output.JSONReport
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("ls json output not parseable: %v\nOUTPUT:\n%s", err, out)
	}
	if got.Schema != output.SchemaURL {
		t.Errorf("ls json output schema = %q, want %q", got.Schema, output.SchemaURL)
	}
	if len(got.Findings) != 2 {
		t.Errorf("ls json findings count = %d, want 2", len(got.Findings))
	}
	if got.Stats.Total != 2 || got.Stats.Critical != 1 || got.Stats.Low != 1 {
		t.Errorf("ls json stats wrong: %+v", got.Stats)
	}
}

func TestFindingsLs_SeverityFilter(t *testing.T) {
	path := writeFixtureFile(t, fixture(t))

	out, _, err := runCmd(t, []string{"findings", "ls", "--from", path, "--severity", "ge:high", "--format", "json"}, "")
	if err != nil {
		t.Fatalf("ls ge:high: %v", err)
	}
	var got output.JSONReport
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got.Findings) != 1 || got.Findings[0].Severity != finding.SeverityCritical {
		t.Errorf("ge:high should yield only critical; got %d findings", len(got.Findings))
	}
	if got.AppliedFilters == nil || got.AppliedFilters.Severity != "ge:high" {
		t.Errorf("applied_filters.severity not propagated: %+v", got.AppliedFilters)
	}
}

func TestFindingsLs_SeverityOperators(t *testing.T) {
	path := writeFixtureFile(t, fixture(t))
	cases := []struct {
		flag       string
		wantCount  int
		wantSevStr string // first finding's severity if count > 0
	}{
		{"ge:high", 1, "critical"},
		{"gt:high", 1, "critical"},
		{"eq:low", 1, "low"},
		{"eq:critical", 1, "critical"},
		{"le:low", 1, "low"},
		{"lt:medium", 1, "low"},
		{"all", 2, "critical"},
	}
	for _, tc := range cases {
		t.Run(tc.flag, func(t *testing.T) {
			out, _, err := runCmd(t, []string{"findings", "ls", "--from", path, "--severity", tc.flag, "--format", "json"}, "")
			if err != nil {
				t.Fatalf("%s: %v", tc.flag, err)
			}
			var got output.JSONReport
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(got.Findings) != tc.wantCount {
				t.Errorf("%s yielded %d findings, want %d", tc.flag, len(got.Findings), tc.wantCount)
			}
		})
	}
}

func TestFindingsLs_BadSeverity(t *testing.T) {
	path := writeFixtureFile(t, fixture(t))
	_, _, err := runCmd(t, []string{"findings", "ls", "--from", path, "--severity", "weird"}, "")
	if err == nil {
		t.Fatalf("expected error for bad severity, got nil")
	}
	if !strings.Contains(err.Error(), "OP:LEVEL") {
		t.Errorf("error message should mention OP:LEVEL syntax; got %q", err.Error())
	}
}

func TestFindingsLs_FixAuthorityFilter(t *testing.T) {
	path := writeFixtureFile(t, fixture(t))

	out, _, err := runCmd(t, []string{"findings", "ls", "--from", path, "--fix-authority", "you", "--format", "json"}, "")
	if err != nil {
		t.Fatalf("ls you: %v", err)
	}
	var got output.JSONReport
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got.Findings) != 1 || got.Findings[0].FixAuthority != finding.FixAuthorityYou {
		t.Errorf("fix-authority=you should yield only YOU findings; got %d", len(got.Findings))
	}
}

func TestFindingsLs_BadFixAuthority(t *testing.T) {
	path := writeFixtureFile(t, fixture(t))
	_, _, err := runCmd(t, []string{"findings", "ls", "--from", path, "--fix-authority", "weird"}, "")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "you|maintainer|upstream") {
		t.Errorf("error message should enumerate values; got %q", err.Error())
	}
}

func TestFindingsLs_RuleIDGlob(t *testing.T) {
	path := writeFixtureFile(t, fixture(t))

	out, _, err := runCmd(t, []string{"findings", "ls", "--from", path, "--rule-id", "secret-*", "--format", "json"}, "")
	if err != nil {
		t.Fatalf("ls glob: %v", err)
	}
	var got output.JSONReport
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got.Findings) != 1 || !strings.HasPrefix(got.Findings[0].RuleID, "secret-") {
		t.Errorf("rule-id glob filter failed; got %d findings", len(got.Findings))
	}
}

func TestFindingsLs_StdinPipe(t *testing.T) {
	jr := fixture(t)
	var buf bytes.Buffer
	if err := output.WriteJSON(&buf, jr); err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, _, err := runCmd(t, []string{"findings", "ls", "--from", "-", "--format", "json"}, buf.String())
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	var got output.JSONReport
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("parse: %v\nOUT:\n%s", err, out)
	}
	if len(got.Findings) != 2 {
		t.Errorf("stdin pipe lost findings: got %d, want 2", len(got.Findings))
	}
}

func TestFindingsLs_EmptyResultStillValidJSON(t *testing.T) {
	path := writeFixtureFile(t, fixture(t))
	out, _, err := runCmd(t, []string{"findings", "ls", "--from", path, "--rule-id", "no-match-anywhere-*", "--format", "json"}, "")
	if err != nil {
		t.Fatalf("ls: %v", err)
	}
	var got output.JSONReport
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("empty-result JSON unparseable: %v\nOUTPUT:\n%s", err, out)
	}
	if len(got.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(got.Findings))
	}
	if got.Stats.Total != 0 {
		t.Errorf("stats should reflect filtered count, got %d", got.Stats.Total)
	}
}

func TestFindingsLs_MalformedInput(t *testing.T) {
	_, _, err := runCmd(t, []string{"findings", "ls", "--from", "-"}, "not json at all")
	if err == nil {
		t.Fatalf("expected parse error, got nil")
	}
	if !strings.Contains(err.Error(), "parse audr report JSON") {
		t.Errorf("error should mention parse; got %q", err.Error())
	}
}

func TestFindingsLs_NoInput(t *testing.T) {
	// No --from, no stdin pipe — runCmd uses strings.Reader which is a
	// real Reader but stdinIsPipe() reads os.Stdin's actual stat. In test
	// invocation, os.Stdin is the terminal-style FD, so stdinIsPipe()
	// returns false and we get the "no input" error.
	_, _, err := runCmd(t, []string{"findings", "ls"}, "")
	if err == nil {
		t.Fatalf("expected no-input error, got nil")
	}
	if !strings.Contains(err.Error(), "no input") {
		t.Errorf("error should say 'no input'; got %q", err.Error())
	}
}

func TestFindingsShow_ByFullID(t *testing.T) {
	jr := fixture(t)
	path := writeFixtureFile(t, jr)
	id := jr.Findings[0].StableID()

	out, _, err := runCmd(t, []string{"findings", "show", id, "--from", path}, "")
	if err != nil {
		t.Fatalf("show: %v", err)
	}
	if !strings.Contains(out, "# audr finding "+id) {
		t.Errorf("show output missing header.\nOUTPUT:\n%s", out)
	}
	if !strings.Contains(out, "<<<UNTRUSTED-CONTEXT") {
		t.Errorf("show output missing envelope.\nOUTPUT:\n%s", out)
	}
}

func TestFindingsShow_ByShortPrefix(t *testing.T) {
	jr := fixture(t)
	path := writeFixtureFile(t, jr)
	id := jr.Findings[0].StableID()
	short := id[:6]

	out, _, err := runCmd(t, []string{"findings", "show", short, "--from", path, "--format", "text"}, "")
	if err != nil {
		t.Fatalf("show short: %v", err)
	}
	if !strings.Contains(out, "id:             "+id) {
		t.Errorf("short-prefix resolution wrong.\nOUTPUT:\n%s", out)
	}
}

func TestFindingsShow_UnknownID(t *testing.T) {
	jr := fixture(t)
	path := writeFixtureFile(t, jr)
	_, _, err := runCmd(t, []string{"findings", "show", "ffffffff", "--from", path}, "")
	if err == nil {
		t.Fatalf("expected error for unknown id")
	}
	if !strings.Contains(err.Error(), "no finding matches") {
		t.Errorf("error should say 'no finding matches'; got %q", err.Error())
	}
}

func TestFindingsShow_TooShort(t *testing.T) {
	jr := fixture(t)
	path := writeFixtureFile(t, jr)
	_, _, err := runCmd(t, []string{"findings", "show", "ab", "--from", path}, "")
	if err == nil {
		t.Fatalf("expected too-short error")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("error should say 'too short'; got %q", err.Error())
	}
}

// TestFindingsShow_AmbiguousPrefix synthesizes a fixture where two
// findings share a fingerprint prefix, then asserts the error lists both
// candidates. Because real findings rarely collide on 4-char prefixes,
// we use the same finding twice in the source — but with different
// fingerprint-irrelevant fields, so they have IDENTICAL StableIDs.
// That's the worst-case collision: same id, multiple distinct objects
// the agent could mean.
//
// Actually that's a dedup bug, not an ambiguity. For real prefix
// collision testing, we exploit that any prefix shorter than the full id
// matches multiple findings if we construct enough findings. The test
// uses two findings that happen to share a short prefix.
func TestFindingsShow_AmbiguousPrefix(t *testing.T) {
	// Find a short prefix length where the two fixture findings collide.
	// If they don't naturally collide on any prefix, the test is skipped
	// — we can't guarantee a collision against hash output. Construct
	// many findings and search for one.
	findings := make([]finding.Finding, 0, 64)
	for i := 0; i < 64; i++ {
		findings = append(findings, finding.New(finding.Args{
			RuleID:   "test-rule",
			Severity: finding.SeverityHigh,
			Path:     "/p",
			Line:     i + 1,
			Match:    "m",
		}))
	}

	// Find shortest prefix where >=2 findings collide.
	prefixHits := map[string][]int{}
	for i, f := range findings {
		id := f.StableID()
		for n := 4; n <= 8; n++ {
			pref := id[:n]
			prefixHits[pref] = append(prefixHits[pref], i)
		}
	}
	var collidingPrefix string
	for pref, idxs := range prefixHits {
		if len(idxs) >= 2 && len(pref) >= 4 {
			collidingPrefix = pref
			break
		}
	}
	if collidingPrefix == "" {
		t.Skip("no natural prefix collision found in 64 synthetic findings; would need a larger pool")
	}

	jr := output.JSONReport{
		Schema:   output.SchemaURL,
		Findings: findings,
		Stats:    output.ComputeStats(findings, 0, 0, 0, 0),
	}
	path := writeFixtureFile(t, jr)
	_, _, err := runCmd(t, []string{"findings", "show", collidingPrefix, "--from", path}, "")
	if err == nil {
		t.Fatalf("expected ambiguous-prefix error")
	}
	if !strings.Contains(err.Error(), "matches") {
		t.Errorf("error should mention 'matches'; got %q", err.Error())
	}
	// Both colliding ids must appear in the error so the agent can pick.
	hits := strings.Count(err.Error(), "\n  ") // each candidate starts with "  "
	if hits < 2 {
		t.Errorf("error should list >=2 candidates; got hits=%d, full error:\n%s", hits, err.Error())
	}
}

func TestFindingsShow_JSONFormat(t *testing.T) {
	jr := fixture(t)
	path := writeFixtureFile(t, jr)
	id := jr.Findings[0].StableID()

	out, _, err := runCmd(t, []string{"findings", "show", id, "--from", path, "--format", "json"}, "")
	if err != nil {
		t.Fatalf("show json: %v", err)
	}
	var got output.JSONReport
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("parse: %v\nOUT:\n%s", err, out)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("show json should contain exactly one finding; got %d", len(got.Findings))
	}
	if got.Findings[0].StableID() != id {
		t.Errorf("id mismatch: %q vs %q", got.Findings[0].StableID(), id)
	}
}

// TestSchemaAdditivity_OldConsumerStillParses is T7's invariant: an
// older consumer that only knows about v1.0 fields (no AppliedFilters,
// no BaselineDiff) must still successfully unmarshal a v1.1 Report that
// carries those new fields. We simulate the old consumer with a struct
// that has exactly the v1.0 field set and no others.
func TestSchemaAdditivity_OldConsumerStillParses(t *testing.T) {
	jr := fixture(t)
	jr.AppliedFilters = &output.AppliedFilters{Severity: "ge:high"}
	jr.BaselineDiff = &output.BaselineDiff{
		BaselinePath:    "before.json",
		Resolved:        []string{"abc"},
		StillPresent:    []string{},
		NewlyIntroduced: []string{},
		SuppressionsOff: true,
	}
	var buf bytes.Buffer
	if err := output.WriteJSON(&buf, jr); err != nil {
		t.Fatalf("write: %v", err)
	}

	// v1.0 consumer shape: knows only the original fields.
	type v10Stats struct {
		FilesSeen   int `json:"files_seen"`
		FilesParsed int `json:"files_parsed"`
		Suppressed  int `json:"suppressed"`
		Skipped     int `json:"skipped"`
		Total       int `json:"total"`
		Critical    int `json:"critical"`
		High        int `json:"high"`
		Medium      int `json:"medium"`
		Low         int `json:"low"`
	}
	type v10Report struct {
		Schema   string            `json:"schema"`
		Version  string            `json:"version"`
		Stats    v10Stats          `json:"stats"`
		Findings []finding.Finding `json:"findings"`
		// Intentionally NOT including AppliedFilters or BaselineDiff.
	}

	var v10 v10Report
	dec := json.NewDecoder(&buf)
	// Do NOT use DisallowUnknownFields — consumers ignoring new fields
	// is exactly the additivity contract.
	if err := dec.Decode(&v10); err != nil {
		t.Fatalf("v1.0 consumer failed to parse v1.1 output: %v", err)
	}
	if v10.Schema != output.SchemaURL {
		t.Errorf("schema URL changed: %q vs %q", v10.Schema, output.SchemaURL)
	}
	if len(v10.Findings) != len(jr.Findings) {
		t.Errorf("findings count lost in v1.0 parse: %d vs %d", len(v10.Findings), len(jr.Findings))
	}
}
