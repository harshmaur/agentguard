package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/output"
)

// buildAudr compiles the audr binary once per test process and reuses
// the same path across cases. Building per-test cost ~1-20s depending
// on how warm the build cache is; amortizing across the E2E suite keeps
// `go test ./cmd/audr/` reasonable.
//
// The binary lives in t.TempDir() of the FIRST test that calls
// buildAudr — Go's test framework cleans it up at process exit. Later
// callers from other tests reuse the same path.
func buildAudr(t *testing.T) string {
	t.Helper()
	buildAudrOnce.Do(func() {
		// Use os.MkdirTemp (not t.TempDir) because the first caller's
		// temp dir is cleaned up when its test ends, while later tests
		// would still reference the binary. We accept a small temp
		// leak: the binary is small and the OS reaps /tmp on reboot.
		dir, err := os.MkdirTemp("", "audr-e2e-bin-")
		if err != nil {
			buildAudrErr = err
			return
		}
		bin := filepath.Join(dir, "audr")
		cmd := exec.Command("go", "build", "-o", bin, "./cmd/audr")
		repo, absErr := filepath.Abs("../..")
		if absErr != nil {
			buildAudrErr = absErr
			return
		}
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			buildAudrErr = err
			buildAudrOutput = string(out)
			return
		}
		buildAudrPath = bin
	})
	if buildAudrErr != nil {
		t.Fatalf("buildAudr: %v\n%s", buildAudrErr, buildAudrOutput)
	}
	return buildAudrPath
}

var (
	buildAudrOnce   sync.Once
	buildAudrPath   string
	buildAudrErr    error
	buildAudrOutput string
)

func runAudr(t *testing.T, bin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var oBuf, eBuf bytes.Buffer
	cmd.Stdout = &oBuf
	cmd.Stderr = &eBuf
	err = cmd.Run()
	return oBuf.String(), eBuf.String(), err
}

// makeScanRoot writes a small fixture tree the scanner can find findings
// in. Uses a vendored copy of the agent-rule trigger patterns so the
// test does not depend on testdata/ paths shifting.
func makeScanRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	// One MCP config that fires the plaintext-api-key rule.
	mcp := filepath.Join(root, ".mcp.json")
	if err := os.WriteFile(mcp, []byte(`{
  "mcpServers": {
    "github-prod": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }
    }
  }
}
`), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return root
}

// TestScanBaseline_SelfDiffYieldsAllStillPresent: running --baseline
// against the SAME source must produce 0 resolved + N still_present
// + 0 newly_introduced. This is the "did nothing change" property —
// the most basic sanity check on the diff math.
func TestScanBaseline_SelfDiffYieldsAllStillPresent(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E binary build")
	}
	bin := buildAudr(t)
	root := makeScanRoot(t)
	before := filepath.Join(t.TempDir(), "before.json")
	if _, _, err := runAudr(t, bin, "scan", root, "-f", "json", "--no-deps", "--no-secrets", "-o", before); err != nil && !isFindingsPresentExit(err) {
		t.Fatalf("baseline scan: %v", err)
	}
	stdout, _, err := runAudr(t, bin, "scan", root, "-f", "json", "--no-deps", "--no-secrets", "--baseline="+before)
	if err != nil && !isFindingsPresentExit(err) {
		t.Fatalf("baseline-against-self scan: %v", err)
	}
	jr, parseErr := parseReportFromMixed(stdout)
	if parseErr != nil {
		t.Fatalf("parse: %v\nOUT:\n%s", parseErr, stdout)
	}
	if jr.BaselineDiff == nil {
		t.Fatalf("baseline_diff missing from output")
	}
	if len(jr.BaselineDiff.Resolved) != 0 {
		t.Errorf("self-diff resolved should be 0, got %d: %v", len(jr.BaselineDiff.Resolved), jr.BaselineDiff.Resolved)
	}
	if len(jr.BaselineDiff.NewlyIntroduced) != 0 {
		t.Errorf("self-diff newly_introduced should be 0, got %d: %v", len(jr.BaselineDiff.NewlyIntroduced), jr.BaselineDiff.NewlyIntroduced)
	}
	if len(jr.BaselineDiff.StillPresent) == 0 {
		t.Errorf("self-diff still_present should be > 0; scan found %d findings", jr.Stats.Total)
	}
	if !jr.BaselineDiff.SuppressionsOff {
		t.Errorf("suppressions_off must be true; got false")
	}
}

// TestScanBaseline_SuppressionsOffInvariant — the security-critical
// test. Confirms that adding the finding's rule to .audrignore AFTER
// the baseline does NOT cause it to appear in baseline_diff.resolved.
// The diff truth must be computed against the unsuppressed scanner
// result, otherwise an agent could fake "fixed" by suppressing.
func TestScanBaseline_SuppressionsOffInvariant(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E binary build")
	}
	bin := buildAudr(t)
	root := makeScanRoot(t)
	before := filepath.Join(t.TempDir(), "before.json")
	if _, _, err := runAudr(t, bin, "scan", root, "-f", "json", "--no-deps", "--no-secrets", "-o", before); err != nil && !isFindingsPresentExit(err) {
		t.Fatalf("baseline scan: %v", err)
	}
	// Read the baseline so we know the finding ids and which rule_ids
	// to suppress.
	baseBytes, err := os.ReadFile(before)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	var baseJR output.JSONReport
	if err := json.Unmarshal(baseBytes, &baseJR); err != nil {
		t.Fatalf("parse baseline: %v", err)
	}
	if len(baseJR.Findings) == 0 {
		t.Fatalf("baseline had 0 findings; can't test suppression")
	}

	// Write .audrignore that suppresses EVERY baseline rule_id by exact
	// match. This is the agent-cheat scenario: instead of fixing the
	// code, the agent appends suppressions.
	ignoreLines := make([]string, 0, len(baseJR.Findings))
	seen := map[string]bool{}
	for _, fnd := range baseJR.Findings {
		if seen[fnd.RuleID] {
			continue
		}
		seen[fnd.RuleID] = true
		ignoreLines = append(ignoreLines, fnd.RuleID)
	}
	if err := os.WriteFile(filepath.Join(root, ".audrignore"), []byte(strings.Join(ignoreLines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write .audrignore: %v", err)
	}

	// Rescan with --baseline. The user-visible findings array will be
	// empty (everything suppressed). But baseline_diff.still_present
	// MUST list every prior finding — they were not fixed, only hidden.
	stdout, _, runErr := runAudr(t, bin, "scan", root, "-f", "json", "--no-deps", "--no-secrets", "--baseline="+before)
	if runErr != nil && !isFindingsPresentExit(runErr) {
		t.Fatalf("rescan: %v", runErr)
	}
	jr, parseErr := parseReportFromMixed(stdout)
	if parseErr != nil {
		t.Fatalf("parse: %v\nOUT:\n%s", parseErr, stdout)
	}
	if jr.BaselineDiff == nil {
		t.Fatalf("baseline_diff missing")
	}
	if !jr.BaselineDiff.SuppressionsOff {
		t.Fatalf("suppressions_off must be true to advertise the invariant")
	}
	if len(jr.BaselineDiff.Resolved) > 0 {
		t.Errorf("INVARIANT VIOLATED: agent suppressed findings appeared as 'resolved'.\nresolved=%v\nstill_present=%v",
			jr.BaselineDiff.Resolved, jr.BaselineDiff.StillPresent)
	}
	if len(jr.BaselineDiff.StillPresent) == 0 {
		t.Errorf("INVARIANT VIOLATED: suppressed findings should appear in still_present (raw scanner truth)")
	}
}

// TestScanBaseline_NewFindingsAppearAsNew — when the rescan produces
// findings the baseline didn't have, they go in newly_introduced.
func TestScanBaseline_NewFindingsAppearAsNew(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E binary build")
	}
	bin := buildAudr(t)
	root := makeScanRoot(t)
	// Empty baseline: every current finding will appear as new.
	emptyBaseline := output.JSONReport{
		Schema:   output.SchemaURL,
		Version:  "test",
		Findings: []finding.Finding{},
	}
	emptyPath := filepath.Join(t.TempDir(), "empty.json")
	f, err := os.Create(emptyPath)
	if err != nil {
		t.Fatalf("create empty: %v", err)
	}
	if err := output.WriteJSON(f, emptyBaseline); err != nil {
		t.Fatalf("write empty: %v", err)
	}
	f.Close()

	stdout, _, runErr := runAudr(t, bin, "scan", root, "-f", "json", "--no-deps", "--no-secrets", "--baseline="+emptyPath)
	if runErr != nil && !isFindingsPresentExit(runErr) {
		t.Fatalf("scan: %v", runErr)
	}
	jr, parseErr := parseReportFromMixed(stdout)
	if parseErr != nil {
		t.Fatalf("parse: %v\nOUT:\n%s", parseErr, stdout)
	}
	if jr.BaselineDiff == nil {
		t.Fatalf("baseline_diff missing")
	}
	if len(jr.BaselineDiff.NewlyIntroduced) == 0 {
		t.Errorf("empty-baseline rescan should put every finding in newly_introduced, got 0")
	}
	if len(jr.BaselineDiff.Resolved) != 0 {
		t.Errorf("empty baseline can't have resolved findings, got %d", len(jr.BaselineDiff.Resolved))
	}
}

// TestScanBaseline_MalformedFile — clear error, no scan run.
func TestScanBaseline_MalformedFile(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E binary build")
	}
	bin := buildAudr(t)
	root := makeScanRoot(t)
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, stderr, err := runAudr(t, bin, "scan", root, "-f", "json", "--no-deps", "--no-secrets", "--baseline="+bad)
	if err == nil {
		t.Fatalf("expected error for malformed baseline, got nil")
	}
	if !strings.Contains(stderr, "parse --baseline") {
		t.Errorf("stderr should mention 'parse --baseline'; got %q", stderr)
	}
}

// TestScanBaseline_MissingFile — clear error, no scan run.
func TestScanBaseline_MissingFile(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E binary build")
	}
	bin := buildAudr(t)
	root := makeScanRoot(t)
	_, stderr, err := runAudr(t, bin, "scan", root, "-f", "json", "--no-deps", "--no-secrets", "--baseline=/nonexistent/audr/baseline.json")
	if err == nil {
		t.Fatalf("expected error for missing baseline")
	}
	if !strings.Contains(stderr, "open --baseline") {
		t.Errorf("stderr should mention 'open --baseline'; got %q", stderr)
	}
}

// isFindingsPresentExit is true when an audr subprocess exited with
// code 1 because findings were present (the design: H/C findings → 1,
// clean → 0). The error in that case is *exec.ExitError with code 1
// and no underlying Go error.
func isFindingsPresentExit(err error) bool {
	ee, ok := err.(*exec.ExitError)
	if !ok {
		return false
	}
	return ee.ExitCode() == 1
}

// parseReportFromMixed extracts a JSONReport from output that may
// contain a non-JSON text summary mixed in. In the current CLI, when
// -o is not used the JSON goes to stdout and the readable summary to
// stderr; we feed stdout to this parser. Returns the parsed report or
// an error.
func parseReportFromMixed(s string) (output.JSONReport, error) {
	// Find first '{' (start of JSON object).
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return output.JSONReport{}, &parseErr{"no JSON object found in output"}
	}
	var jr output.JSONReport
	dec := json.NewDecoder(strings.NewReader(s[start:]))
	if err := dec.Decode(&jr); err != nil {
		return output.JSONReport{}, err
	}
	return jr, nil
}

type parseErr struct{ msg string }

func (e *parseErr) Error() string { return e.msg }
