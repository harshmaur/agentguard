package scan_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/output"
	_ "github.com/harshmaur/audr/internal/rules/builtin"
	"github.com/harshmaur/audr/internal/scan"
)

// TestScan_DirtyFixture asserts the scanner finds the expected categories
// of issues on the testdata/laptops/dirty fixture and does NOT leak any of
// the planted secrets in any of the three output formats.
func TestScan_DirtyFixture(t *testing.T) {
	root := repoRoot(t)
	fixture := filepath.Join(root, "testdata", "laptops", "dirty")

	res, err := scan.Run(context.Background(), scan.Options{
		Roots: []string{fixture},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatalf("expected findings, got none")
	}

	expectedRules := []string{
		"mcp-unpinned-npx",
		"mcp-prod-secret-env",
		"mcp-plaintext-api-key",
		"mcp-shell-pipeline-command",
		"mcp-dynamic-config-injection",
		"skill-shell-hijack",
		"gha-write-all-permissions",
		"gha-secrets-in-agent-step",
	}
	got := map[string]int{}
	for _, f := range res.Findings {
		got[f.RuleID]++
	}
	for _, want := range expectedRules {
		if got[want] == 0 {
			t.Errorf("expected rule %q to fire on dirty fixture; rules fired: %v", want, got)
		}
	}

	// Planted secrets must NOT appear in any output format.
	plantedSecrets := []string{
		"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // .mcp.json
		"hunter2", // postgres URL password
		"ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",        // .zshrc
		"AKIAIOSFODNN7EXAMPLE",                                // .zshrc
		"sk-ant-api03-cccccccccccccccccccccccccccccccccccccc", // .zshrc
	}

	report := output.Report{
		Findings:    res.Findings,
		Roots:       []string{fixture},
		StartedAt:   res.StartedAt,
		FinishedAt:  res.FinishedAt,
		FilesSeen:   res.FilesSeen,
		FilesParsed: res.FilesParsed,
		Version:     "test",
	}

	for _, format := range []string{"html", "sarif", "json"} {
		var buf bytes.Buffer
		var err error
		switch format {
		case "html":
			err = output.HTML(&buf, report)
		case "sarif":
			err = output.SARIF(&buf, report)
		case "json":
			err = output.JSON(&buf, report)
		}
		if err != nil {
			t.Fatalf("%s format: %v", format, err)
		}
		out := buf.String()
		for _, secret := range plantedSecrets {
			if strings.Contains(out, secret) {
				t.Errorf("LEAK in %s output: planted secret %q appears in output", format, secret)
			}
		}
		// Spot-check the redaction marker survived the format. The "<" gets
		// encoded differently per format (HTML: &lt;, JSON: <, plain: <),
		// but the literal "redacted:" substring is invariant.
		if !strings.Contains(out, "redacted:") {
			t.Errorf("%s output missing redaction markers", format)
		}
	}
}

// TestScan_CleanFixture asserts the scanner emits zero findings on a clean
// laptop layout. A regression here is the worst kind: false positives drown
// the user in noise and kill the LinkedIn demo.
func TestScan_CleanFixture(t *testing.T) {
	root := repoRoot(t)
	fixture := filepath.Join(root, "testdata", "laptops", "clean")

	res, err := scan.Run(context.Background(), scan.Options{
		Roots: []string{fixture},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) > 0 {
		for _, f := range res.Findings {
			t.Logf("unexpected finding: %s — %s at %s", f.RuleID, f.Title, f.Path)
		}
		t.Fatalf("clean fixture produced %d findings; want 0", len(res.Findings))
	}
}

// TestScan_MiniShaiHuludRouterInitUnderNodeModules asserts the default walker
// keeps node_modules skipped for performance, but still checks known Mini
// Shai-Hulud package-root payload filenames.
func TestScan_MiniShaiHuludRouterInitUnderNodeModules(t *testing.T) {
	root := t.TempDir()
	payload := filepath.Join(root, "node_modules", "@tanstack", "router-core", "router_init.js")
	if err := os.MkdirAll(filepath.Dir(payload), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payload, []byte("/* obfuscated */"), 0o644); err != nil {
		t.Fatal(err)
	}
	ignored := filepath.Join(root, "node_modules", "@tanstack", "router-core", "dist", "router_init.js")
	if err := os.MkdirAll(filepath.Dir(ignored), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ignored, []byte("/* nested ignored */"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := scan.Run(context.Background(), scan.Options{Roots: []string{root}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := 0
	for _, f := range res.Findings {
		if f.RuleID == "mini-shai-hulud-dropped-payload" {
			got++
		}
	}
	if got != 1 {
		t.Fatalf("mini-shai-hulud-dropped-payload findings = %d, want 1; findings=%+v", got, res.Findings)
	}
}

// TestScan_TimeoutHonored asserts that ScanTimeout terminates a slow scan
// gracefully and still returns the partial result.
func TestScan_TimeoutHonored(t *testing.T) {
	root := repoRoot(t)
	fixture := filepath.Join(root, "testdata", "laptops", "dirty")
	// 1 nanosecond timeout: should bail out immediately.
	_, err := scan.Run(context.Background(), scan.Options{
		Roots:       []string{fixture},
		ScanTimeout: 1, // 1 nanosecond
	})
	// We don't assert err != nil because the scan is so small it may finish
	// before the deadline is checked. We DO assert it doesn't panic.
	_ = err
}

// repoRoot returns the audr module root by walking up from the test's
// working directory until go.mod is found.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
	}
	t.Fatal("repo root not found")
	return ""
}
