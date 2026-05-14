package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	// Register built-in rules so scan.Run can find them.
	_ "github.com/harshmaur/audr/internal/rules/builtin"
	"github.com/harshmaur/audr/internal/state"
)

// newTestStore opens a fresh state.Store in a temp dir, drives its
// writer goroutine, and registers cleanup. Mirrors state/store_test's
// helper but lives here so the orchestrator package doesn't import
// state's internal test helpers.
func newTestStore(t *testing.T) *state.Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := state.Open(state.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = s.Close() })
	go func() { _ = s.Run(ctx) }()
	time.Sleep(5 * time.Millisecond)
	return s
}

func TestOrchestratorRunOnceFindsRealRuleHit(t *testing.T) {
	// Plant a Codex config that triggers codex-trust-home-or-broad:
	// the rule fires on [projects."<home-or-root>"] trust_level = "trusted".
	// The fixture's filesystem path doesn't matter — the rule inspects
	// the TOML body's projects key.
	root := t.TempDir()
	codexCfg := filepath.Join(root, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexCfg), 0o700); err != nil {
		t.Fatal(err)
	}
	body := `
[projects."/home/parallels"]
trust_level = "trusted"
`
	if err := os.WriteFile(codexCfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	store := newTestStore(t)

	orch, err := New(Options{
		Store:   store,
		Roots:   []string{root},
		HomeDir: root,
		// RunSecrets=false: we don't have trufflehog in this test env
		// and we don't need it for this assertion.
		RunSecrets: ptr(false),
		RunOSPkg:   ptr(false),
		Interval:   time.Hour, // we drive runOnce directly; Run won't tick
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := orch.runOnce(context.Background()); err != nil {
		t.Fatalf("runOnce: %v", err)
	}

	// Verify the finding landed in the store.
	findings, err := store.SnapshotFindings(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding from the planted codex config")
	}
	var trustFinding *state.Finding
	for i := range findings {
		if findings[i].RuleID == "codex-trust-home-or-broad" {
			trustFinding = &findings[i]
			break
		}
	}
	if trustFinding == nil {
		t.Fatalf("no codex-trust-home-or-broad finding produced. got rules: %v", ruleIDs(findings))
	}
	if trustFinding.Severity != "critical" {
		t.Errorf("severity = %q, want critical", trustFinding.Severity)
	}
	if trustFinding.Category != "ai-agent" {
		t.Errorf("category = %q, want ai-agent", trustFinding.Category)
	}
	if trustFinding.Kind != "file" {
		t.Errorf("kind = %q, want file", trustFinding.Kind)
	}
}

func TestOrchestratorResolutionDetection(t *testing.T) {
	// Two cycles: first finds the config, second cycle the config is
	// fixed → the finding gets resolved automatically (the daemon's
	// "fix → goes green" loop).
	root := t.TempDir()
	codexCfg := filepath.Join(root, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexCfg), 0o700); err != nil {
		t.Fatal(err)
	}
	bad := `
[projects."/home/parallels"]
trust_level = "trusted"
`
	if err := os.WriteFile(codexCfg, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}

	store := newTestStore(t)
	orch, err := New(Options{
		Store:      store,
		Roots:      []string{root},
		HomeDir:    root,
		RunSecrets: ptr(false),
		RunOSPkg:   ptr(false),
		Interval:   time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Cycle 1: should produce the finding.
	if err := orch.runOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	cycle1, _ := store.SnapshotFindings(context.Background())
	if !containsOpenRule(cycle1, "codex-trust-home-or-broad") {
		t.Fatal("cycle 1: expected open finding for codex-trust-home-or-broad")
	}

	// "Fix" the config — change trust_level to on_request.
	fixed := `
[projects."/home/parallels"]
trust_level = "on_request"
`
	if err := os.WriteFile(codexCfg, []byte(fixed), 0o600); err != nil {
		t.Fatal(err)
	}

	// Cycle 2: rule should no longer fire → orchestrator marks the
	// previous finding resolved.
	if err := orch.runOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	cycle2, _ := store.SnapshotFindings(context.Background())
	for _, f := range cycle2 {
		if f.RuleID == "codex-trust-home-or-broad" {
			if f.Open() {
				t.Errorf("cycle 2: finding still open; resolution detection failed: %+v", f)
			}
		}
	}
}

func TestOrchestratorRecordsScannerStatusForEveryCategory(t *testing.T) {
	store := newTestStore(t)
	orch, err := New(Options{
		Store:      store,
		Roots:      []string{t.TempDir()}, // empty dir → 0 findings, but scanner status still recorded
		HomeDir:    t.TempDir(),
		RunSecrets: ptr(false),
		RunOSPkg:   ptr(false),
		Interval:   time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := orch.runOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	statuses, err := store.SnapshotScannerStatuses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]state.ScannerStatus{}
	for _, s := range statuses {
		got[s.Category] = s
	}

	wantCategories := []string{"ai-agent", "secrets", "deps", "os-pkg"}
	for _, c := range wantCategories {
		s, ok := got[c]
		if !ok {
			t.Errorf("scanner status missing for category %q", c)
			continue
		}
		// secrets/deps/os-pkg should be "unavailable" in this config
		// (trufflehog disabled, dep + ospkg not wired yet). ai-agent
		// should be "ok".
		switch c {
		case "ai-agent":
			if s.Status != "ok" {
				t.Errorf("ai-agent status = %q, want ok", s.Status)
			}
		case "secrets", "deps", "os-pkg":
			if s.Status != "unavailable" {
				t.Errorf("%s status = %q, want unavailable", c, s.Status)
			}
			if s.ErrorText == "" {
				t.Errorf("%s status: error_text should be non-empty so the dashboard banner has content", c)
			}
		}
	}
}

func ruleIDs(findings []state.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.RuleID)
	}
	return out
}

func containsOpenRule(findings []state.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID && f.Open() {
			return true
		}
	}
	return false
}

func ptr[T any](v T) *T { return &v }
