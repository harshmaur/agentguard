package orchestrator

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/harshmaur/audr/internal/depscan"
	_ "github.com/harshmaur/audr/internal/rules/builtin"
)

// countingRunner is a depscan.CommandRunner stub for orchestrator
// tests. It records every Run call and returns a canned OSV-Scanner
// JSON document. The cache test uses invocation count to prove that a
// second runOnce cycle short-circuits the sidecar call when no
// lockfiles changed.
type countingRunner struct {
	mu    sync.Mutex
	calls []countingCall

	// payloadFor returns the bytes to send back for a given set of
	// project root args. nil → empty results.
	payloadFor func(args []string) []byte
}

type countingCall struct {
	name string
	args []string
}

func (c *countingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, countingCall{name: name, args: append([]string(nil), args...)})
	if c.payloadFor != nil {
		return c.payloadFor(args), nil
	}
	return []byte(`{"results":[]}`), nil
}

func (c *countingRunner) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.calls)
}

// osvJSONFor builds a minimal but valid OSV-Scanner JSON report for
// each project root. The manifest path inside the report references
// rootDir/package.json so the orchestrator's findings-by-root grouping
// can attribute findings back to their owning cache scope.
func osvJSONFor(projectRoots []string) []byte {
	var parts []string
	for _, root := range projectRoots {
		parts = append(parts, fmt.Sprintf(`{
			"source": {"path": %q},
			"packages": [{
				"package": {"name": "lodash", "version": "4.17.0", "ecosystem": "npm"},
				"version": "4.17.0",
				"vulnerabilities": [{
					"id": "GHSA-test-1",
					"summary": "Prototype pollution",
					"database_specific": {"severity": "HIGH"},
					"affected": [{"ranges": [{"events": [{"introduced": "0", "fixed": "4.17.21"}]}]}]
				}]
			}]
		}`, filepath.Join(root, "package.json")))
	}
	body := `{"results":[` + strings.Join(parts, ",") + `]}`
	return []byte(body)
}

// runnerCalledWith reports whether any recorded call's positional
// arguments contained the given project root. osv-scanner is invoked
// with `scan source --format json --recursive --allow-no-lockfiles
// --verbosity error <roots...>`, so the root appears verbatim in the
// args slice.
func (c *countingRunner) calledWith(root string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, call := range c.calls {
		for _, a := range call.args {
			if a == root {
				return true
			}
		}
	}
	return false
}

func TestDepscanCache_SecondCycleSkipsRunnerWhenNothingChanged(t *testing.T) {
	if _, err := os.Stat("/tmp"); err != nil {
		t.Skip("filesystem temp not available")
	}

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{"name":"x","version":"0.0.1"}`)

	store := newTestStore(t)
	runner := &countingRunner{
		payloadFor: func(args []string) []byte {
			// Strip leading osv-scanner flag args; project-root args
			// are the trailing entries with no leading "-".
			var roots []string
			for _, a := range args {
				if strings.HasPrefix(a, "-") || a == "scan" || a == "source" || a == "json" || a == "error" {
					continue
				}
				roots = append(roots, a)
			}
			return osvJSONFor(roots)
		},
	}

	orch, err := New(Options{
		Store:      store,
		Roots:      []string{root},
		HomeDir:    root,
		RunSecrets: ptr(false),
		RunOSPkg:   ptr(false),
		RunDeps:    ptr(true),
		DepsRunner: runner,
		Interval:   time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := orch.runOnce(context.Background()); err != nil {
		t.Fatalf("runOnce #1: %v", err)
	}
	if got := runner.callCount(); got != 1 {
		t.Fatalf("after first cycle: runner.callCount = %d, want 1", got)
	}
	if !runner.calledWith(root) {
		t.Fatalf("first cycle did not invoke osv-scanner against %q (calls=%v)", root, runner.calls)
	}

	// Second cycle without modifying any lockfile — the cache must
	// short-circuit osv-scanner entirely. The cached findings must
	// still feed `seen` so resolution detection doesn't close them.
	if err := orch.runOnce(context.Background()); err != nil {
		t.Fatalf("runOnce #2: %v", err)
	}
	if got := runner.callCount(); got != 1 {
		t.Fatalf("after second cycle (cached): runner.callCount = %d, want 1 (cache MISS — sidecar reran)", got)
	}

	// Findings must persist across both cycles. If the cached payload
	// failed to feed `seen`, the resolution sweep would have closed the
	// row and snapshot would show resolved_at non-null.
	findings, err := store.SnapshotFindings(context.Background())
	if err != nil {
		t.Fatalf("SnapshotFindings: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("no findings present after two cycles — cached findings were dropped")
	}
	var saw bool
	for _, f := range findings {
		if f.Category == "deps" && f.ResolvedAt == nil {
			saw = true
			break
		}
	}
	if !saw {
		t.Fatalf("deps finding either missing or got resolved across cached cycle; findings=%+v", findings)
	}
}

func TestDepscanCache_LockfileEditInvalidatesCache(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "package.json")
	mustWrite(t, manifest, `{"name":"x","version":"0.0.1"}`)

	store := newTestStore(t)
	runner := &countingRunner{
		payloadFor: func(args []string) []byte {
			return osvJSONFor([]string{root})
		},
	}

	orch, err := New(Options{
		Store:      store,
		Roots:      []string{root},
		HomeDir:    root,
		RunSecrets: ptr(false),
		RunOSPkg:   ptr(false),
		RunDeps:    ptr(true),
		DepsRunner: runner,
		Interval:   time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := orch.runOnce(context.Background()); err != nil {
		t.Fatalf("runOnce #1: %v", err)
	}
	first := runner.callCount()
	if first != 1 {
		t.Fatalf("first cycle: callCount = %d, want 1", first)
	}

	// Modify the lockfile so its (mtime, size) changes. Need a wait to
	// defeat filesystems with second-granularity mtime; otherwise the
	// fingerprint can match by coincidence and the cache stays valid.
	time.Sleep(1100 * time.Millisecond)
	mustWrite(t, manifest, `{"name":"x","version":"0.0.2","added":true}`)

	if err := orch.runOnce(context.Background()); err != nil {
		t.Fatalf("runOnce #2: %v", err)
	}
	second := runner.callCount()
	if second != 2 {
		t.Fatalf("after lockfile edit: callCount = %d, want 2 (cache should invalidate)", second)
	}
}

// mustWrite is a test-only helper that bubbles up errors fatally. Mirrors
// orchestrator_test.go's local style (no errcheck noise).
func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// sanity check that the OSV JSON helper produces something the parser
// accepts — protects the integration test from a silent-parse regression
// in the canned payload generator.
func TestDepscanCache_CannedJSONParses(t *testing.T) {
	root := t.TempDir()
	out, err := depscan.ParseOSVScannerJSON(osvJSONFor([]string{root}))
	if err != nil {
		t.Fatalf("ParseOSVScannerJSON: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("canned JSON parsed to zero findings — fixture is wrong")
	}
}

