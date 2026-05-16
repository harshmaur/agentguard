package orchestrator

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harshmaur/audr/internal/ospkg"
	_ "github.com/harshmaur/audr/internal/rules/builtin"
)

func TestOSPkgCache_SecondCycleReusesCachedPayload(t *testing.T) {
	store := newTestStore(t)

	var calls int32
	scanner := func(_ context.Context) ([]ospkg.Vulnerability, error) {
		atomic.AddInt32(&calls, 1)
		return []ospkg.Vulnerability{
			{
				Package:    ospkg.Package{Manager: ospkg.ManagerDpkg, Name: "openssl", Version: "1.1.1f-1ubuntu2.16"},
				AdvisoryID: "CVE-2022-0778",
				Severity:   "high",
				Summary:    "BN_mod_sqrt infinite loop",
				FixedIn:    "1.1.1f-1ubuntu2.17",
			},
		}, nil
	}
	fp := "dpkg|status:1000:200"
	fingerprinter := func() (string, error) { return fp, nil }

	orch, err := New(Options{
		Store:            store,
		Roots:            []string{t.TempDir()},
		HomeDir:          t.TempDir(),
		RunSecrets:       ptr(false),
		RunDeps:          ptr(false),
		RunOSPkg:         ptr(true),
		OSPkgScanner:     scanner,
		OSPkgFingerprint: fingerprinter,
		Interval:         time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := orch.runOnce(context.Background()); err != nil {
		t.Fatalf("runOnce #1: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("first cycle: scanner calls = %d, want 1", got)
	}

	// Second cycle without changing fingerprint — scanner must NOT
	// run; cache feeds the findings instead.
	if err := orch.runOnce(context.Background()); err != nil {
		t.Fatalf("runOnce #2: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("after second cycle (cached): scanner calls = %d, want 1 (cache MISS)", got)
	}

	// Findings remain open across both cycles — cached payload fed
	// `seen` so resolution didn't close them.
	findings, err := store.SnapshotFindings(context.Background())
	if err != nil {
		t.Fatalf("SnapshotFindings: %v", err)
	}
	var sawOpen bool
	for _, f := range findings {
		if f.Category == "os-pkg" && f.ResolvedAt == nil {
			sawOpen = true
			break
		}
	}
	if !sawOpen {
		t.Fatalf("os-pkg finding missing or got resolved across cached cycle; findings=%+v", findings)
	}
}

func TestOSPkgCache_FingerprintChangeReinvokesScanner(t *testing.T) {
	store := newTestStore(t)

	var calls int32
	scanner := func(_ context.Context) ([]ospkg.Vulnerability, error) {
		atomic.AddInt32(&calls, 1)
		return nil, nil
	}
	var currentFP atomic.Value
	currentFP.Store("dpkg|status:1000:200")
	fingerprinter := func() (string, error) { return currentFP.Load().(string), nil }

	orch, err := New(Options{
		Store:            store,
		Roots:            []string{t.TempDir()},
		HomeDir:          t.TempDir(),
		RunSecrets:       ptr(false),
		RunDeps:          ptr(false),
		RunOSPkg:         ptr(true),
		OSPkgScanner:     scanner,
		OSPkgFingerprint: fingerprinter,
		Interval:         time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := orch.runOnce(context.Background()); err != nil {
		t.Fatalf("runOnce #1: %v", err)
	}
	// Bump the fingerprint — simulates an apt install having shifted
	// /var/lib/dpkg/status's (mtime, size). The next cycle should
	// re-invoke the scanner because the cache row is now stale.
	currentFP.Store("dpkg|status:2000:300")
	if err := orch.runOnce(context.Background()); err != nil {
		t.Fatalf("runOnce #2: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("after fingerprint change: scanner calls = %d, want 2 (cache should invalidate)", got)
	}
}

func TestOSPkgCache_EmptyFingerprintSkipsCacheAlwaysRuns(t *testing.T) {
	store := newTestStore(t)
	var calls int32
	scanner := func(_ context.Context) ([]ospkg.Vulnerability, error) {
		atomic.AddInt32(&calls, 1)
		return nil, nil
	}
	fingerprinter := func() (string, error) { return "", nil }

	orch, err := New(Options{
		Store:            store,
		Roots:            []string{t.TempDir()},
		HomeDir:          t.TempDir(),
		RunSecrets:       ptr(false),
		RunDeps:          ptr(false),
		RunOSPkg:         ptr(true),
		OSPkgScanner:     scanner,
		OSPkgFingerprint: fingerprinter,
		Interval:         time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := orch.runOnce(context.Background()); err != nil {
			t.Fatalf("runOnce #%d: %v", i+1, err)
		}
	}
	// Empty fingerprint means "caching disabled" (unsupported
	// platform or stat failed) — the scanner must run every cycle so
	// we don't silently drop os-pkg coverage.
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("empty-fingerprint mode: scanner calls = %d, want 3 (cache should be bypassed)", got)
	}
}
