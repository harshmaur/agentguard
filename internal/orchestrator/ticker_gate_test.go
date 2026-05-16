package orchestrator

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/harshmaur/audr/internal/rules/builtin"
	"github.com/harshmaur/audr/internal/state"
)

// TestTickerGate_SkipTickerWhenSuppressesPeriodicScan drives the
// orchestrator's Run loop with a 10ms ticker and a gate that flips
// open/closed. While the gate is "skip", no new scans should appear;
// once the gate clears, scans resume on the next tick.
//
// Note: the initial scan in Run() is NOT gated — it's the "I just
// started up, populate the dashboard" pulse. The gate only governs
// the periodic ticker.
func TestTickerGate_SkipTickerWhenSuppressesPeriodicScan(t *testing.T) {
	store := newTestStore(t)

	var skip atomic.Bool
	skip.Store(true)

	orch, err := New(Options{
		Store:          store,
		Roots:          []string{t.TempDir()},
		HomeDir:        t.TempDir(),
		RunSecrets:     ptr(false),
		RunDeps:        ptr(false),
		RunOSPkg:       ptr(false),
		Interval:       10 * time.Millisecond,
		SkipTickerWhen: func() bool { return skip.Load() },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = orch.Run(ctx)
	}()

	// Let the initial (ungated) scan complete and become our baseline.
	time.Sleep(200 * time.Millisecond)
	baseline := scanCount(t, store)
	if baseline == 0 {
		t.Fatalf("expected at least the initial scan to land; got 0 rows")
	}

	// Sleep long enough that ungated the 10ms ticker would fire many
	// times. Gate is "skip" — count must NOT grow.
	time.Sleep(200 * time.Millisecond)
	if got := scanCount(t, store); got != baseline {
		t.Fatalf("ticker scans fired while gate was true: baseline=%d, got=%d", baseline, got)
	}

	// Open the gate. Ticker should resume.
	skip.Store(false)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if scanCount(t, store) > baseline {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := scanCount(t, store); got <= baseline {
		t.Fatalf("ticker scans did not resume after gate cleared: baseline=%d, got=%d", baseline, got)
	}

	cancel()
	<-runDone
}

func scanCount(t *testing.T, store *state.Store) int {
	t.Helper()
	scans, err := store.SnapshotScans(context.Background(), 10000)
	if err != nil {
		t.Fatalf("SnapshotScans: %v", err)
	}
	return len(scans)
}
