package orchestrator

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/harshmaur/audr/internal/rules/builtin"
	"github.com/harshmaur/audr/internal/watch"
)

// TestTriggerFilter_DropsBurstWhereNoPathMatches feeds the
// orchestrator a watch.Trigger carrying only noisy paths (transcripts,
// log files) and asserts no scan fires. Then it sends one with a
// relevant path and asserts a scan DOES fire.
func TestTriggerFilter_DropsBurstWhereNoPathMatches(t *testing.T) {
	store := newTestStore(t)
	triggers := make(chan watch.Trigger, 4)

	orch, err := New(Options{
		Store:            store,
		Roots:            []string{t.TempDir()},
		HomeDir:          t.TempDir(),
		RunSecrets:       ptr(false),
		RunDeps:          ptr(false),
		RunOSPkg:         ptr(false),
		Interval:         time.Hour,
		ExternalTriggers: triggers,
		// Relevance filter: only ".env" basenames pass. Realistic
		// daemon-side filter uses parse.DetectFormat + lockfile
		// basenames; this is a minimal stand-in.
		RelevantPath: func(p string) bool {
			return strings.HasSuffix(p, ".env")
		},
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

	// Let the initial (always-on) scan land.
	time.Sleep(150 * time.Millisecond)
	baseline := scanCount(t, store)
	if baseline == 0 {
		t.Fatalf("initial scan didn't land; got 0 scans")
	}

	// Send a noisy trigger — no relevant paths. Must NOT scan.
	triggers <- watch.Trigger{
		Time: time.Now(),
		Paths: []string{
			"/home/me/.claude/projects/foo/transcripts/2026-05-16.jsonl",
			"/home/me/.local/state/audr/audr.db-wal",
			"/var/log/syslog",
		},
	}
	time.Sleep(200 * time.Millisecond)
	if got := scanCount(t, store); got != baseline {
		t.Fatalf("noisy trigger fired a scan: baseline=%d got=%d", baseline, got)
	}

	// Send a relevant trigger — at least one path matches. MUST scan.
	triggers <- watch.Trigger{
		Time: time.Now(),
		Paths: []string{
			"/home/me/.claude/projects/foo/transcripts/2026-05-16.jsonl",
			"/home/me/projects/app/.env",
		},
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if scanCount(t, store) > baseline {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := scanCount(t, store); got <= baseline {
		t.Fatalf("relevant trigger didn't fire: baseline=%d got=%d", baseline, got)
	}

	cancel()
	<-runDone
}

// TestTriggerFilter_EmptyPathsAlwaysScans documents the "fail safe"
// rule: a trigger with no Paths (rare; watcher couldn't attribute the
// burst) bypasses the filter and scans. Better to over-run than miss
// a real change.
func TestTriggerFilter_EmptyPathsAlwaysScans(t *testing.T) {
	store := newTestStore(t)
	triggers := make(chan watch.Trigger, 4)

	filterCalls := atomic.Int32{}
	orch, err := New(Options{
		Store:            store,
		Roots:            []string{t.TempDir()},
		HomeDir:          t.TempDir(),
		RunSecrets:       ptr(false),
		RunDeps:          ptr(false),
		RunOSPkg:         ptr(false),
		Interval:         time.Hour,
		ExternalTriggers: triggers,
		RelevantPath: func(p string) bool {
			filterCalls.Add(1)
			return false // would normally reject everything
		},
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
	time.Sleep(150 * time.Millisecond)
	baseline := scanCount(t, store)

	triggers <- watch.Trigger{Time: time.Now(), Paths: nil}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if scanCount(t, store) > baseline {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := scanCount(t, store); got <= baseline {
		t.Fatalf("empty-Paths trigger didn't bypass filter")
	}
	if filterCalls.Load() != 0 {
		t.Fatalf("filter consulted on empty-Paths trigger: calls=%d", filterCalls.Load())
	}

	cancel()
	<-runDone
}

