package policy

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestWatcher_FiresOnFileWrite: writing to the watched policy file
// triggers the callback. The fundamental smoke test.
func TestWatcher_FiresOnFileWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	// Seed an empty file so the watcher can resolve the dir.
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	w, err := NewWatcher(path, func() { calls.Add(1) }, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx) }()

	// Let the watcher subscribe to fsnotify.
	time.Sleep(50 * time.Millisecond)

	// Modify the file.
	if err := os.WriteFile(path, []byte("version: 1\nrules:\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Watcher debounces to 150ms; wait long enough for the callback.
	time.Sleep(400 * time.Millisecond)

	if calls.Load() == 0 {
		t.Errorf("watcher callback never fired; expected at least 1 call")
	}
}

// TestWatcher_DebouncesBursts: multiple writes in quick succession
// produce at most a small number of callbacks (not one per write).
// The atomic-save pattern (write + chmod + rename) triggers ~3
// underlying events; we want one callback for the logical save.
func TestWatcher_DebouncesBursts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("v"), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	w, err := NewWatcher(path, func() { calls.Add(1) }, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)

	// Fire 5 writes in rapid succession.
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(path, []byte("v"+string(rune('a'+i))), 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Settling time.
	time.Sleep(400 * time.Millisecond)

	got := calls.Load()
	if got == 0 {
		t.Errorf("watcher never fired; expected at least 1 callback")
	}
	if got > 3 {
		t.Errorf("watcher fired %d times for 5 rapid writes; want <= 3 (debounced)", got)
	}
}

// TestWatcher_IgnoresUnrelatedFiles: writing to a different file in
// the watched directory does NOT fire the callback. We watch the
// dir, but filter on the policy file's basename.
func TestWatcher_IgnoresUnrelatedFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("v"), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	w, err := NewWatcher(path, func() { calls.Add(1) }, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)

	// Touch a sibling file in the same dir.
	other := filepath.Join(dir, "something-else.txt")
	if err := os.WriteFile(other, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)

	if calls.Load() != 0 {
		t.Errorf("watcher fired for unrelated file; got %d callbacks", calls.Load())
	}
}

// TestWatcher_CreatesDirIfMissing: a fresh install has no
// ~/.audr/policy.yaml AND no ~/.audr/ directory. The watcher must
// create the dir so fsnotify has something to subscribe to.
func TestWatcher_CreatesDirIfMissing(t *testing.T) {
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "fresh-install", ".audr")
	path := filepath.Join(policyDir, "policy.yaml")

	w, err := NewWatcher(path, func() {}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)

	if _, err := os.Stat(policyDir); err != nil {
		t.Errorf("watcher should have created %s; stat: %v", policyDir, err)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Errorf("watcher.Run did not return after ctx-cancel")
	}
}

// TestWatcher_ClosesIdempotent: calling Close() twice is safe.
func TestWatcher_ClosesIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("v"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := NewWatcher(path, func() {}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = w.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)

	if err := w.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestWatcher_NilCallbackRejected: a nil callback returns an error
// at construction. Catches the misuse where a caller forgets to
// wire the callback up.
func TestWatcher_NilCallbackRejected(t *testing.T) {
	_, err := NewWatcher("/tmp/x", nil, nil)
	if err == nil {
		t.Error("NewWatcher should reject nil callback")
	}
}

// TestPathExists: helper smoke test.
func TestPathExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	ok, err := PathExists(path)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("PathExists should be false for missing file")
	}
	if err := os.WriteFile(path, []byte("v"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, err = PathExists(path)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("PathExists should be true after write")
	}
}

// TestWatcher_ParallelFiresStayBounded: stress test under concurrent
// writes from multiple goroutines. Callback count must stay
// reasonable; we should never fire 1-per-event.
func TestWatcher_ParallelFiresStayBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("v"), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	w, err := NewWatcher(path, func() { calls.Add(1) }, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_ = os.WriteFile(path,
					[]byte("v-"+string(rune('a'+id))+string(rune('a'+j))),
					0o600)
				time.Sleep(3 * time.Millisecond)
			}
		}(i)
	}
	wg.Wait()
	time.Sleep(400 * time.Millisecond)

	got := calls.Load()
	if got == 0 {
		t.Errorf("watcher never fired across 80 writes")
	}
	if got > 10 {
		t.Errorf("watcher fired %d times for 80 writes in 8 goroutines; want <= 10 (debounce should coalesce)", got)
	}
}
