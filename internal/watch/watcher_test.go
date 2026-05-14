package watch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatcherFiresOnFileChange(t *testing.T) {
	home := t.TempDir()
	// Plant a per-tool config dir so DiscoverScope picks it up. The
	// watcher will inotify-watch this directory.
	must(t, os.MkdirAll(filepath.Join(home, ".claude", "projects", "test"), 0o700))

	w, err := NewWatcher(Options{
		HomeDir:              home,
		QuiescenceWindow:     100 * time.Millisecond, // fast for tests
		SlowMinInterval:      time.Hour,
		SignalReader:         stubReader{}, // → RUN forever
		BackoffSampleInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()

	// Give the watcher a moment to spin up its goroutines.
	time.Sleep(50 * time.Millisecond)

	// Cause a file change inside a watched directory.
	target := filepath.Join(home, ".claude", "projects", "test", "settings.json")
	must(t, os.WriteFile(target, []byte(`{"foo":1}`), 0o600))

	// Expect a trigger within (quiescence + a bit of jitter).
	select {
	case <-w.Triggers():
		// good
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not fire a trigger after file write")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestWatcherPauseDropsTriggers(t *testing.T) {
	home := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(home, ".cursor"), 0o700))

	// Signal reader pinned to "PAUSE" (load=5, on AC).
	r := &fakeReader{}
	r.set(5.5, true, false, true)

	w, err := NewWatcher(Options{
		HomeDir:              home,
		QuiescenceWindow:     50 * time.Millisecond,
		SlowMinInterval:      time.Hour,
		SignalReader:         r,
		BackoffSampleInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx) }()

	// Wait for state machine to converge on PAUSE.
	waitFor(t, time.Second, func() bool { return w.CurrentState() == StatePause })

	// Cause a file change.
	must(t, os.WriteFile(filepath.Join(home, ".cursor", "config.json"), []byte(`{}`), 0o600))

	// In PAUSE, NO trigger should arrive.
	select {
	case <-w.Triggers():
		t.Fatal("trigger fired during PAUSE; backoff gate failed")
	case <-time.After(500 * time.Millisecond):
		// good
	}
}

func TestWatcherInotifyModeReportedForLinux(t *testing.T) {
	// On Linux with a real max_user_watches sysctl reachable, mode
	// should be "full" for an empty scope (zero watches against any
	// budget is trivially full). On other OSes it's "n/a".
	w, err := NewWatcher(Options{
		HomeDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	mode := w.InotifyMode()
	if mode == "" {
		t.Errorf("InotifyMode = empty, want one of full/degraded/n/a")
	}
}

func TestIsExcludedPathMatchesAnySegment(t *testing.T) {
	excludes := map[string]bool{
		"node_modules": true,
		".git":         true,
	}
	cases := []struct {
		path string
		want bool
	}{
		{"/repo/node_modules/lodash/package.json", true},
		{"/repo/.git/HEAD", true},
		{"/repo/src/main.go", false},
		{"/home/user/audr/cmd/audr/main.go", false},
		// substring-only matches don't trip the filter:
		{"/repo/node_modulesXY/foo", false},
	}
	for _, tt := range cases {
		t.Run(tt.path, func(t *testing.T) {
			if got := isExcludedPath(tt.path, excludes); got != tt.want {
				t.Errorf("isExcludedPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
