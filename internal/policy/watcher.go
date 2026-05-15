package policy

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watcher emits change events when `~/.audr/policy.yaml` is modified
// on disk. Used by the daemon to push a SSE "policy-changed" event
// to the dashboard editor so the user sees their `$EDITOR` hand-edit
// reflected without manually clicking reload.
//
// Implementation notes:
//
//   - We watch the parent directory, not the file itself. Watching a
//     specific file's inode breaks under atomic-rename saves (the
//     temp file becomes the new inode); the directory-watch sees
//     the rename event and we re-stat to confirm the target file
//     was touched.
//
//   - Events are debounced: tools that touch the file in quick
//     succession (atomic save = WRITE + CHMOD + RENAME) shouldn't
//     fire three events to the dashboard. We coalesce within a
//     150ms window per the same rationale as the v0.4.x SSE
//     coalescing in dashboard.js.
//
//   - Errors from fsnotify are logged but never propagated as fatal.
//     The watcher is a UI nicety; losing it doesn't break the
//     per-scan-cycle reload path that's the primary hot-reload
//     mechanism.
type Watcher struct {
	logger *slog.Logger
	path   string
	cb     func()

	mu sync.Mutex
	w  *fsnotify.Watcher

	debounceMu sync.Mutex
	debounceAt time.Time
}

// NewWatcher constructs a watcher for the given policy path. The
// callback `onChange` is invoked at most once per ~150ms even when
// the underlying filesystem emits multiple events for one logical
// save. Pass a logger; nil → slog.Default().
func NewWatcher(path string, onChange func(), logger *slog.Logger) (*Watcher, error) {
	if onChange == nil {
		return nil, errors.New("watcher: onChange callback is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Watcher{
		logger: logger,
		path:   path,
		cb:     onChange,
	}, nil
}

// Run blocks until ctx cancels, watching the parent directory of the
// policy file for changes. Implements the policy-watcher contract:
// emit one debounced callback per logical save. The daemon
// orchestrator calls this in a goroutine; ctx-cancel terminates
// cleanly.
func (w *Watcher) Run(ctx context.Context) error {
	nw, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.w = nw
	w.mu.Unlock()
	defer w.Close()

	dir := filepath.Dir(w.path)
	// The directory might not exist yet (fresh install, no
	// ~/.audr/policy.yaml). Create it so we have something to watch.
	// Mode 0700 mirrors the file's 0600 — owner-only access.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		w.logger.Warn("policy watcher: create dir", "path", dir, "err", err)
		return err
	}
	if err := w.w.Add(dir); err != nil {
		w.logger.Warn("policy watcher: add dir", "path", dir, "err", err)
		return err
	}
	// Also watch the file directly when it exists.
	//
	// fsnotify backends differ on what a directory-watch sees:
	//   - Linux (inotify): firing on file-content changes when
	//     watching the parent dir is the default. Adding the file
	//     too is redundant but harmless.
	//   - macOS (kqueue): a directory-watch fires for directory
	//     mutations (entries added/removed/renamed) but NOT for
	//     content changes to existing files. We have to add the
	//     file itself to see writes.
	//   - Windows (ReadDirectoryChangesW): directory-watch sees both
	//     directory mutations and file content changes; adding the
	//     file is harmless.
	//
	// The dir-watch alone catches atomic-rename saves (write to
	// .tmp + rename over) because the rename event lands at the
	// directory level. The file-watch catches in-place writes —
	// what `$EDITOR` does when configured to edit in place. Both
	// matter for the policy hot-reload contract on every OS.
	w.watchFileIfExists()

	// Capture the channels under the lock once; subsequent receives
	// don't need to re-fetch w.w because the underlying channel
	// stays valid until fsnotify.Watcher.Close() closes it, which
	// only happens via our Close() (also locked).
	w.mu.Lock()
	events := w.w.Events
	errors := w.w.Errors
	w.mu.Unlock()

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-events:
			if !ok {
				return nil
			}
			if !w.relevant(ev) {
				continue
			}
			// macOS kqueue note: when an atomic-rename save replaces
			// the file (write .tmp + rename over original), the
			// existing inode-level watch becomes stale. Re-add the
			// file watch after every relevant event so we keep
			// receiving content-change notifications on the new
			// inode.
			if ev.Op&(fsnotify.Create|fsnotify.Rename|fsnotify.Remove) != 0 {
				w.watchFileIfExists()
			}
			w.debouncedFire()
		case err, ok := <-errors:
			if !ok {
				return nil
			}
			w.logger.Warn("policy watcher: fsnotify error", "err", err)
		}
	}
}

// Close releases the underlying fsnotify watcher. Idempotent.
func (w *Watcher) Close() error {
	w.mu.Lock()
	cur := w.w
	w.w = nil
	w.mu.Unlock()
	if cur == nil {
		return nil
	}
	return cur.Close()
}

// relevant filters out events that don't touch the policy file.
// fsnotify reports every event in the watched directory; we only
// care about ones whose target is policy.yaml itself (any operation:
// write, create, remove, rename).
func (w *Watcher) relevant(ev fsnotify.Event) bool {
	return filepath.Clean(ev.Name) == filepath.Clean(w.path)
}

// watchFileIfExists registers a watch on the policy file when it
// exists on disk. Idempotent — fsnotify dedupes path adds internally.
// Failures are logged but never fatal: the directory-watch keeps
// working as a fallback (catches atomic-rename saves on every OS
// and content changes on Linux).
//
// Critical for macOS where the directory-watch alone misses
// in-place file content changes (kqueue dir events fire only for
// directory mutations).
func (w *Watcher) watchFileIfExists() {
	if _, err := os.Stat(w.path); err != nil {
		return // file doesn't exist yet; nothing to add
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.w == nil {
		return
	}
	if err := w.w.Add(w.path); err != nil {
		w.logger.Debug("policy watcher: add file watch",
			"path", w.path, "err", err)
	}
}

// debouncedFire schedules a callback fire if the last one was more
// than 150ms ago, or extends the debounce window. The fire happens
// in a goroutine so the fsnotify-event loop never blocks on a slow
// callback.
func (w *Watcher) debouncedFire() {
	w.debounceMu.Lock()
	defer w.debounceMu.Unlock()

	now := time.Now()
	if !w.debounceAt.IsZero() && now.Sub(w.debounceAt) < 150*time.Millisecond {
		w.debounceAt = now
		return
	}
	w.debounceAt = now
	go func() {
		time.Sleep(150 * time.Millisecond)
		w.debounceMu.Lock()
		fireTime := w.debounceAt
		w.debounceMu.Unlock()
		// If another event extended the window past our sleep, skip;
		// the next goroutine will fire after its own settling.
		if time.Since(fireTime) < 100*time.Millisecond {
			return
		}
		w.cb()
	}()
}

// PathExists is a small helper the daemon uses at startup to decide
// whether to seed an empty policy.yaml before the watcher boots.
// fsnotify is unhappy watching a directory that doesn't exist; the
// caller's create-if-missing path keeps the contract simple.
func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}
