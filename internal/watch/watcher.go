package watch

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/harshmaur/audr/internal/scanignore"
)

// Watcher is the daemon's filesystem-change → scan-trigger pump.
// Implements daemon.Subsystem: Run(ctx) blocks until ctx cancels,
// emits scan triggers on Triggers().
//
// Composition:
//
//   fsnotify    →  quiescence gate (5s)  →  backoff gate (RUN/SLOW/PAUSE)  →  Triggers()
//
// fsnotify produces noisy event streams (npm install, git checkout,
// build artifacts); the quiescence gate collapses storms into a
// single "scan now" pulse 5s after the FS settles. The backoff gate
// drops triggers when the system is under load (PAUSE) or throttles
// them when on battery / moderate load (SLOW). What reaches
// Triggers() is what the orchestrator should act on.
type Watcher struct {
	opts Options

	scope    Scope
	notify   *fsnotify.Watcher
	quiesce  *QuiescenceGate
	backoff  *Backoff
	logger   *slog.Logger

	// trigger emits scan-now pulses. Consumers (the orchestrator)
	// read this; buffer of 8 absorbs short bursts without dropping.
	// Each Trigger carries the deduplicated set of paths that fired
	// during the burst so the orchestrator can filter no-op events
	// (Claude transcript churn, log file rotation, etc.) before
	// running a full scan cycle.
	trigger chan Trigger

	// lastForward is the timestamp of the most recent trigger emitted
	// downstream. Used by the SLOW state to throttle: minimum 5
	// minutes between forwarded triggers.
	lastForward atomic.Int64 // unix nano

	// remoteRoots is the set of scope paths whose filesystem returned
	// non-FSLocal at startup. We don't add fsnotify watches there
	// (NFS, SMB, FUSE: events don't deliver reliably or at all);
	// instead they're polled-only. Surfaced for status reporting.
	remoteRoots []string

	// inotifyMode reports what happened at startup on Linux:
	//   "full"     — all scope paths got inotify watches
	//   "degraded" — some paths skipped because inotify budget was
	//                tight; user should raise fs.inotify.max_user_watches
	//   "n/a"      — non-Linux
	inotifyMode string

	// stopOnce protects Close from double-running.
	stopOnce sync.Once
	closed   atomic.Bool
}

// Options configures a Watcher.
type Options struct {
	// HomeDir scopes the watch. Empty defaults to os.UserHomeDir().
	HomeDir string

	// QuiescenceWindow is how long the gate waits after the last
	// event before emitting a trigger. Default 5 seconds (per
	// /plan-eng-review).
	QuiescenceWindow time.Duration

	// SlowMinInterval is the minimum time between forwarded triggers
	// in StateSlow. Default 5 minutes. RUN is unthrottled; PAUSE
	// drops everything.
	SlowMinInterval time.Duration

	// SignalReader supplies load avg + battery for the backoff state
	// machine. Defaults to DefaultSignalReader(); tests pass a fake.
	SignalReader SignalReader

	// RemoteFSDetector classifies a path's filesystem. Defaults to
	// DefaultRemoteFSDetector().
	RemoteFSDetector RemoteFSDetector

	// LimitReader reads /proc/sys/fs/inotify/max_user_watches on
	// Linux. Defaults to DefaultLimitReader().
	LimitReader LimitReader

	// BackoffSampleInterval is how often the backoff polls signals.
	// Default 5 seconds.
	BackoffSampleInterval time.Duration

	// Logger receives operational events. nil → discard.
	Logger *slog.Logger
}

// NewWatcher constructs but does not start the watcher. Discovers
// scope, classifies each path's filesystem, and seeds fsnotify (on
// local paths) or records the path for poll-only mode (on remote
// paths). Returns the watcher ready to Run().
func NewWatcher(opts Options) (*Watcher, error) {
	if opts.HomeDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("watch: resolve home: %w", err)
		}
		opts.HomeDir = home
	}
	if opts.QuiescenceWindow <= 0 {
		opts.QuiescenceWindow = 5 * time.Second
	}
	if opts.SlowMinInterval <= 0 {
		opts.SlowMinInterval = 5 * time.Minute
	}
	if opts.SignalReader == nil {
		opts.SignalReader = DefaultSignalReader()
	}
	if opts.RemoteFSDetector == nil {
		opts.RemoteFSDetector = DefaultRemoteFSDetector()
	}
	if opts.LimitReader == nil {
		opts.LimitReader = DefaultLimitReader()
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
	}

	scope, repos, err := DiscoverScope(opts.HomeDir)
	if err != nil {
		logger.Warn("scope discovery partial", "err", err)
	}
	logger.Info("scope discovered", "tight_paths", len(scope.TightPaths), "git_repos", repos)

	w := &Watcher{
		opts:    opts,
		scope:   scope,
		quiesce: NewQuiescenceGate(opts.QuiescenceWindow),
		backoff: NewBackoff(opts.SignalReader, opts.BackoffSampleInterval),
		logger:  logger,
		trigger: make(chan Trigger, 8),
	}

	// Construct the fsnotify watcher even before scope filtering — a
	// failed New() means we can't watch anything regardless of the
	// scope's content.
	nw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("watch: fsnotify.NewWatcher: %w", err)
	}
	w.notify = nw

	// inotify-limit pre-check on Linux. If the configured max is
	// tight (default 8192 on many distros), refuse to add more
	// watches than ~80% of the budget. Phase 3 ships the check; full
	// dynamic demotion of subtrees is v1.1.
	maxWatches := opts.LimitReader.ReadMaxUserWatches()
	budget := 0
	if maxWatches > 0 {
		budget = maxWatches * 8 / 10 // 80%
	}

	added := 0
	for _, root := range scope.TightPaths {
		kind, err := opts.RemoteFSDetector.Detect(root)
		if err != nil {
			logger.Warn("remote-fs detect failed; treating as local", "path", root, "err", err)
			kind = FSLocal
		}
		if kind.IsRemote() {
			w.remoteRoots = append(w.remoteRoots, root)
			logger.Info("remote filesystem detected; poll-only fallback", "path", root, "kind", string(kind))
			continue
		}

		// fsnotify on Linux + Windows is non-recursive: walk every
		// subdirectory and add a watch per dir. macOS FSEvents IS
		// recursive (a single AddWatch on the root suffices), but
		// fsnotify abstracts that for us — AddWatch on each subdir
		// works on macOS too, just redundantly.
		paths, walkErr := enumerateWatchableDirs(root)
		if walkErr != nil {
			logger.Warn("enumerate watch dirs", "root", root, "err", walkErr)
			// Continue with whatever we got.
		}
		for _, p := range paths {
			if budget > 0 && added >= budget {
				w.inotifyMode = "degraded"
				logger.Warn("inotify budget reached; remaining paths will be poll-only", "max_user_watches", maxWatches, "added", added, "skipped", root)
				break
			}
			if err := w.notify.Add(p); err != nil {
				// ENOSPC = budget exhausted by another caller; we
				// give up gracefully + mark degraded mode.
				if isENOSPC(err) {
					w.inotifyMode = "degraded"
					logger.Warn("inotify ENOSPC; remaining paths will be poll-only", "added", added, "skipped", p, "err", err)
					break
				}
				logger.Warn("fsnotify add failed", "path", p, "err", err)
				continue
			}
			added++
		}
	}
	if w.inotifyMode == "" {
		if maxWatches > 0 {
			w.inotifyMode = "full"
		} else {
			w.inotifyMode = "n/a"
		}
	}
	logger.Info("watcher ready",
		"watches", added,
		"inotify_mode", w.inotifyMode,
		"max_user_watches", maxWatches,
		"remote_roots", len(w.remoteRoots),
	)

	return w, nil
}

// Name implements daemon.Subsystem.
func (w *Watcher) Name() string { return "watch" }

// Triggers returns the channel the orchestrator reads. Each value is
// the timestamp of the underlying quiescence pulse. The receiver
// runs one scan per trigger.
func (w *Watcher) Triggers() <-chan Trigger { return w.trigger }

// RemoteRoots returns scope paths classified as remote at startup.
// Used by the daemon log + future dashboard banner.
func (w *Watcher) RemoteRoots() []string {
	out := make([]string, len(w.remoteRoots))
	copy(out, w.remoteRoots)
	return out
}

// InotifyMode returns "full" / "degraded" / "n/a" depending on whether
// all scope paths got watches.
func (w *Watcher) InotifyMode() string { return w.inotifyMode }

// CurrentState returns the backoff state cached by the last sample
// tick. Useful for the dashboard's daemon-state indicator.
func (w *Watcher) CurrentState() BackoffState { return w.backoff.Current() }

// Run implements daemon.Subsystem. Spawns three goroutines:
//   - the backoff sampler
//   - the fsnotify event drain → quiescence bumper
//   - the quiescence-trigger → backoff-gate → downstream-trigger forwarder
// Blocks until ctx cancels.
func (w *Watcher) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	// 1. Backoff sampler.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = w.backoff.Run(ctx)
	}()

	// 2. fsnotify event drain.
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.eventLoop(ctx)
	}()

	// 3. Trigger forwarder.
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.forwardLoop(ctx)
	}()

	wg.Wait()
	return nil
}

// Close implements daemon.Subsystem. Idempotent.
func (w *Watcher) Close() error {
	var err error
	w.stopOnce.Do(func() {
		w.closed.Store(true)
		if w.notify != nil {
			err = w.notify.Close()
		}
		_ = w.quiesce.Close()
	})
	return err
}

// eventLoop reads fsnotify events, filters via scanignore, and bumps
// the quiescence gate. Exits on ctx cancel.
func (w *Watcher) eventLoop(ctx context.Context) {
	excludes := scanignoreSegmentsSet()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.notify.Events:
			if !ok {
				return
			}
			if isExcludedPath(ev.Name, excludes) {
				continue
			}
			w.quiesce.Bump(ev.Name)
		case err, ok := <-w.notify.Errors:
			if !ok {
				return
			}
			w.logger.Warn("fsnotify error", "err", err)
		}
	}
}

// forwardLoop consumes quiescence pulses, consults the backoff
// state, and forwards downstream to Triggers() per the throttling
// rules (RUN: forward; SLOW: forward iff > SlowMinInterval since
// last; PAUSE: drop). Exits on ctx cancel.
func (w *Watcher) forwardLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case t, ok := <-w.quiesce.Triggers():
			if !ok {
				return
			}
			w.maybeForward(t)
		}
	}
}

func (w *Watcher) maybeForward(t Trigger) {
	state := w.backoff.Current()
	switch state {
	case StatePause:
		w.logger.Debug("trigger dropped: PAUSE", "ts", t.Time, "paths", len(t.Paths))
		return
	case StateSlow:
		last := time.Unix(0, w.lastForward.Load())
		if time.Since(last) < w.opts.SlowMinInterval {
			w.logger.Debug("trigger throttled: SLOW", "since_last", time.Since(last))
			return
		}
	}
	select {
	case w.trigger <- t:
		w.lastForward.Store(time.Now().UnixNano())
	default:
		// Downstream is slow. Don't block; orchestrator's ticker is
		// the fallback safety net.
		w.logger.Warn("trigger downstream full; dropping")
	}
}

// enumerateWatchableDirs returns root + every subdirectory (recursive)
// for fsnotify.AddWatch. Skips scanignore-listed directories to bound
// the watch count and avoid wasting inotify slots on caches.
//
// If root is a file (e.g., ~/.bashrc), returns just root.
func enumerateWatchableDirs(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{root}, nil
	}
	excludes := scanignoreSegmentsSet()
	var out []string
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if excludes[base] {
			return fs.SkipDir
		}
		out = append(out, path)
		return nil
	})
	return out, walkErr
}

// scanignoreSegmentsSet returns a set of single-segment names that
// match scanignore.Defaults() entries. Multi-segment entries (e.g.,
// "Library/Caches") aren't checked here — they only matter at the
// $HOME shallow-watch boundary, which we handle via the per-tool
// path allowlist in DiscoverScope.
func scanignoreSegmentsSet() map[string]bool {
	out := map[string]bool{}
	for _, seg := range scanignore.Defaults() {
		// Take only the first path component; multi-segment entries
		// won't match a basename anyway.
		if i := indexByte(seg, '/'); i >= 0 {
			seg = seg[:i]
		}
		out[seg] = true
	}
	return out
}

func isExcludedPath(p string, excludes map[string]bool) bool {
	// Match if ANY segment of p is in excludes. Cheap split walk.
	for _, seg := range splitPath(p) {
		if excludes[seg] {
			return true
		}
	}
	return false
}

func splitPath(p string) []string {
	out := make([]string, 0, 8)
	start := 0
	for i := 0; i < len(p); i++ {
		if p[i] == filepath.Separator {
			if i > start {
				out = append(out, p[start:i])
			}
			start = i + 1
		}
	}
	if start < len(p) {
		out = append(out, p[start:])
	}
	return out
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// isENOSPC reports whether err is the "no space left on device" the
// kernel returns when a per-user inotify quota is exhausted.
func isENOSPC(err error) bool {
	// We unwrap manually since syscall.ENOSPC isn't always
	// recognized by errors.Is across cross-OS builds.
	for err != nil {
		s := err.Error()
		if containsAny(s, "no space left on device", "ENOSPC") {
			return true
		}
		// Unwrap one level if possible.
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if len(n) == 0 {
			continue
		}
		for i := 0; i+len(n) <= len(s); i++ {
			if s[i:i+len(n)] == n {
				return true
			}
		}
	}
	return false
}

// discardWriter is the no-op io.Writer used as a logger sink when the
// caller doesn't supply one.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// staticErrors so the package can be made to fail Tests cleanly.
var (
	errScopeEmpty = errors.New("watch: scope is empty; nothing to watch")
)
