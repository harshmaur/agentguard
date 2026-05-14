// Package notify emits OS-native toast notifications for new
// CRITICAL findings discovered by the audr daemon, with batching so
// a first-run scan against a "compromised machine" doesn't bombard
// the user with thousands of toasts.
//
// Design points (from /plan-design-review D3 + user feedback on v0.4.0):
//
//  1. Only NEW CRITICAL findings produce toasts. High / Medium / Low
//     stay in the dashboard; only CRITICAL is loud enough to interrupt.
//
//  2. Per-fingerprint 24h cooldown: a CRITICAL re-detected on every
//     scan doesn't re-fire its toast every cycle.
//
//  3. Rolling 5-minute window with a hard cap of 3 toasts. Anything
//     above the cap is suppressed and counted. When the scan
//     completes, a single aggregate toast says "audr · N more
//     critical findings since last alert" — so a 500-CVE first scan
//     produces 3 individual toasts (the loudest ones) + 1 aggregate,
//     not 500.
//
//  4. First-scan special case: the very first scan after `audr
//     daemon install` (when no scan has completed yet) suppresses
//     all individual toasts. The scan-completed aggregate then says
//     "audr first scan · X critical, Y high · audr open".
//
//  5. `audr daemon notify --off` writes a config flag the notifier
//     reads on every event; the notifier doesn't restart when
//     toggled — it just re-reads the config.
//
//  6. When the OS denies notification permission (macOS Focus, Linux
//     missing notify-send, etc.), the notifier writes
//     ${state_dir}/pending-notify.json. `audr open` reads this on
//     startup and shows a dashboard banner so the user knows toasts
//     were dropped.
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gen2brain/beeep"

	"github.com/harshmaur/audr/internal/state"
)

// Toaster is the interface the notifier uses to actually display a
// toast. Real production uses beeepToaster which calls
// gen2brain/beeep; tests inject a fake that records calls without
// touching the OS.
type Toaster interface {
	Toast(title, body string) error
}

// Options configures a Notifier. Sensible defaults are provided by
// New(); callers usually only set Logger + StateDir + Store.
type Options struct {
	// Store is the audr state store. Required. Notifier subscribes
	// to its event bus and reads the most-recent completed-scan
	// count to decide whether this is "the first scan."
	Store *state.Store

	// StateDir is the daemon's state directory (typically
	// daemon.Paths.State). Notifier writes notify.config.json and
	// pending-notify.json here.
	StateDir string

	// Logger receives notifier-level diagnostics. Defaults to
	// slog.Default().
	Logger *slog.Logger

	// Toaster overrides the OS-toast implementation. nil → beeep.
	Toaster Toaster

	// CooldownPerFingerprint is how long a given fingerprint stays
	// silent after a toast has fired for it. Default 24h.
	CooldownPerFingerprint time.Duration

	// RateWindow is the rolling window for the toast-rate cap.
	// Default 5 minutes.
	RateWindow time.Duration

	// RateWindowCap is the max toasts per RateWindow. Anything past
	// this is suppressed and counted toward the scan-completed
	// aggregate. Default 3.
	RateWindowCap int

	// Now overrides the clock for tests. Default time.Now.
	Now func() time.Time
}

// Notifier implements daemon.Subsystem. Subscribes to the store's
// event bus and produces toasts according to the policy in the
// package doc.
type Notifier struct {
	opts Options

	mu                sync.Mutex
	perFingerprintAt  map[string]time.Time
	windowStart       time.Time
	windowCount       int
	suppressedSince   int
	firstScanDone     bool
	configCache       Config
	configCacheLoaded bool
}

// Config is the user-controllable notification config persisted at
// ${state_dir}/notify.config.json. Currently just an enable toggle;
// future fields (severity threshold, do-not-disturb hours) land here
// without changing the type signature.
type Config struct {
	Enabled bool `json:"enabled"`
}

// DefaultConfig returns the config a fresh installation starts with:
// notifications enabled. Users can flip via `audr daemon notify --off`.
func DefaultConfig() Config { return Config{Enabled: true} }

// PendingNotification is one row of the pending-notify.json fallback
// file. Written when a toast call returns an error so `audr open`
// can surface the dropped ones via dashboard banner.
type PendingNotification struct {
	Fingerprint string    `json:"fingerprint"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	At          time.Time `json:"at"`
	Error       string    `json:"error"`
}

// New constructs a Notifier with defaults filled in. Returns an
// error only when the required fields are missing.
func New(opts Options) (*Notifier, error) {
	if opts.Store == nil {
		return nil, errors.New("notify: Store is required")
	}
	if opts.StateDir == "" {
		return nil, errors.New("notify: StateDir is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Toaster == nil {
		opts.Toaster = beeepToaster{}
	}
	if opts.CooldownPerFingerprint == 0 {
		opts.CooldownPerFingerprint = 24 * time.Hour
	}
	if opts.RateWindow == 0 {
		opts.RateWindow = 5 * time.Minute
	}
	if opts.RateWindowCap == 0 {
		opts.RateWindowCap = 3
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Notifier{
		opts:             opts,
		perFingerprintAt: map[string]time.Time{},
	}, nil
}

// Name implements daemon.Subsystem.
func (n *Notifier) Name() string { return "notify" }

// Run implements daemon.Subsystem. Subscribes to the store's event
// bus and dispatches events to handleEvent until ctx cancels.
// Returns nil on graceful shutdown.
func (n *Notifier) Run(ctx context.Context) error {
	events, unsub := n.opts.Store.Subscribe()
	defer unsub()
	// Hydrate firstScanDone from the store: if there's already a
	// completed scan when we start, we're past the first-run
	// suppression window.
	if scans, err := n.opts.Store.SnapshotScans(ctx, 5); err == nil {
		for _, s := range scans {
			if s.Status == "completed" {
				n.firstScanDone = true
				break
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case e, ok := <-events:
			if !ok {
				return nil
			}
			n.handleEvent(e)
		}
	}
}

// Close implements daemon.Subsystem.
func (n *Notifier) Close() error { return nil }

// handleEvent routes a store event through the policy: only
// finding-opened with severity=critical and scan-completed are
// relevant; everything else is dropped silently.
func (n *Notifier) handleEvent(e state.Event) {
	switch e.Kind {
	case state.EventFindingOpened:
		f, ok := e.Payload.(state.Finding)
		if !ok {
			return
		}
		if f.Severity != "critical" {
			return
		}
		n.maybeNotify(f)
	case state.EventScanCompleted:
		s, ok := e.Payload.(state.Scan)
		if !ok {
			return
		}
		n.flushAggregate(s)
	}
}

// maybeNotify decides whether to fire a toast for a critical
// finding. Decisions, in order: (1) config disabled → drop, (2)
// first scan still in progress → suppress + count, (3) per-fingerprint
// cooldown active → drop silently, (4) rate window cap exceeded →
// suppress + count, (5) actually toast.
func (n *Notifier) maybeNotify(f state.Finding) {
	cfg := n.config()
	if !cfg.Enabled {
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.firstScanDone {
		// During the very first scan, suppress everything and let
		// the scan-completed aggregate carry the summary.
		n.suppressedSince++
		return
	}

	now := n.opts.Now()

	// Per-fingerprint cooldown.
	if last, ok := n.perFingerprintAt[f.Fingerprint]; ok {
		if now.Sub(last) < n.opts.CooldownPerFingerprint {
			return
		}
	}

	// Rolling window cap.
	if now.Sub(n.windowStart) >= n.opts.RateWindow {
		n.windowStart = now
		n.windowCount = 0
	}
	if n.windowCount >= n.opts.RateWindowCap {
		// Past the cap: suppress, will roll into the next
		// scan-completed aggregate.
		n.suppressedSince++
		return
	}

	// Actually toast.
	n.windowCount++
	n.perFingerprintAt[f.Fingerprint] = now
	title := "audr"
	body := fmt.Sprintf("CRITICAL: %s · run \"audr open\" to investigate", f.Title)
	if err := n.opts.Toaster.Toast(title, body); err != nil {
		n.opts.Logger.Warn("toast failed; falling back to pending-notify marker",
			"fingerprint", f.Fingerprint, "err", err)
		n.recordPending(PendingNotification{
			Fingerprint: f.Fingerprint,
			Title:       f.Title,
			Severity:    f.Severity,
			At:          now,
			Error:       err.Error(),
		})
	}
}

// flushAggregate fires the scan-completed aggregate toast. Two cases:
//   - first scan: emit the "audr first scan complete · N criticals" toast
//     regardless of suppression count, then mark firstScanDone.
//   - subsequent scans: emit "audr · N more critical findings" ONLY when
//     suppressedSince > 0.
func (n *Notifier) flushAggregate(_ state.Scan) {
	cfg := n.config()
	if !cfg.Enabled {
		// Even when disabled, still mark first scan done so that if
		// the user re-enables notifications later we don't replay
		// the first-run suppression.
		n.mu.Lock()
		n.firstScanDone = true
		n.suppressedSince = 0
		n.mu.Unlock()
		return
	}

	n.mu.Lock()
	wasFirst := !n.firstScanDone
	suppressed := n.suppressedSince
	n.firstScanDone = true
	n.suppressedSince = 0
	n.mu.Unlock()

	if wasFirst {
		// Pull the actual count from the store for accuracy. If
		// that fails (rare), fall back to the suppressed counter.
		critCount := n.criticalOpenCount()
		title := "audr"
		body := fmt.Sprintf("First scan complete · %d critical · audr open", critCount)
		_ = n.opts.Toaster.Toast(title, body)
		return
	}

	if suppressed > 0 {
		title := "audr"
		body := fmt.Sprintf("%d more critical findings since last alert · audr open", suppressed)
		_ = n.opts.Toaster.Toast(title, body)
	}
}

// criticalOpenCount returns the open critical count from the store.
// Errors return 0 (the aggregate copy just won't be precise).
func (n *Notifier) criticalOpenCount() int {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	findings, err := n.opts.Store.SnapshotFindings(ctx)
	if err != nil {
		return 0
	}
	c := 0
	for _, f := range findings {
		if f.Open() && f.Severity == "critical" {
			c++
		}
	}
	return c
}

// ----- Config IO ------------------------------------------------

func (n *Notifier) configPath() string {
	return filepath.Join(n.opts.StateDir, "notify.config.json")
}

// config returns the current persisted config, with default-on
// behavior when the file doesn't exist yet. Cached on the Notifier
// so we don't re-stat on every event.
func (n *Notifier) config() Config {
	n.mu.Lock()
	if n.configCacheLoaded {
		c := n.configCache
		n.mu.Unlock()
		return c
	}
	n.mu.Unlock()

	cfg := DefaultConfig()
	b, err := os.ReadFile(n.configPath())
	if err == nil {
		_ = json.Unmarshal(b, &cfg)
	}
	n.mu.Lock()
	n.configCache = cfg
	n.configCacheLoaded = true
	n.mu.Unlock()
	return cfg
}

// SetEnabled is the in-process API the `audr daemon notify` CLI
// command uses to flip the config. Writes the config file atomically
// and invalidates the cache.
func (n *Notifier) SetEnabled(enabled bool) error {
	cfg := Config{Enabled: enabled}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := n.configPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, n.configPath()); err != nil {
		return err
	}
	n.mu.Lock()
	n.configCache = cfg
	n.configCacheLoaded = true
	n.mu.Unlock()
	return nil
}

// ReadConfig is a static helper for CLI subcommands that don't have
// a live Notifier instance — they just want to print or flip the
// config on disk.
func ReadConfig(stateDir string) (Config, error) {
	cfg := DefaultConfig()
	b, err := os.ReadFile(filepath.Join(stateDir, "notify.config.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// WriteConfig atomically writes config to ${stateDir}/notify.config.json.
// Used by `audr daemon notify --off/--on`.
func WriteConfig(stateDir string, cfg Config) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("notify: create state dir: %w", err)
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(stateDir, "notify.config.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ----- Pending-notify marker ------------------------------------

func (n *Notifier) pendingPath() string {
	return filepath.Join(n.opts.StateDir, "pending-notify.json")
}

// recordPending appends a row to pending-notify.json. The file is a
// JSON array; we read-extend-write atomically so concurrent writes
// (impossible today — single Notifier subsystem — but defensive) are
// safe.
func (n *Notifier) recordPending(p PendingNotification) {
	var rows []PendingNotification
	if b, err := os.ReadFile(n.pendingPath()); err == nil {
		_ = json.Unmarshal(b, &rows)
	}
	rows = append(rows, p)
	b, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return
	}
	tmp := n.pendingPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, n.pendingPath())
}

// ReadPending returns the pending-notify rows on disk, or nil + nil
// if the file doesn't exist. `audr open` calls this to decide
// whether to render the dashboard banner.
func ReadPending(stateDir string) ([]PendingNotification, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, "pending-notify.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var rows []PendingNotification
	if err := json.Unmarshal(b, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// ClearPending truncates the pending-notify file. Called by
// `audr open` after surfacing the banner so the same drops don't
// re-show on the next open.
func ClearPending(stateDir string) error {
	return os.Remove(filepath.Join(stateDir, "pending-notify.json"))
}

// ----- OS toast adapter -----------------------------------------

type beeepToaster struct{}

func (beeepToaster) Toast(title, body string) error {
	// beeep.Notify takes (title, message, appIcon). Empty icon path
	// uses the platform default which lets us avoid shipping a PNG
	// in the binary for v1.
	return beeep.Notify(title, body, "")
}
