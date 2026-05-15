package notify

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/harshmaur/audr/internal/state"
)

// fakeToaster records every toast attempt and lets tests preload an
// error to simulate OS permission-denied / "notify-send not on PATH"
// failure modes.
type fakeToaster struct {
	mu      sync.Mutex
	calls   []toastCall
	nextErr error // when non-nil, EVERY call returns it
}

type toastCall struct{ title, body string }

func (f *fakeToaster) Toast(title, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, toastCall{title, body})
	return f.nextErr
}

func (f *fakeToaster) Calls() []toastCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]toastCall, len(f.calls))
	copy(out, f.calls)
	return out
}

func newTestNotifier(t *testing.T, ft *fakeToaster, nowFn func() time.Time) *Notifier {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := state.Open(state.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = s.Close() })
	go func() { _ = s.Run(ctx) }()
	// Tiny sleep so the writer goroutine is ready before tests
	// start pushing events (matches existing test patterns elsewhere).
	time.Sleep(5 * time.Millisecond)

	if nowFn == nil {
		nowFn = time.Now
	}
	n, err := New(Options{
		Store:                  s,
		StateDir:               t.TempDir(),
		Toaster:                ft,
		CooldownPerFingerprint: 24 * time.Hour,
		RateWindow:             5 * time.Minute,
		RateWindowCap:          3,
		Now:                    nowFn,
	})
	if err != nil {
		t.Fatalf("notify.New: %v", err)
	}
	return n
}

// TestFirstScanSuppressesIndividualToasts: during the very first
// scan, individual critical findings should NOT produce toasts —
// only the scan-completed aggregate.
func TestFirstScanSuppressesIndividualToasts(t *testing.T) {
	ft := &fakeToaster{}
	n := newTestNotifier(t, ft, nil)

	// Simulate 5 critical findings during the first scan.
	for i := 0; i < 5; i++ {
		n.handleEvent(state.Event{
			Kind: state.EventFindingOpened,
			Payload: state.Finding{
				Fingerprint: makeFp(i),
				Severity:    "critical",
				Title:       "test critical " + makeFp(i),
			},
		})
	}
	// No toasts yet — everything is suppressed in first scan.
	if got := len(ft.Calls()); got != 0 {
		t.Errorf("toasts during first scan = %d, want 0", got)
	}

	// Scan completes: one aggregate toast fires.
	n.handleEvent(state.Event{Kind: state.EventScanCompleted, Payload: state.Scan{ID: 1, Status: "completed"}})
	calls := ft.Calls()
	if len(calls) != 1 {
		t.Fatalf("toasts after first scan-completed = %d, want 1", len(calls))
	}
	if calls[0].title != "audr" {
		t.Errorf("aggregate title = %q, want audr", calls[0].title)
	}
	if !contains(calls[0].body, "First scan complete") {
		t.Errorf("aggregate body should mention 'First scan complete', got %q", calls[0].body)
	}
}

// TestSteadyStateRespectsPerFingerprintCooldown: after the first
// scan, the same critical fingerprint re-detected within 24h must
// NOT re-fire its toast.
func TestSteadyStateRespectsPerFingerprintCooldown(t *testing.T) {
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{t: now}
	ft := &fakeToaster{}
	n := newTestNotifier(t, ft, clock.now)
	// Skip first-scan suppression by faking that one already completed.
	n.firstScanDone = true

	fp := "fp-A"
	f := state.Finding{Fingerprint: fp, Severity: "critical", Title: "X"}

	// First detection → toast fires.
	n.handleEvent(state.Event{Kind: state.EventFindingOpened, Payload: f})
	if got := len(ft.Calls()); got != 1 {
		t.Fatalf("first detection toasts = %d, want 1", got)
	}

	// Same fingerprint 1h later → cooldown still active, suppressed.
	clock.advance(1 * time.Hour)
	n.handleEvent(state.Event{Kind: state.EventFindingOpened, Payload: f})
	if got := len(ft.Calls()); got != 1 {
		t.Errorf("re-detection within cooldown produced toasts = %d, want still 1", got)
	}

	// 25h later → cooldown lapsed, toast fires again.
	clock.advance(24 * time.Hour)
	n.handleEvent(state.Event{Kind: state.EventFindingOpened, Payload: f})
	if got := len(ft.Calls()); got != 2 {
		t.Errorf("re-detection after cooldown produced toasts = %d, want 2", got)
	}
}

// TestRollingWindowCapsToastsAtThree: across a 5-minute window the
// notifier emits at most 3 individual toasts, regardless of how many
// distinct critical fingerprints fire.
func TestRollingWindowCapsToastsAtThree(t *testing.T) {
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{t: now}
	ft := &fakeToaster{}
	n := newTestNotifier(t, ft, clock.now)
	n.firstScanDone = true

	// 5 distinct critical fingerprints in quick succession (each
	// inside the same 5-min window).
	for i := 0; i < 5; i++ {
		n.handleEvent(state.Event{
			Kind: state.EventFindingOpened,
			Payload: state.Finding{
				Fingerprint: makeFp(i),
				Severity:    "critical",
				Title:       "X" + makeFp(i),
			},
		})
		clock.advance(10 * time.Second)
	}
	if got := len(ft.Calls()); got != 3 {
		t.Errorf("individual toasts in window = %d, want 3", got)
	}

	// Scan-completed flushes the 2 suppressed as an aggregate.
	n.handleEvent(state.Event{Kind: state.EventScanCompleted, Payload: state.Scan{ID: 1, Status: "completed"}})
	calls := ft.Calls()
	if len(calls) != 4 {
		t.Fatalf("total toasts after flush = %d, want 4 (3 individual + 1 aggregate)", len(calls))
	}
	if !contains(calls[3].body, "2 more critical findings") {
		t.Errorf("aggregate body should mention '2 more critical findings', got %q", calls[3].body)
	}
}

// TestWindowResetsAfterFiveMinutes: a fresh batch of toasts is
// allowed once the 5-minute window rolls.
func TestWindowResetsAfterFiveMinutes(t *testing.T) {
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{t: now}
	ft := &fakeToaster{}
	n := newTestNotifier(t, ft, clock.now)
	n.firstScanDone = true

	// Fill the first window.
	for i := 0; i < 3; i++ {
		n.handleEvent(state.Event{
			Kind: state.EventFindingOpened,
			Payload: state.Finding{
				Fingerprint: makeFp(i),
				Severity:    "critical",
				Title:       "X",
			},
		})
	}
	// Advance past the window.
	clock.advance(6 * time.Minute)
	// New criticals — window has reset, fires.
	n.handleEvent(state.Event{
		Kind: state.EventFindingOpened,
		Payload: state.Finding{Fingerprint: "fp-new", Severity: "critical", Title: "Y"},
	})
	if got := len(ft.Calls()); got != 4 {
		t.Errorf("toasts after window reset = %d, want 4", got)
	}
}

// TestNonCriticalIgnored: high / medium / low findings never produce
// toasts.
func TestNonCriticalIgnored(t *testing.T) {
	ft := &fakeToaster{}
	n := newTestNotifier(t, ft, nil)
	n.firstScanDone = true

	for _, sev := range []string{"high", "medium", "low", ""} {
		n.handleEvent(state.Event{
			Kind: state.EventFindingOpened,
			Payload: state.Finding{
				Fingerprint: "fp-" + sev,
				Severity:    sev,
				Title:       "non-critical",
			},
		})
	}
	if got := len(ft.Calls()); got != 0 {
		t.Errorf("non-critical toasts = %d, want 0", got)
	}
}

// TestDisabledConfigSuppressesAll: with the persisted config in
// "Enabled: false", individual toasts and the aggregate are both
// suppressed.
func TestDisabledConfigSuppressesAll(t *testing.T) {
	ft := &fakeToaster{}
	n := newTestNotifier(t, ft, nil)
	n.firstScanDone = true

	// Write disabled config to the notifier's state dir before any
	// events arrive.
	if err := WriteConfig(n.opts.StateDir, Config{Enabled: false}); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}

	n.handleEvent(state.Event{
		Kind:    state.EventFindingOpened,
		Payload: state.Finding{Fingerprint: "fp-X", Severity: "critical", Title: "Y"},
	})
	n.handleEvent(state.Event{Kind: state.EventScanCompleted, Payload: state.Scan{ID: 1, Status: "completed"}})
	if got := len(ft.Calls()); got != 0 {
		t.Errorf("toasts with config disabled = %d, want 0", got)
	}
}

// TestToastErrorWritesPendingMarker: when the OS toast call fails
// (permission denied / missing notify-send / etc.), the notifier
// records the dropped notification to pending-notify.json so `audr
// open` can surface a banner.
func TestToastErrorWritesPendingMarker(t *testing.T) {
	ft := &fakeToaster{nextErr: errors.New("permission denied")}
	n := newTestNotifier(t, ft, nil)
	n.firstScanDone = true

	n.handleEvent(state.Event{
		Kind: state.EventFindingOpened,
		Payload: state.Finding{Fingerprint: "fp-Y", Severity: "critical", Title: "Toast me"},
	})

	pending, err := ReadPending(n.opts.StateDir)
	if err != nil {
		t.Fatalf("ReadPending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending count = %d, want 1", len(pending))
	}
	if pending[0].Fingerprint != "fp-Y" {
		t.Errorf("pending fingerprint = %q, want fp-Y", pending[0].Fingerprint)
	}
	if pending[0].Error == "" {
		t.Error("pending row should carry the toast error")
	}
}

// TestSetEnabledRoundtripsToFile: SetEnabled writes a JSON file that
// ReadConfig can parse back into the same shape.
func TestSetEnabledRoundtripsToFile(t *testing.T) {
	dir := t.TempDir()
	if err := WriteConfig(dir, Config{Enabled: false}); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	cfg, err := ReadConfig(dir)
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if cfg.Enabled {
		t.Errorf("Enabled = true, want false")
	}
	// Re-write to true and confirm.
	if err := WriteConfig(dir, Config{Enabled: true}); err != nil {
		t.Fatalf("WriteConfig (true): %v", err)
	}
	cfg, _ = ReadConfig(dir)
	if !cfg.Enabled {
		t.Errorf("Enabled = false, want true")
	}
	// And the file is mode 0600 (per Defaults; security-sensitive
	// nothing in this file but still).
	info, err := os.Stat(filepath.Join(dir, "notify.config.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", info.Mode().Perm())
	}
}

// TestReadConfigMissingFileReturnsDefault: a fresh installation has
// no notify.config.json yet — ReadConfig must return the default
// (Enabled: true) without erroring.
func TestReadConfigMissingFileReturnsDefault(t *testing.T) {
	cfg, err := ReadConfig(t.TempDir())
	if err != nil {
		t.Fatalf("ReadConfig on missing file: %v", err)
	}
	if !cfg.Enabled {
		t.Errorf("default Enabled = false, want true")
	}
}

// TestPendingNotifySerializationShape ensures the on-disk JSON has
// the fields `audr open` expects to read back. Pinning the shape
// here so a future refactor doesn't silently break the banner code.
func TestPendingNotifySerializationShape(t *testing.T) {
	dir := t.TempDir()
	n := &Notifier{opts: Options{StateDir: dir}}
	n.recordPending(PendingNotification{
		Fingerprint: "abc",
		Title:       "test",
		Severity:    "critical",
		At:          time.Now(),
		Error:       "permission denied",
	})
	b, err := os.ReadFile(filepath.Join(dir, "pending-notify.json"))
	if err != nil {
		t.Fatalf("read pending: %v", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	for _, want := range []string{"fingerprint", "title", "severity", "at", "error"} {
		if _, ok := rows[0][want]; !ok {
			t.Errorf("missing field %q in pending row", want)
		}
	}
}

// clickableFakeToaster wraps fakeToaster and reports
// SupportsClickAction()==true so tests can drive the
// body-composition-with-click code path.
type clickableFakeToaster struct {
	fakeToaster
}

func (*clickableFakeToaster) SupportsClickAction() bool { return true }

// TestBodyOmitsHintWhenClickActionSupported: with a clickable toaster
// the body must NOT carry the "run audr open" suffix — the click IS
// the action. Anchors the macOS terminal-notifier / Linux dbus /
// Windows AppUserModelID success paths in one regression.
func TestBodyOmitsHintWhenClickActionSupported(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{t: now}
	ft := &clickableFakeToaster{}
	n := newTestNotifier(t, &ft.fakeToaster, clock.now)
	n.opts.Toaster = ft // re-bind so the clickable-aware interface is in play
	n.firstScanDone = true

	n.handleEvent(state.Event{
		Kind: state.EventFindingOpened,
		Payload: state.Finding{
			Fingerprint: "fp-click",
			Severity:    "critical",
			Title:       "test critical",
		},
	})
	calls := ft.Calls()
	if len(calls) != 1 {
		t.Fatalf("toasts = %d, want 1", len(calls))
	}
	if !contains(calls[0].body, "CRITICAL: test critical") {
		t.Errorf("body should lead with 'CRITICAL: test critical', got %q", calls[0].body)
	}
	if contains(calls[0].body, "audr open") {
		t.Errorf("body must NOT carry 'audr open' hint when click works, got %q", calls[0].body)
	}
}

// TestBodyIncludesHintWhenNoClickAction: the non-clickable fallback
// (beeep on Windows, osascript on macOS without terminal-notifier)
// MUST surface the "run audr open" hint so the user has a manual
// path to the dashboard.
func TestBodyIncludesHintWhenNoClickAction(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{t: now}
	ft := &fakeToaster{} // plain fake, no SupportsClickAction
	n := newTestNotifier(t, ft, clock.now)
	n.firstScanDone = true

	n.handleEvent(state.Event{
		Kind: state.EventFindingOpened,
		Payload: state.Finding{
			Fingerprint: "fp-noclick",
			Severity:    "critical",
			Title:       "test critical",
		},
	})
	calls := ft.Calls()
	if len(calls) != 1 {
		t.Fatalf("toasts = %d, want 1", len(calls))
	}
	if !contains(calls[0].body, "run \"audr open\" to investigate") {
		t.Errorf("non-clickable body must contain the hint, got %q", calls[0].body)
	}
}

// TestAggregateBodyAdaptsToClickAction: the first-scan and rolling-cap
// aggregate toasts also adapt their suffix — "Open dashboard" when
// the click works (terminal-notifier / dbus / AppUserModelID),
// "audr open" otherwise.
func TestAggregateBodyAdaptsToClickAction(t *testing.T) {
	ft := &clickableFakeToaster{}
	n := newTestNotifier(t, &ft.fakeToaster, nil)
	n.opts.Toaster = ft

	// Trigger first-scan aggregate by firing scan-completed without
	// any prior scan-completed (firstScanDone stays false until
	// flushAggregate marks it).
	n.handleEvent(state.Event{Kind: state.EventScanCompleted, Payload: state.Scan{ID: 1, Status: "completed"}})
	calls := ft.Calls()
	if len(calls) != 1 {
		t.Fatalf("aggregate toasts = %d, want 1", len(calls))
	}
	if !contains(calls[0].body, "Open dashboard") {
		t.Errorf("clickable aggregate body should end with 'Open dashboard', got %q", calls[0].body)
	}
	if contains(calls[0].body, "audr open") {
		t.Errorf("clickable aggregate body should NOT carry 'audr open' CLI hint, got %q", calls[0].body)
	}
}

// ----- Helpers --------------------------------------------------

func makeFp(i int) string {
	return "fp-" + string(rune('A'+i))
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// fakeClock is a thread-safe-enough manual clock for the rate
// limiter tests. Notifier only reads via Now func, so a single-
// goroutine clock is sufficient.
type fakeClock struct {
	t  time.Time
}

func (f *fakeClock) now() time.Time     { return f.t }
func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }
