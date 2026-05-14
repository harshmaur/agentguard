package watch

import (
	"context"
	"sync/atomic"
	"time"
)

// BackoffState describes how aggressively the daemon should scan. The
// state machine in this package reads system signals (load avg +
// battery) and reports the current state; the watcher consumes it to
// decide whether to fire scan triggers normally, throttled, or not at
// all.
//
// Per /plan-eng-review:
//
//   - RUN:   1-min load avg < 2.0 AND on AC power. Normal cadence.
//   - SLOW:  load 2-4 OR on battery. Throttle: emit triggers but at
//            half the normal rate (orchestrator's next-tick interval
//            doubles).
//   - PAUSE: load > 4 OR thermal pressure detected. Stop emitting
//            triggers entirely; the watcher still consumes fsnotify
//            events so the inotify queue doesn't overflow, but no
//            scans fire until pressure clears.
type BackoffState int32

const (
	StateRun BackoffState = iota
	StateSlow
	StatePause
)

// String makes the state human-readable in the dashboard's daemon-
// state indicator + log lines.
func (s BackoffState) String() string {
	switch s {
	case StateRun:
		return "RUN"
	case StateSlow:
		return "SLOW"
	case StatePause:
		return "PAUSE"
	default:
		return "UNKNOWN"
	}
}

// SignalReader is the contract a per-OS signal source implements.
// LoadAvg returns the 1-minute system load average. OnBattery reports
// whether the machine is currently on battery power. Either method
// may return ok=false when the signal is unavailable on this OS or
// runtime; the state machine treats unknown signals as "safe RUN"
// (we never PAUSE on unknown information).
type SignalReader interface {
	LoadAvg() (float64, bool)
	OnBattery() (bool, bool)
}

// classify is the pure decision function. Tested directly so the
// state-machine semantics are golden-file regardless of OS quirks
// in the signal reader.
func classify(load float64, loadOK bool, onBattery, batteryOK bool) BackoffState {
	// Always-known thresholds first — load is the dominant signal.
	if loadOK {
		switch {
		case load > 4.0:
			return StatePause
		case load >= 2.0:
			return StateSlow
		}
	}
	// Load was either unknown or under 2.0. Battery acts as a tie-
	// breaker: on-battery → SLOW (be a good neighbor), AC → RUN.
	if batteryOK && onBattery {
		return StateSlow
	}
	return StateRun
}

// Backoff polls SignalReader on a tick and exposes the current state
// via Current(). Implements daemon.Subsystem-like Run/Close so it
// composes cleanly into the watcher's lifecycle (we don't register
// it as a top-level subsystem; the watcher owns it).
type Backoff struct {
	reader   SignalReader
	interval time.Duration
	state    atomic.Int32 // BackoffState — read concurrently from many goroutines

	// Cached signal values for the dashboard's daemon-state surface.
	// The state indicator shows "SLOW: battery" or "PAUSE: load 5.2",
	// so we expose the inputs that drove the decision.
	lastLoad    atomic.Uint64 // float64 bits
	lastLoadOK  atomic.Bool
	lastBatt    atomic.Bool
	lastBattOK  atomic.Bool
}

// NewBackoff constructs a Backoff. tickInterval defaults to 5 seconds
// if zero (frequent enough to react quickly to npm install storms,
// rare enough that the signal reads don't show up in profiles).
func NewBackoff(reader SignalReader, tickInterval time.Duration) *Backoff {
	if tickInterval <= 0 {
		tickInterval = 5 * time.Second
	}
	b := &Backoff{reader: reader, interval: tickInterval}
	b.state.Store(int32(StateRun))
	return b
}

// Current returns the cached state. O(1), safe to call from any
// goroutine. The watcher calls this on every quiescence trigger to
// decide whether to dispatch to the orchestrator.
func (b *Backoff) Current() BackoffState {
	return BackoffState(b.state.Load())
}

// LastSignals returns the most recent (load, on-battery) pair the
// state machine observed, with the "ok" flags from the underlying
// reader. Used by the dashboard's daemon-state indicator to render
// "SLOW: battery" or "PAUSE: load 5.2".
func (b *Backoff) LastSignals() (load float64, loadOK bool, onBattery bool, batteryOK bool) {
	load = floatFromBits(b.lastLoad.Load())
	loadOK = b.lastLoadOK.Load()
	onBattery = b.lastBatt.Load()
	batteryOK = b.lastBattOK.Load()
	return
}

// Run polls signals on the configured cadence until ctx cancels.
// Updates Current() between ticks. Errors from the underlying reader
// are silently treated as "unknown" — the classify function handles
// that case explicitly.
func (b *Backoff) Run(ctx context.Context) error {
	// Sample once immediately so Current() is meaningful before the
	// first tick fires.
	b.sampleOnce()

	tick := time.NewTicker(b.interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			b.sampleOnce()
		}
	}
}

func (b *Backoff) sampleOnce() {
	load, loadOK := b.reader.LoadAvg()
	onBattery, batteryOK := b.reader.OnBattery()
	newState := classify(load, loadOK, onBattery, batteryOK)

	b.lastLoad.Store(bitsFromFloat(load))
	b.lastLoadOK.Store(loadOK)
	b.lastBatt.Store(onBattery)
	b.lastBattOK.Store(batteryOK)
	b.state.Store(int32(newState))
}

// Stub reader for tests + Windows fallback. Always reports "unknown"
// signals → state machine resolves to RUN.
type stubReader struct{}

func (stubReader) LoadAvg() (float64, bool)  { return 0, false }
func (stubReader) OnBattery() (bool, bool)   { return false, false }
