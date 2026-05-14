package watch

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestClassifyMatchesDesignDoc(t *testing.T) {
	cases := []struct {
		name      string
		load      float64
		loadOK    bool
		onBattery bool
		battOK    bool
		want      BackoffState
	}{
		// Load is the dominant signal when known.
		{"low load + AC", 0.5, true, false, true, StateRun},
		{"low load + battery", 0.5, true, true, true, StateSlow},
		{"load=2 → SLOW boundary", 2.0, true, false, true, StateSlow},
		{"load=3.5 → SLOW", 3.5, true, false, true, StateSlow},
		{"load=4.5 → PAUSE", 4.5, true, false, true, StatePause},
		{"load PAUSE overrides battery=ok", 5.0, true, false, true, StatePause},

		// Load unknown: battery decides.
		{"load unknown + AC", 0, false, false, true, StateRun},
		{"load unknown + battery", 0, false, true, true, StateSlow},

		// Both unknown: default to RUN (safest — never PAUSE on
		// missing info).
		{"all unknown", 0, false, false, false, StateRun},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := classify(tt.load, tt.loadOK, tt.onBattery, tt.battOK)
			if got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

// fakeReader lets us drive the Backoff in tests without touching real
// /proc or sysctl. Atomic fields so the polling goroutine and the
// test goroutine can race safely.
type fakeReader struct {
	load      atomic.Uint64 // float64 bits
	loadOK    atomic.Bool
	onBattery atomic.Bool
	battOK    atomic.Bool
}

func (f *fakeReader) set(load float64, loadOK bool, onBattery, battOK bool) {
	f.load.Store(bitsFromFloat(load))
	f.loadOK.Store(loadOK)
	f.onBattery.Store(onBattery)
	f.battOK.Store(battOK)
}

func (f *fakeReader) LoadAvg() (float64, bool) {
	return floatFromBits(f.load.Load()), f.loadOK.Load()
}
func (f *fakeReader) OnBattery() (bool, bool) {
	return f.onBattery.Load(), f.battOK.Load()
}

func TestBackoffTransitionsAsSignalsChange(t *testing.T) {
	r := &fakeReader{}
	r.set(0.1, true, false, true) // RUN

	b := NewBackoff(r, 25*time.Millisecond) // fast tick for tests
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = b.Run(ctx); close(done) }()

	// Initial state.
	waitFor(t, 500*time.Millisecond, func() bool {
		return b.Current() == StateRun
	})

	// Battery → SLOW.
	r.set(0.1, true, true, true)
	waitFor(t, 500*time.Millisecond, func() bool {
		return b.Current() == StateSlow
	})

	// Load spike → PAUSE.
	r.set(5.5, true, true, true)
	waitFor(t, 500*time.Millisecond, func() bool {
		return b.Current() == StatePause
	})

	// Back to AC + low load → RUN.
	r.set(0.1, true, false, true)
	waitFor(t, 500*time.Millisecond, func() bool {
		return b.Current() == StateRun
	})

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestBackoffLastSignalsExposesValues(t *testing.T) {
	r := &fakeReader{}
	r.set(1.5, true, true, true)
	b := NewBackoff(r, 20*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = b.Run(ctx) }()

	// Sample immediately runs once in Run; give it a moment.
	time.Sleep(50 * time.Millisecond)
	load, loadOK, batt, battOK := b.LastSignals()
	if !loadOK || !battOK {
		t.Errorf("expected both OK flags true, got loadOK=%v battOK=%v", loadOK, battOK)
	}
	if load != 1.5 {
		t.Errorf("load = %v, want 1.5", load)
	}
	if !batt {
		t.Errorf("battery = false, want true")
	}
}

func TestBackoffStringRendersAllStates(t *testing.T) {
	cases := map[BackoffState]string{
		StateRun:   "RUN",
		StateSlow:  "SLOW",
		StatePause: "PAUSE",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("%v.String() = %q, want %q", int32(s), got, want)
		}
	}
}

// waitFor polls cond until it returns true or timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not satisfied within %v", timeout)
}
