package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSubsystem is a test double that records lifecycle calls and can be
// instructed to error from Run or Close.
type fakeSubsystem struct {
	name      string
	runErr    error
	closeErr  error
	runCalled atomic.Bool
	closed    atomic.Bool

	// runBlock, when non-nil, causes Run to block on it until cancelled.
	// Default: block on ctx.Done().
	runBlock chan struct{}
}

func newFakeSubsystem(name string) *fakeSubsystem {
	return &fakeSubsystem{name: name}
}

func (f *fakeSubsystem) Name() string { return f.name }

func (f *fakeSubsystem) Run(ctx context.Context) error {
	f.runCalled.Store(true)
	if f.runErr != nil {
		return f.runErr
	}
	if f.runBlock != nil {
		select {
		case <-f.runBlock:
			return nil
		case <-ctx.Done():
			return nil
		}
	}
	<-ctx.Done()
	return nil
}

func (f *fakeSubsystem) Close() error {
	f.closed.Store(true)
	return f.closeErr
}

func TestLifecycleRunsAllSubsystemsAndCloses(t *testing.T) {
	a := newFakeSubsystem("a")
	b := newFakeSubsystem("b")
	c := newFakeSubsystem("c")

	l := NewLifecycle(2 * time.Second)
	l.Register(a)
	l.Register(b)
	l.Register(c)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()

	// Give subsystems a moment to enter Run.
	if !waitFor(t, 2*time.Second, func() bool {
		return a.runCalled.Load() && b.runCalled.Load() && c.runCalled.Load()
	}) {
		t.Fatalf("not all subsystems entered Run: a=%v b=%v c=%v",
			a.runCalled.Load(), b.runCalled.Load(), c.runCalled.Load())
	}

	cancel() // trigger graceful shutdown
	err := waitForRun(t, done, 5*time.Second)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}

	for _, s := range []*fakeSubsystem{a, b, c} {
		if !s.closed.Load() {
			t.Errorf("subsystem %s not closed", s.name)
		}
	}
}

func TestLifecycleSurfacesFatalSubsystemError(t *testing.T) {
	a := newFakeSubsystem("good")
	bad := newFakeSubsystem("bad")
	bad.runErr = errors.New("kaboom")

	l := NewLifecycle(2 * time.Second)
	l.Register(a)
	l.Register(bad)

	done := make(chan error, 1)
	go func() { done <- l.Run(context.Background()) }()

	err := waitForRun(t, done, 5*time.Second)
	if err == nil {
		t.Fatalf("expected non-nil error from Run when subsystem fails")
	}
	if want := "kaboom"; err.Error() == "" || !contains(err.Error(), want) {
		t.Errorf("Run err = %v, want it to wrap %q", err, want)
	}
	if !a.closed.Load() || !bad.closed.Load() {
		t.Errorf("subsystems must still be closed after fatal: good.closed=%v bad.closed=%v", a.closed.Load(), bad.closed.Load())
	}
}

func TestLifecycleClosesInReverseRegistrationOrder(t *testing.T) {
	var (
		closedOrder []string
		mu          struct{}
	)
	_ = mu
	makeRecorder := func(name string, record *[]string) *recordingSubsystem {
		return &recordingSubsystem{
			name:    name,
			closeFn: func() { *record = append(*record, name) },
		}
	}

	a := makeRecorder("a", &closedOrder)
	b := makeRecorder("b", &closedOrder)
	c := makeRecorder("c", &closedOrder)

	l := NewLifecycle(2 * time.Second)
	l.Register(a)
	l.Register(b)
	l.Register(c)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	cancel()
	if err := waitForRun(t, done, 5*time.Second); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(closedOrder) != 3 {
		t.Fatalf("close order has %d entries, want 3: %v", len(closedOrder), closedOrder)
	}
	want := []string{"c", "b", "a"}
	for i, w := range want {
		if closedOrder[i] != w {
			t.Errorf("close order[%d] = %q, want %q (full: %v)", i, closedOrder[i], w, closedOrder)
		}
	}
}

func TestLifecycleAggregatesCloseErrorsWhenRunSucceeded(t *testing.T) {
	a := newFakeSubsystem("a")
	a.closeErr = fmt.Errorf("close-a-fail")
	b := newFakeSubsystem("b")
	b.closeErr = fmt.Errorf("close-b-fail")

	l := NewLifecycle(2 * time.Second)
	l.Register(a)
	l.Register(b)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	cancel()

	err := waitForRun(t, done, 5*time.Second)
	if err == nil {
		t.Fatalf("expected aggregated close error, got nil")
	}
	msg := err.Error()
	if !contains(msg, "close-a-fail") || !contains(msg, "close-b-fail") {
		t.Errorf("aggregated err = %v, want both close-a-fail and close-b-fail", err)
	}
}

func TestLifecycleRunErrorMasksCloseErrors(t *testing.T) {
	// If Run fails AND Close fails, Run is the load-bearing failure to
	// surface — close errors get swallowed (logged in real code; tested
	// for "not in the returned error" here).
	a := newFakeSubsystem("a")
	a.runErr = errors.New("run-fail")
	a.closeErr = errors.New("close-fail")

	l := NewLifecycle(2 * time.Second)
	l.Register(a)

	err := l.Run(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if !contains(err.Error(), "run-fail") {
		t.Errorf("err = %v, want it to contain run-fail", err)
	}
	if contains(err.Error(), "close-fail") {
		t.Errorf("err = %v, must NOT contain close-fail (Run failure is the surfaced one)", err)
	}
}

// recordingSubsystem captures Close() invocation order for the ordering test.
type recordingSubsystem struct {
	name    string
	closeFn func()
}

func (r *recordingSubsystem) Name() string                  { return r.name }
func (r *recordingSubsystem) Run(ctx context.Context) error { <-ctx.Done(); return nil }
func (r *recordingSubsystem) Close() error                  { r.closeFn(); return nil }

// waitFor polls cond until it returns true or timeout elapses. Returns
// true on success.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// waitForRun blocks for done up to timeout. Fails the test if timeout.
func waitForRun(t *testing.T, done chan error, timeout time.Duration) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		t.Fatalf("Run did not return within %v", timeout)
		return nil
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
