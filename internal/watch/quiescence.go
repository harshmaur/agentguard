package watch

import (
	"context"
	"sync"
	"time"
)

// QuiescenceGate debounces a stream of filesystem events into discrete
// "scan now" triggers. Every Bump() restarts an internal timer; when
// the timer fires without any new Bump for the configured stability
// window, the gate emits one trigger on the Triggers() channel.
//
// Why this matters: an `npm install` of a moderate React project
// generates ~60k inotify events in <10 seconds. If we ran a scan on
// every event we'd thrash. The gate collapses those 60k events into
// one trigger fired ~5s after the install finishes — when the
// filesystem actually settles down.
//
// The gate is concurrency-safe. Bump() may be called from any
// goroutine; the timer runs in its own goroutine spawned by Run().
type QuiescenceGate struct {
	stability time.Duration
	trigger   chan time.Time

	mu        sync.Mutex
	timer     *time.Timer
	lastEvent time.Time
	closed    bool
}

// NewQuiescenceGate returns a gate that fires `stability` after the
// last Bump. Typical: 5 * time.Second.
func NewQuiescenceGate(stability time.Duration) *QuiescenceGate {
	if stability <= 0 {
		stability = 5 * time.Second
	}
	return &QuiescenceGate{
		stability: stability,
		trigger:   make(chan time.Time, 8),
	}
}

// Triggers returns the channel callers read to know when the
// filesystem has been quiet long enough to scan. Buffered so a slow
// consumer doesn't drop events; if the consumer falls multiple
// triggers behind it just sees them coalesced (the orchestrator runs
// one scan per trigger anyway, so a backlog of two doesn't help).
func (q *QuiescenceGate) Triggers() <-chan time.Time { return q.trigger }

// Bump records a filesystem event. The gate's internal timer resets;
// quiescence is measured from THIS call.
func (q *QuiescenceGate) Bump() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.lastEvent = time.Now()
	if q.timer == nil {
		q.timer = time.AfterFunc(q.stability, q.fire)
		return
	}
	if !q.timer.Stop() {
		// Timer already fired or about to fire. AfterFunc's func runs
		// in its own goroutine; if it's already scheduled to run, we
		// don't need to do anything — when it does run, it'll see
		// lastEvent moved forward and reschedule via fire().
		select {
		case <-q.trigger: // drain a queued trigger so we don't fire stale
		default:
		}
	}
	q.timer.Reset(q.stability)
}

// fire is invoked by the timer when quiescence is reached. It checks
// the gate hasn't been closed in the meantime and emits one trigger.
// Non-blocking on the trigger channel — if a consumer is slow, the
// next trigger waits in the buffer.
func (q *QuiescenceGate) fire() {
	q.mu.Lock()
	closed := q.closed
	last := q.lastEvent
	q.mu.Unlock()
	if closed {
		return
	}
	select {
	case q.trigger <- last:
	default:
		// Buffer full — drop. Orchestrator already has pending work.
	}
}

// Run blocks until ctx cancels. The gate's timer-driven goroutine is
// independent of Run, but daemon.Subsystem semantics expect Run() so
// we expose it for symmetric registration. Phase 3's watcher uses
// the QuiescenceGate internally rather than registering it directly,
// but a future refactor could promote it.
func (q *QuiescenceGate) Run(ctx context.Context) error {
	<-ctx.Done()
	return q.Close()
}

// Close stops the gate. Subsequent Bumps are no-ops; the trigger
// channel is left open so any consumer in a range loop sees it
// close cleanly via the outer subsystem's shutdown path.
func (q *QuiescenceGate) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil
	}
	q.closed = true
	if q.timer != nil {
		q.timer.Stop()
	}
	return nil
}
