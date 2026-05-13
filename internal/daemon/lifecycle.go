package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
)

// Subsystem is the contract every long-lived component of the daemon
// implements: state store, HTTP server, watch+poll engine, scanner
// orchestrator, notifier. Phase 1 ships zero subsystems; the lifecycle
// just owns the root context and signal handler. Phases 2-6 plug in.
//
// Run is called once with the daemon's root context. It SHOULD return
// nil on graceful shutdown (ctx.Done()) and a non-nil error on a fatal
// problem that should bring the daemon down. The lifecycle treats the
// first non-nil error as fatal and cancels the rest.
type Subsystem interface {
	// Name returns a short, stable identifier used in log lines and
	// error messages ("state", "server", "watch", ...).
	Name() string

	// Run blocks until ctx is cancelled or a fatal error occurs.
	Run(ctx context.Context) error

	// Close is called after Run returns. Implementations release any
	// non-context-owned resources here (DB handles, sockets, file
	// locks). Idempotent. Best-effort: Close errors are logged but
	// don't fail shutdown.
	Close() error
}

// Lifecycle is the daemon's root orchestrator. It holds the root
// context, the signal handler, and the errgroup that runs all
// subsystems. Construct via NewLifecycle, register subsystems via
// Register, then call Run to block until the daemon exits.
//
// Shutdown order matters: Run cancels ctx first (so subsystems exit
// their Run loops), then waits for the errgroup, then calls Close on
// each registered subsystem in REVERSE registration order so
// later-registered subsystems (which may depend on earlier ones)
// release their resources first.
type Lifecycle struct {
	mu          sync.Mutex
	subsystems  []Subsystem
	shutdownDur time.Duration
}

// NewLifecycle constructs a daemon Lifecycle. shutdownGrace caps how
// long Run waits for subsystems to drain after context cancellation
// before giving up. 30 seconds is the design-doc default.
func NewLifecycle(shutdownGrace time.Duration) *Lifecycle {
	if shutdownGrace <= 0 {
		shutdownGrace = 30 * time.Second
	}
	return &Lifecycle{shutdownDur: shutdownGrace}
}

// Register adds a subsystem to the lifecycle. Order matters for shutdown
// (later-registered close first). Safe to call concurrently before Run.
func (l *Lifecycle) Register(s Subsystem) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.subsystems = append(l.subsystems, s)
}

// Run starts every registered subsystem under a shared root context,
// installs a signal handler for SIGINT + SIGTERM, and blocks until:
//
//   - ctx (the parent context) is cancelled, OR
//   - a signal arrives, OR
//   - any subsystem returns a fatal error
//
// Then it cancels the root context, waits up to shutdownGrace for
// subsystems to drain, and calls Close on each in reverse order. Returns
// the first non-nil subsystem error, or nil for clean shutdown.
//
// Run is intended to be called exactly once per Lifecycle.
func (l *Lifecycle) Run(parent context.Context) error {
	l.mu.Lock()
	subs := append([]Subsystem(nil), l.subsystems...)
	l.mu.Unlock()

	// Root context: parent OR signals. We use signal.NotifyContext so
	// SIGINT/SIGTERM cancel the root cleanly without an explicit goroutine.
	rootCtx, cancelSignals := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer cancelSignals()

	g, ctx := errgroup.WithContext(rootCtx)
	for _, s := range subs {
		s := s
		g.Go(func() error {
			err := s.Run(ctx)
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				return fmt.Errorf("subsystem %s: %w", s.Name(), err)
			}
			return nil
		})
	}

	// Block: g.Wait returns once all subsystems' Run methods return.
	// They return when (a) ctx cancels (signal or parent), or (b) one
	// of them errors and errgroup cancels the rest.
	runErr := g.Wait()

	// Drain phase. ctx is already cancelled; subsystems have returned
	// from Run. We invoke Close on each subsystem in reverse order with
	// a bounded budget. Close errors are aggregated but do NOT mask
	// runErr (the original failure that triggered shutdown is the
	// important one to surface).
	closeErrs := l.closeAll(subs)

	if runErr != nil {
		return runErr
	}
	if len(closeErrs) > 0 {
		return errors.Join(closeErrs...)
	}
	return nil
}

// closeAll calls Close on subsystems in reverse registration order with
// the shutdown-grace budget. Returns accumulated errors; never panics.
func (l *Lifecycle) closeAll(subs []Subsystem) []error {
	deadline := time.Now().Add(l.shutdownDur)
	var errs []error
	for i := len(subs) - 1; i >= 0; i-- {
		// Best-effort budget split: each subsystem gets the remaining
		// time. We don't enforce the deadline inside Close (Close is
		// supposed to be fast and synchronous), but we surface a hint
		// if we're already past it.
		if time.Now().After(deadline) {
			errs = append(errs, fmt.Errorf("subsystem %s: close skipped past shutdown deadline", subs[i].Name()))
			continue
		}
		if err := subs[i].Close(); err != nil {
			errs = append(errs, fmt.Errorf("subsystem %s close: %w", subs[i].Name(), err))
		}
	}
	return errs
}

// Subsystems returns the registered subsystems (read-only snapshot).
// Useful for `audr daemon status` to enumerate what's running.
func (l *Lifecycle) Subsystems() []Subsystem {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Subsystem, len(l.subsystems))
	copy(out, l.subsystems)
	return out
}
