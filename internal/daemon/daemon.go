package daemon

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// Options configures a daemon Run. Zero-value is fine for Phase 1 — the
// constructor fills in defaults.
type Options struct {
	// Paths controls where the daemon writes state, logs, etc. If
	// zero-value, Resolve() is called.
	Paths Paths

	// Sidecars pins the minimum sidecar versions. Zero-value uses
	// DefaultSidecarConfig().
	Sidecars SidecarConfig

	// ShutdownGrace caps how long Run waits for subsystems to drain
	// after context cancellation. Defaults to 30s.
	ShutdownGrace time.Duration

	// Logger receives daemon-level events. If nil, a slog handler
	// writing to the daemon's log file is created.
	Logger *slog.Logger

	// LogWriter, when non-nil, overrides where the auto-created logger
	// writes. Used by tests to capture log output. Ignored when Logger
	// is non-nil (then the caller owns the destination).
	LogWriter io.Writer

	// Subsystems are registered with the lifecycle before it Run()s.
	// The caller owns construction; daemon.Run takes responsibility for
	// the lifecycle (Run + Close + shutdown grace). Order matters for
	// shutdown — see Lifecycle.closeAll which closes in reverse.
	Subsystems []Subsystem
}

// Run boots the daemon: ensures paths exist, acquires the PID lock,
// probes sidecars, registers Phase 1's subsystems (none yet), and blocks
// in Lifecycle.Run until ctx is cancelled or a signal arrives.
//
// This is what `audr daemon run-internal` invokes when launched by the
// OS service manager. It's also callable directly for `audr daemon
// start --foreground` (developer convenience, not exposed in the CLI
// in Phase 1).
//
// Returns nil on graceful shutdown. Returns *AlreadyRunningError if
// another daemon already holds the PID lock (the CLI surfaces this as a
// friendly message). Returns other errors for setup failures.
func Run(ctx context.Context, opts Options) error {
	// 1. Resolve + create paths.
	if opts.Paths.State == "" {
		p, err := Resolve()
		if err != nil {
			return fmt.Errorf("daemon: resolve paths: %w", err)
		}
		opts.Paths = p
	}
	if err := opts.Paths.Ensure(); err != nil {
		return fmt.Errorf("daemon: ensure paths: %w", err)
	}

	// 2. Acquire the PID lock. If another daemon is running, surface a
	//    friendly error WITHOUT modifying any state.
	lock, err := AcquirePIDLock(opts.Paths.PIDFile())
	if err != nil {
		return err
	}
	defer lock.Release()

	// 3. Build a logger (file-backed by default; LogWriter override for
	//    tests; explicit Logger overrides both).
	logger, logCloser, err := buildLogger(opts)
	if err != nil {
		return fmt.Errorf("daemon: build logger: %w", err)
	}
	if logCloser != nil {
		defer logCloser.Close()
	}

	logger.Info("daemon starting",
		"pid", os.Getpid(),
		"state_dir", opts.Paths.State,
		"log_file", opts.Paths.LogFile(),
	)

	// 4. Probe sidecars. Failures DON'T abort startup (per D15 + D4 in
	//    the eng review): the daemon must keep running so other
	//    categories work. We just log the per-sidecar status.
	if opts.Sidecars.ProbeTimeout == 0 {
		opts.Sidecars = DefaultSidecarConfig()
	}
	statuses := CheckSidecars(ctx, opts.Sidecars)
	for _, s := range statuses {
		logger.Info("sidecar probed",
			"sidecar", s.Name,
			"state", string(s.State),
			"path", s.Path,
			"found_version", s.FoundVersion,
			"min_version", s.MinVersion,
			"error_text", s.ErrorText,
		)
	}

	// 5. Build + run the lifecycle, registering caller-supplied
	//    subsystems first (server, state store, watch engine, ...).
	lc := NewLifecycle(opts.ShutdownGrace)
	for _, sub := range opts.Subsystems {
		lc.Register(sub)
	}
	logger.Info("daemon ready", "subsystems", len(lc.Subsystems()))

	err = lc.Run(ctx)
	logger.Info("daemon shutting down", "err", err)
	return err
}

// buildLogger returns a logger for the daemon. Order of preference:
//   - opts.Logger (caller-provided)
//   - opts.LogWriter (test injection)
//   - file at opts.Paths.LogFile() (production default)
//
// Returns the optional file closer so callers can defer-close.
func buildLogger(opts Options) (*slog.Logger, io.Closer, error) {
	if opts.Logger != nil {
		return opts.Logger, nil, nil
	}

	var sink io.Writer = opts.LogWriter
	var closer io.Closer
	if sink == nil {
		// Append-only daemon log under Logs dir.
		if err := os.MkdirAll(filepath.Dir(opts.Paths.LogFile()), 0o700); err != nil {
			return nil, nil, fmt.Errorf("create log dir: %w", err)
		}
		f, err := os.OpenFile(opts.Paths.LogFile(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("open log file %s: %w", opts.Paths.LogFile(), err)
		}
		sink = f
		closer = f
	}

	handler := slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: slog.LevelInfo})
	return slog.New(handler), closer, nil
}
