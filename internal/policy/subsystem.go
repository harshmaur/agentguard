package policy

import (
	"context"
	"log/slog"

	"github.com/harshmaur/audr/internal/state"
)

// Subsystem is the daemon-side glue between the file watcher and the
// state store's pub-sub. Implements daemon.Subsystem (Name/Run/Close)
// without importing the daemon package — the lifecycle accepts any
// matching interface.
//
// Wiring: the daemon constructs a Subsystem with a Store reference
// and a policy file path, registers it via lifecycle.Register, and
// the lifecycle drives Run/Close. When the watcher fires, the
// Subsystem publishes EventPolicyChanged on the Store's event bus;
// connected dashboards see it via SSE and reload.
//
// Failure mode: if the watcher can't subscribe (e.g., fsnotify
// quota exhausted on Linux), Run returns the error and the daemon
// lifecycle logs it. The daemon still boots — the per-scan-cycle
// reload remains the primary hot-reload path; live SSE reload is
// the polish layer.
type Subsystem struct {
	store    *state.Store
	path     string
	logger   *slog.Logger
	watcher  *Watcher
}

// NewSubsystem constructs the daemon glue. path may be empty — when
// empty we resolve it via policy.Path() at Run time (this lets the
// daemon construct the Subsystem before $HOME is fully resolved in
// some test scenarios).
func NewSubsystem(store *state.Store, path string, logger *slog.Logger) *Subsystem {
	if logger == nil {
		logger = slog.Default()
	}
	return &Subsystem{store: store, path: path, logger: logger}
}

// Name implements daemon.Subsystem.
func (s *Subsystem) Name() string { return "policy-watcher" }

// Run starts the fsnotify watcher and blocks until ctx cancels.
// Resolves the policy path lazily if Subsystem was constructed
// with an empty path.
func (s *Subsystem) Run(ctx context.Context) error {
	path := s.path
	if path == "" {
		p, err := Path()
		if err != nil {
			return err
		}
		path = p
	}

	cb := func() {
		if s.store == nil {
			return
		}
		s.store.Publish(state.Event{
			Kind: state.EventPolicyChanged,
		})
		s.logger.Debug("policy watcher: published policy-changed event",
			"path", path)
	}

	w, err := NewWatcher(path, cb, s.logger)
	if err != nil {
		return err
	}
	s.watcher = w
	return w.Run(ctx)
}

// Close releases the watcher's resources.
func (s *Subsystem) Close() error {
	if s.watcher == nil {
		return nil
	}
	return s.watcher.Close()
}
