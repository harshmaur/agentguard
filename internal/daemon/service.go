package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/kardianos/service"
)

// ServiceConfig captures the per-install knobs for the daemon's OS-level
// service entry. Mostly stable values; exposed as a struct so tests can
// override.
type ServiceConfig struct {
	// Name is the OS-level service identifier ("audr-daemon"). This is
	// what shows up in `systemctl --user list-units`, `launchctl list`,
	// `sc query`, etc. Must be filesystem-safe.
	Name string

	// DisplayName is the human-friendly label.
	DisplayName string

	// Description is the one-line "what is this thing" text.
	Description string

	// ExecPath, when set, is the absolute path to the audr binary the
	// service manager will invoke. Defaults to os.Executable().
	ExecPath string

	// Args are the arguments the service manager passes. We default to
	// the hidden `daemon run-internal` subcommand, which boots the
	// lifecycle with no interactive UI.
	Args []string
}

// DefaultServiceConfig returns the production service registration. The
// caller may override fields before passing to NewService.
func DefaultServiceConfig() ServiceConfig {
	return ServiceConfig{
		Name:        "audr-daemon",
		DisplayName: "audr — developer-machine security daemon",
		Description: "Continuously monitors developer-machine security posture (AI agent configs, dep CVEs, secrets, OS packages). Loopback dashboard at http://127.0.0.1:<port>.",
		Args:        []string{"daemon", "run-internal"},
	}
}

// Service wraps a kardianos service.Service so callers don't have to
// import kardianos themselves. The wrapped Service is the OS-specific
// thing that knows how to talk to launchd / systemd / Windows SC.
type Service struct {
	svc    service.Service
	prog   *serviceProgram
	cfg    ServiceConfig
}

// NewService builds a Service ready to Install / Uninstall / Start /
// Stop / Status. The `run` callback is what the OS service manager
// invokes when it starts the daemon — typically a Lifecycle.Run.
// Pass nil if you only need install/uninstall (e.g., from the CLI):
// in that case Start-as-service still works via the OS service manager
// invoking the configured ExecPath + Args, but RunAsService will refuse.
func NewService(cfg ServiceConfig, run func(ctx context.Context) error) (*Service, error) {
	if cfg.Name == "" {
		return nil, errors.New("service: Name is required")
	}
	if cfg.ExecPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("service: resolve own executable: %w", err)
		}
		cfg.ExecPath = exe
	}
	if len(cfg.Args) == 0 {
		cfg.Args = []string{"daemon", "run-internal"}
	}

	prog := &serviceProgram{run: run}
	svcCfg := &service.Config{
		Name:        cfg.Name,
		DisplayName: cfg.DisplayName,
		Description: cfg.Description,
		Executable:  cfg.ExecPath,
		Arguments:   cfg.Args,
		Option:      service.KeyValue{},
	}
	// On Linux, kardianos defaults to system services. We force user
	// scope so we never touch /etc/systemd/system or require admin.
	if runtime.GOOS == "linux" {
		svcCfg.Option["UserService"] = true
	}

	svc, err := service.New(prog, svcCfg)
	if err != nil {
		return nil, fmt.Errorf("service: construct: %w", err)
	}
	prog.svc = svc

	return &Service{svc: svc, prog: prog, cfg: cfg}, nil
}

// Install registers the daemon with the host OS service manager.
// Idempotent against repeat installs of the SAME spec; differs from
// re-install with a changed ExecPath (re-Install is required after
// upgrade).
func (s *Service) Install() error {
	if err := s.svc.Install(); err != nil {
		return fmt.Errorf("service install: %w", err)
	}
	return nil
}

// Uninstall removes the OS service registration. Safe to call on a
// not-installed service; returns the underlying error so callers can
// distinguish.
func (s *Service) Uninstall() error {
	if err := s.svc.Uninstall(); err != nil {
		return fmt.Errorf("service uninstall: %w", err)
	}
	return nil
}

// Start asks the OS service manager to start the daemon. This is the
// equivalent of `systemctl --user start audr-daemon`, `launchctl
// kickstart`, or `sc start`. Returns once the service manager has
// accepted the request; the daemon may still be initializing.
func (s *Service) Start() error {
	if err := s.svc.Start(); err != nil {
		return fmt.Errorf("service start: %w", err)
	}
	return nil
}

// Stop asks the OS service manager to stop the daemon. Returns once the
// request is accepted; teardown completes asynchronously.
func (s *Service) Stop() error {
	if err := s.svc.Stop(); err != nil {
		return fmt.Errorf("service stop: %w", err)
	}
	return nil
}

// Status reports the current state of the daemon as the OS service
// manager sees it. Returns one of "running", "stopped",
// "not-installed", or "unknown".
func (s *Service) Status() (string, error) {
	st, err := s.svc.Status()
	if err != nil {
		// kardianos returns errors for both "not installed" and "can't
		// determine". Normalize: ErrNotInstalled becomes the
		// not-installed string.
		if errors.Is(err, service.ErrNotInstalled) {
			return "not-installed", nil
		}
		return "", fmt.Errorf("service status: %w", err)
	}
	switch st {
	case service.StatusRunning:
		return "running", nil
	case service.StatusStopped:
		return "stopped", nil
	default:
		return "unknown", nil
	}
}

// RunAsService blocks running the daemon under the host OS service
// manager. This is the call the `audr daemon run-internal` subcommand
// makes — the OS service manager invokes us with those args, we hand
// control to kardianos, kardianos calls our Start callback, our Start
// callback runs Lifecycle.Run, and we block until the service manager
// asks us to stop.
//
// In interactive mode (running the same subcommand from a terminal),
// kardianos detects it via service.Interactive() and routes
// appropriately — the daemon runs in the foreground attached to the
// terminal, Ctrl-C cancels.
func (s *Service) RunAsService() error {
	if s.prog.run == nil {
		return errors.New("service: RunAsService called without a configured run callback")
	}
	if err := s.svc.Run(); err != nil {
		return fmt.Errorf("service run: %w", err)
	}
	return nil
}

// IsInteractive reports whether the current process appears to be a
// user-launched CLI (true) vs being run by a service manager (false).
// Useful in `audr daemon run-internal` to decide whether to wire up
// signal handling identically — which we always do anyway, but the
// information is useful for telemetry and logging.
func IsInteractive() bool {
	return service.Interactive()
}

// serviceProgram implements kardianos/service.Interface. It bridges the
// service manager's Start/Stop semantics to our Lifecycle.Run model:
// Start spawns a goroutine that calls run(ctx); Stop cancels the
// context and waits up to a short grace period for the run to return.
type serviceProgram struct {
	run    func(ctx context.Context) error
	svc    service.Service
	cancel context.CancelFunc
	done   chan struct{}
}

func (p *serviceProgram) Start(_ service.Service) error {
	// Start MUST NOT block — the service manager expects a quick return.
	// We spawn a goroutine for the actual daemon body.
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan struct{})
	go func() {
		defer close(p.done)
		if err := p.run(ctx); err != nil {
			// Surface to the service manager's log so a failed daemon
			// is visible without grep-ing audr's own log file.
			_, _ = os.Stderr.WriteString("audr daemon: " + err.Error() + "\n")
		}
	}()
	return nil
}

func (p *serviceProgram) Stop(_ service.Service) error {
	if p.cancel == nil {
		return nil
	}
	p.cancel()
	// Bounded wait: we don't want the service manager to hang
	// indefinitely if a subsystem misbehaves.
	select {
	case <-p.done:
	case <-time.After(15 * time.Second):
		return errors.New("audr daemon: stop timed out waiting for subsystems to drain")
	}
	return nil
}
