package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// ServiceConfig captures the per-install knobs for the daemon's OS-level
// service entry. Mostly stable values; exposed as a struct so tests can
// override.
type ServiceConfig struct {
	// Name is the OS-level service identifier ("audr-daemon"). This is
	// what shows up in `systemctl --user list-units`, `launchctl list`,
	// `schtasks /Query`, etc. Must be filesystem-safe.
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

// Service is the public face of the daemon's OS-level service entry.
// Methods are routed through a per-OS backend:
//
//   - Linux / macOS / BSD: kardianos/service (LaunchAgent / systemd --user)
//   - Windows: Scheduled Task at user logon via schtasks.exe shell-out
//
// The Windows split exists because kardianos's Windows backend uses
// the Service Control Manager, which lives in Session 0 — the
// "non-interactive desktop" Microsoft introduced in Vista. A process
// running in Session 0 cannot deliver toast notifications to the
// user's desktop, which breaks audr's click-to-open contract. A
// per-user Scheduled Task runs in the user's logon session and
// reaches the desktop normally.
type Service struct {
	cfg     ServiceConfig
	backend serviceBackend
}

// serviceBackend is the per-OS install/lifecycle surface the
// platform-specific files (service_kardianos.go, service_windows.go)
// implement. Methods mirror Service's public API; Service.Method just
// dispatches.
//
// Status returns one of: "running", "stopped", "not-installed",
// "unknown". Run executes the daemon's main loop under the backend's
// service-manager protocol (or, for the schtasks backend, just calls
// the run callback with signal-aware ctx).
type serviceBackend interface {
	Install() error
	Uninstall() error
	Start() error
	Stop() error
	Status() (string, error)
	Run() error
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

	backend, err := newServiceBackend(cfg, run)
	if err != nil {
		return nil, err
	}
	return &Service{cfg: cfg, backend: backend}, nil
}

// Install registers the daemon with the host OS service manager.
// Idempotent against repeat installs of the SAME spec; differs from
// re-install with a changed ExecPath (re-Install is required after
// upgrade).
func (s *Service) Install() error {
	if err := s.backend.Install(); err != nil {
		return fmt.Errorf("service install: %w", err)
	}
	return nil
}

// Uninstall removes the OS service registration. Safe to call on a
// not-installed service; the backend translates "not installed" into
// either a successful no-op or a typed error the caller can branch on.
func (s *Service) Uninstall() error {
	if err := s.backend.Uninstall(); err != nil {
		return fmt.Errorf("service uninstall: %w", err)
	}
	return nil
}

// Start asks the OS service manager to start the daemon. This is the
// equivalent of `systemctl --user start audr-daemon`, `launchctl
// kickstart`, or `schtasks /Run`. Returns once the service manager
// has accepted the request; the daemon may still be initializing.
func (s *Service) Start() error {
	if err := s.backend.Start(); err != nil {
		return fmt.Errorf("service start: %w", err)
	}
	return nil
}

// Stop asks the OS service manager to stop the daemon. Returns once the
// request is accepted; teardown completes asynchronously.
func (s *Service) Stop() error {
	if err := s.backend.Stop(); err != nil {
		return fmt.Errorf("service stop: %w", err)
	}
	return nil
}

// Status reports the current state of the daemon as the OS service
// manager sees it. Returns one of "running", "stopped",
// "not-installed", or "unknown".
func (s *Service) Status() (string, error) {
	return s.backend.Status()
}

// RunAsService blocks running the daemon under the host OS service
// manager. This is the call the `audr daemon run-internal` subcommand
// makes — the OS service manager invokes us with those args, we hand
// control to the backend, the backend invokes the configured run
// callback, and we block until the service manager asks us to stop.
//
// On Linux/macOS the backend is kardianos and the service-manager
// protocol routes Start/Stop callbacks through serviceProgram. On
// Windows under a Scheduled Task there is no service-manager
// protocol — the task simply spawns us as a user process. The
// Windows backend's Run wires signal handling so a `schtasks /End`
// (which sends CTRL_BREAK_EVENT) cleanly cancels the run-context.
func (s *Service) RunAsService() error {
	if err := s.backend.Run(); err != nil {
		return fmt.Errorf("service run: %w", err)
	}
	return nil
}
