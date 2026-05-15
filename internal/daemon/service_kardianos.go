//go:build !windows

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

// kardianosBackend wraps kardianos/service for platforms whose
// service manager works naturally with that abstraction:
//
//   - Linux: systemd --user unit at ~/.config/systemd/user/audr-daemon.service
//   - macOS: LaunchAgent at ~/Library/LaunchAgents/com.harshmaur.audr.plist
//   - BSDs: kardianos's per-OS fallback (rcd, openrc, etc.)
//
// Windows deliberately does NOT use kardianos — see service.go for
// the Session 0 / desktop-notification problem that motivated the
// separate schtasks backend.
type kardianosBackend struct {
	svc  service.Service
	prog *serviceProgram
	cfg  ServiceConfig
}

func newServiceBackend(cfg ServiceConfig, run func(ctx context.Context) error) (serviceBackend, error) {
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
	return &kardianosBackend{svc: svc, prog: prog, cfg: cfg}, nil
}

func (b *kardianosBackend) Install() error   { return b.svc.Install() }
func (b *kardianosBackend) Uninstall() error { return b.svc.Uninstall() }
func (b *kardianosBackend) Start() error     { return b.svc.Start() }
func (b *kardianosBackend) Stop() error      { return b.svc.Stop() }

func (b *kardianosBackend) Status() (string, error) {
	st, err := b.svc.Status()
	if err != nil {
		// kardianos returns errors for both "not installed" and "can't
		// determine". Normalize: ErrNotInstalled becomes the
		// not-installed string.
		if errors.Is(err, service.ErrNotInstalled) {
			return "not-installed", nil
		}
		return "", err
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

func (b *kardianosBackend) Run() error {
	if b.prog.run == nil {
		return errors.New("service: RunAsService called without a configured run callback")
	}
	return b.svc.Run()
}

// IsInteractive reports whether the current process appears to be a
// user-launched CLI (true) vs being run by a service manager (false).
// Used in `audr daemon run-internal` to decide whether to wire up
// signal handling identically — which we always do anyway, but the
// information is useful for telemetry and logging.
//
// On Linux/macOS this is service.Interactive() from kardianos (checks
// if stdin is a TTY + a few OS-specific heuristics). On Windows the
// schtasks backend has its own implementation in service_windows.go.
func IsInteractive() bool {
	return service.Interactive()
}

// serviceProgram implements kardianos/service.Interface. It bridges the
// service manager's Start/Stop semantics to our Lifecycle.Run model:
// Start spawns a goroutine that calls run(ctx); Stop cancels the
// context and waits up to a short grace period for the run to return.
//
// Windows note: serviceProgram is unused on Windows — that build uses
// the schtasks backend in service_windows.go which does its own
// signal-driven run.
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
