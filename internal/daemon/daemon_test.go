package daemon

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRunHoldsPIDLockAndReleasesOnShutdown(t *testing.T) {
	tmp := t.TempDir()
	p := Paths{
		State: filepath.Join(tmp, "state"),
		Logs:  filepath.Join(tmp, "logs"),
	}

	var logBuf bytes.Buffer
	opts := Options{
		Paths:         p,
		ShutdownGrace: 500 * time.Millisecond,
		LogWriter:     &logBuf,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, opts) }()

	// Wait until the daemon has created the PID file (proxy for "lock
	// acquired + entered the lifecycle wait"). 10s is generous — the
	// happy path takes single-digit ms locally. Previous 2s ceiling
	// tripped reliably on GitHub Actions runners under -race + sidecar
	// probe contention. While polling, drain `done` non-blocking so an
	// early Run() error surfaces as the actual failure instead of a
	// misleading "no PID file" — CI failures (11 in a row before this
	// fix) showed only the timeout message; the underlying reason was
	// invisible. Including the log buffer in the failure message lets
	// the next CI failure tell us what actually broke.
	pidReady := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(p.PIDFile()); err == nil {
			pidReady = true
			break
		}
		select {
		case err := <-done:
			t.Fatalf("Run returned before creating PID file: %v\nlog buffer:\n%s", err, logBuf.String())
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !pidReady {
		t.Fatalf("daemon did not create PID file at %s within 10s\nlog buffer:\n%s",
			p.PIDFile(), logBuf.String())
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run err: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	// PID file removed on graceful shutdown.
	if _, err := os.Stat(p.PIDFile()); !os.IsNotExist(err) {
		t.Errorf("PID file still present after shutdown, stat err = %v", err)
	}
}

func TestRunWithUnresolvableStateDirFailsCleanly(t *testing.T) {
	// State dir set to a path under a non-existent parent that we don't
	// have permission to create. On Linux, /proc/1/zzz reliably fails.
	if runtime.GOOS != "linux" {
		t.Skipf("test relies on /proc/1 unwritability; runtime is %s", runtime.GOOS)
	}
	opts := Options{
		Paths: Paths{
			State: "/proc/1/zzz/state",
			Logs:  "/proc/1/zzz/logs",
		},
		ShutdownGrace: 500 * time.Millisecond,
		LogWriter:     &bytes.Buffer{},
	}
	err := Run(context.Background(), opts)
	if err == nil {
		t.Fatal("expected error for unwritable paths")
	}
	// We don't pin the exact wording — just confirm it's a setup error.
	var already *AlreadyRunningError
	if errors.As(err, &already) {
		t.Errorf("unexpected AlreadyRunningError for setup failure: %v", err)
	}
}

func TestBuildLoggerHonorsExplicitLogWriter(t *testing.T) {
	var buf bytes.Buffer
	opts := Options{
		Paths:     Paths{State: t.TempDir(), Logs: t.TempDir()},
		LogWriter: &buf,
	}
	logger, closer, err := buildLogger(opts)
	if err != nil {
		t.Fatalf("buildLogger: %v", err)
	}
	if logger == nil {
		t.Fatal("logger nil")
	}
	if closer != nil {
		defer closer.Close()
	}
	logger.Info("hello", "k", "v")
	out := buf.String()
	if !strings.Contains(out, "hello") || !strings.Contains(out, `"k":"v"`) {
		t.Errorf("log output missing expected fields: %q", out)
	}
}

func TestBuildLoggerCreatesLogFileWhenNoWriter(t *testing.T) {
	tmp := t.TempDir()
	opts := Options{
		Paths: Paths{
			State: filepath.Join(tmp, "state"),
			Logs:  filepath.Join(tmp, "logs"),
		},
	}
	if err := opts.Paths.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	logger, closer, err := buildLogger(opts)
	if err != nil {
		t.Fatalf("buildLogger: %v", err)
	}
	if closer == nil {
		t.Fatal("closer should be non-nil when writing to file")
	}
	defer closer.Close()

	logger.Info("daemon test event", "phase", 1)

	raw, err := os.ReadFile(opts.Paths.LogFile())
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(raw), "daemon test event") {
		t.Errorf("log file missing event: %q", raw)
	}
}

