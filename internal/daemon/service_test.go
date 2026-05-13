package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDefaultServiceConfigHasSaneValues(t *testing.T) {
	c := DefaultServiceConfig()
	if c.Name == "" {
		t.Error("Name empty")
	}
	if c.DisplayName == "" {
		t.Error("DisplayName empty")
	}
	if c.Description == "" {
		t.Error("Description empty")
	}
	if len(c.Args) == 0 {
		t.Error("Args empty")
	}
	if c.Args[0] != "daemon" {
		t.Errorf("Args[0] = %q, want %q", c.Args[0], "daemon")
	}
	// The hidden-subcommand convention is essential; assert it.
	if !contains(strings.Join(c.Args, " "), "run-internal") {
		t.Errorf("Args do not include the run-internal subcommand: %v", c.Args)
	}
}

func TestNewServiceRejectsEmptyName(t *testing.T) {
	cfg := DefaultServiceConfig()
	cfg.Name = ""
	_, err := NewService(cfg, func(context.Context) error { return nil })
	if err == nil {
		t.Fatal("expected error for empty Name")
	}
	if !contains(err.Error(), "Name") {
		t.Errorf("err = %v, want it to mention Name", err)
	}
}

func TestRunAsServiceRefusesWithoutCallback(t *testing.T) {
	cfg := DefaultServiceConfig()
	s, err := NewService(cfg, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	err = s.RunAsService()
	if err == nil {
		t.Fatal("expected error when run callback is nil")
	}
	if !contains(err.Error(), "without a configured run callback") {
		t.Errorf("err = %v, want it to mention missing callback", err)
	}
}

func TestNewServiceResolvesOwnExecutable(t *testing.T) {
	cfg := DefaultServiceConfig()
	cfg.ExecPath = "" // force auto-resolution
	s, err := NewService(cfg, func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if s.cfg.ExecPath == "" {
		t.Fatal("NewService did not resolve ExecPath")
	}
	// Tests run under the `go test` binary, so the resolved exec path
	// should at least exist. Don't assert exact contents (varies per OS).
}

func TestIsInteractiveReturnsBool(t *testing.T) {
	// We can't deterministically assert true/false because the test
	// binary runs interactively under `go test`. Just ensure the
	// call doesn't panic and returns a usable bool.
	_ = IsInteractive()
}

// errFakeRun is the sentinel a fake run callback returns when called,
// proving the callback is in the call chain (used by service_test).
var errFakeRun = errors.New("fake run was called")
