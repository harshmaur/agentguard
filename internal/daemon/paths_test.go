package daemon

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolveReturnsOSAppropriatePaths(t *testing.T) {
	p, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.State == "" || p.Logs == "" {
		t.Fatalf("empty paths: %+v", p)
	}
	if !filepath.IsAbs(p.State) {
		t.Errorf("State should be absolute: %q", p.State)
	}
	if !filepath.IsAbs(p.Logs) {
		t.Errorf("Logs should be absolute: %q", p.Logs)
	}

	// Per-OS sanity: the path contains the right OS-conventional segment.
	switch runtime.GOOS {
	case "darwin":
		if !strings.Contains(p.State, filepath.Join("Library", "Application Support", "audr")) {
			t.Errorf("darwin State should live under Library/Application Support/audr: %q", p.State)
		}
		if !strings.Contains(p.Logs, filepath.Join("Library", "Logs", "audr")) {
			t.Errorf("darwin Logs should live under Library/Logs/audr: %q", p.Logs)
		}
	case "windows":
		if !strings.Contains(strings.ToLower(p.State), "audr") {
			t.Errorf("windows State should contain audr: %q", p.State)
		}
	default:
		if !strings.HasSuffix(p.State, filepath.Join("audr")) {
			t.Errorf("linux State should end in audr: %q", p.State)
		}
	}
}

func TestResolveHonorsXDGStateHomeOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("XDG behavior is Linux-only; runtime is %s", runtime.GOOS)
	}
	tmp := t.TempDir()
	t.Setenv("XDG_STATE_HOME", tmp)
	p, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := filepath.Join(tmp, "audr")
	if p.State != want {
		t.Errorf("State = %q, want %q", p.State, want)
	}
	if p.Logs != want {
		t.Errorf("Logs = %q, want %q (XDG state is the canonical home for both on Linux)", p.Logs, want)
	}
}

func TestEnsureCreatesMissingDirsAndIsIdempotent(t *testing.T) {
	tmp := t.TempDir()
	p := Paths{
		State: filepath.Join(tmp, "state"),
		Logs:  filepath.Join(tmp, "logs"),
	}
	if err := p.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	for _, d := range []string{p.State, p.Logs} {
		info, err := os.Stat(d)
		if err != nil {
			t.Fatalf("expected dir %q to exist: %v", d, err)
		}
		if !info.IsDir() {
			t.Fatalf("expected %q to be a dir", d)
		}
		// Mode 0700 only applies on Unix; on Windows the OS may report
		// something else. Skip the mode assertion on Windows.
		if runtime.GOOS != "windows" {
			if mode := info.Mode().Perm(); mode != 0o700 {
				t.Errorf("dir %q mode = %o, want 0700", d, mode)
			}
		}
	}
	// Re-running should be a no-op.
	if err := p.Ensure(); err != nil {
		t.Fatalf("Ensure (second call): %v", err)
	}
}

func TestEnsureErrorsOnEmptyPath(t *testing.T) {
	p := Paths{State: "", Logs: t.TempDir()}
	if err := p.Ensure(); err == nil {
		t.Fatalf("Ensure with empty State should error")
	}
}

func TestPathFileHelpers(t *testing.T) {
	p := Paths{State: "/x", Logs: "/x/logs"}
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"PIDFile", p.PIDFile(), "/x/daemon.pid"},
		{"StateFile", p.StateFile(), "/x/daemon.state"},
		{"LogFile", p.LogFile(), "/x/logs/daemon.log"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.want)
		}
	}
}
