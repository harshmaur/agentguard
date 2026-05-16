package daemon

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestAugmentPATHPrependsLinuxbrew is the regression test for the
// 2026-05-14 observation: user installed a secret scanner via Linuxbrew,
// daemon kept reporting "secrets: unavailable" because systemd-user
// stripped /home/linuxbrew/.linuxbrew/bin from the daemon's PATH.
//
// The test creates a fake Linuxbrew directory under t.TempDir, sets
// PATH to a minimal /usr/bin only, runs AugmentPATH, and asserts
// the fake Linuxbrew dir got prepended. Uses temp dirs so the test
// is hermetic regardless of which package managers exist on the
// CI runner.
//
// Skipped on Windows (PATH semantics + locations are different).
func TestAugmentPATHPrependsKnownLocations(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("AugmentPATH is a no-op on Windows")
	}
	tmp := t.TempDir()
	fakeHome := filepath.Join(tmp, "home")
	fakeLinuxbrew := filepath.Join(fakeHome, ".linuxbrew", "bin")
	if err := os.MkdirAll(fakeLinuxbrew, 0o755); err != nil {
		t.Fatalf("mkdir fake linuxbrew: %v", err)
	}

	origPath := os.Getenv("PATH")
	origHome := os.Getenv("HOME")
	t.Cleanup(func() {
		_ = os.Setenv("PATH", origPath)
		_ = os.Setenv("HOME", origHome)
	})
	_ = os.Setenv("HOME", fakeHome)
	_ = os.Setenv("PATH", "/usr/bin:/bin")

	AugmentPATH()

	newPath := os.Getenv("PATH")
	if !strings.Contains(newPath, fakeLinuxbrew) {
		t.Errorf("PATH does not contain fake Linuxbrew (%s):\n  PATH=%s", fakeLinuxbrew, newPath)
	}
	// The user's original PATH entries must still be present.
	if !strings.Contains(newPath, "/usr/bin") {
		t.Errorf("PATH lost original entries: %s", newPath)
	}
}

// TestAugmentPATHIdempotent verifies a second call doesn't duplicate
// entries — important because the daemon may call this multiple
// times across restart cycles or unit-test invocations.
func TestAugmentPATHIdempotent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("AugmentPATH is a no-op on Windows")
	}
	tmp := t.TempDir()
	fakeHome := filepath.Join(tmp, "home")
	cargoBin := filepath.Join(fakeHome, ".cargo", "bin")
	if err := os.MkdirAll(cargoBin, 0o755); err != nil {
		t.Fatalf("mkdir fake cargo: %v", err)
	}

	origPath := os.Getenv("PATH")
	origHome := os.Getenv("HOME")
	t.Cleanup(func() {
		_ = os.Setenv("PATH", origPath)
		_ = os.Setenv("HOME", origHome)
	})
	_ = os.Setenv("HOME", fakeHome)
	_ = os.Setenv("PATH", "/usr/bin")

	AugmentPATH()
	firstPath := os.Getenv("PATH")
	AugmentPATH()
	secondPath := os.Getenv("PATH")

	if firstPath != secondPath {
		t.Errorf("AugmentPATH not idempotent:\n  first:  %s\n  second: %s", firstPath, secondPath)
	}
	// And cargo bin appears exactly once.
	if c := strings.Count(secondPath, cargoBin); c != 1 {
		t.Errorf("cargo bin appears %d times, want 1: %s", c, secondPath)
	}
}

// TestAugmentPATHSkipsMissingDirs verifies non-existent candidate
// paths are silently skipped — we shouldn't add bogus entries to
// PATH just because the candidate list mentions them.
//
// Tests only the $HOME-anchored candidates (~/.cargo/bin, etc.)
// because system-wide locations (/home/linuxbrew/.linuxbrew/bin)
// may genuinely exist on the test machine and we don't want the
// test failing based on the host's package-manager layout.
func TestAugmentPATHSkipsMissingDirs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("AugmentPATH is a no-op on Windows")
	}
	origPath := os.Getenv("PATH")
	origHome := os.Getenv("HOME")
	t.Cleanup(func() {
		_ = os.Setenv("PATH", origPath)
		_ = os.Setenv("HOME", origHome)
	})
	fakeHome := t.TempDir()
	_ = os.Setenv("HOME", fakeHome)
	_ = os.Setenv("PATH", "/usr/bin")

	AugmentPATH()

	newPath := os.Getenv("PATH")
	// $HOME-anchored candidates that don't exist must NOT appear.
	// (Use the absolute path with fakeHome so we don't accidentally
	// match a real ~/.cargo/bin on the runner.)
	for _, abs := range []string{
		filepath.Join(fakeHome, ".cargo", "bin"),
		filepath.Join(fakeHome, ".linuxbrew", "bin"),
		filepath.Join(fakeHome, "go", "bin"),
		filepath.Join(fakeHome, ".local", "bin"),
	} {
		if strings.Contains(newPath, abs) {
			t.Errorf("PATH unexpectedly contains missing %s: %s", abs, newPath)
		}
	}
}
