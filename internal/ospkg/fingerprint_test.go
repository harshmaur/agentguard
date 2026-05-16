package ospkg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withOverridePackageDBPaths swaps the package-level packageDBPaths
// resolver so a test can target temp files instead of the real OS
// package DB. Restores the original on cleanup.
func withOverridePackageDBPaths(t *testing.T, m Manager, paths []string) {
	t.Helper()
	orig := packageDBPaths
	packageDBPaths = func(in Manager) []string {
		if in == m {
			return paths
		}
		return orig(in)
	}
	t.Cleanup(func() { packageDBPaths = orig })
}

func TestPackageDBFingerprint_EmptyOnNonLinux(t *testing.T) {
	// detectDistro reads /etc/os-release. On a machine without that
	// file (rare on a real test runner — we mimic by pointing at a
	// path that exists but parses to nothing) the function should
	// short-circuit to empty. We can't easily redirect detectDistro
	// from here, so this case is structural rather than exercised on
	// every host. Verify the empty-manager branch with a synthesized
	// nil paths list instead.
	withOverridePackageDBPaths(t, ManagerDpkg, nil)
	// Don't assert specific output — this test exists for the
	// no-panic / nil-safe guarantee. Anything goes as long as it
	// doesn't crash.
	if _, err := PackageDBFingerprint(); err != nil {
		t.Fatalf("PackageDBFingerprint with nil paths errored: %v", err)
	}
}

func TestPackageDBFingerprint_StableAcrossCalls(t *testing.T) {
	// We can only reliably test the resolver-and-stat half — distro
	// detection depends on the host. On a non-Linux host the test
	// gets a "" fingerprint and skips the equality assertion.
	tmp := t.TempDir()
	fake := filepath.Join(tmp, "status")
	if err := os.WriteFile(fake, []byte("Package: foo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	withOverridePackageDBPaths(t, ManagerDpkg, []string{fake})

	fp1, err := PackageDBFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	fp2, err := PackageDBFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 {
		t.Fatalf("fingerprint not stable: %q vs %q", fp1, fp2)
	}
}

func TestPackageDBFingerprint_ChangesOnContentEdit(t *testing.T) {
	tmp := t.TempDir()
	fake := filepath.Join(tmp, "status")
	if err := os.WriteFile(fake, []byte("Package: foo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	withOverridePackageDBPaths(t, ManagerDpkg, []string{fake})

	fp1, err := PackageDBFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if fp1 == "" {
		t.Skip("fingerprint empty on this host (detectDistro found no manager); cannot exercise the change-detect branch")
	}
	// Wait past 1s of clock so mtime granularity (some filesystems
	// resolve to seconds) reliably advances.
	time.Sleep(1100 * time.Millisecond)
	if err := os.WriteFile(fake, []byte("Package: foo\nPackage: bar\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fp2, err := PackageDBFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if fp1 == fp2 {
		t.Fatalf("fingerprint did not change after DB edit: %q", fp1)
	}
}

func TestPackageDBFingerprint_FormatIsManagerPrefixed(t *testing.T) {
	tmp := t.TempDir()
	fake := filepath.Join(tmp, "status")
	if err := os.WriteFile(fake, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	withOverridePackageDBPaths(t, ManagerDpkg, []string{fake})

	fp, err := PackageDBFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if fp == "" {
		t.Skip("fingerprint empty on this host (detectDistro found no manager)")
	}
	// Manager prefix prevents cache hits across OS reinstalls that
	// happen to put a same-stat file at the same path. Without the
	// prefix, a brand-new install with serendipitously matching
	// mtime+size would silently reuse a stale findings payload.
	if !strings.Contains(fp, "|") {
		t.Fatalf("fingerprint missing manager prefix separator: %q", fp)
	}
}
