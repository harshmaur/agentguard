package depscan

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLockfileFingerprint_StableAcrossCalls(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"a"}`)
	writeFile(t, filepath.Join(root, "sub", "go.mod"), "module x\n")

	fp1, err := LockfileFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 == "" {
		t.Fatal("fingerprint empty despite lockfiles present")
	}
	fp2, err := LockfileFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 {
		t.Fatalf("fingerprint not stable across calls: %q vs %q", fp1, fp2)
	}
}

func TestLockfileFingerprint_ChangesOnContentEdit(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "package.json")
	writeFile(t, pkg, `{"name":"a"}`)
	fp1, err := LockfileFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}

	// Both size and mtime should shift after this rewrite. Sleep a tick
	// to defeat filesystems with second-granularity mtime — without it,
	// a write inside the same second leaves the mtime unchanged.
	time.Sleep(20 * time.Millisecond)
	writeFile(t, pkg, `{"name":"a","version":"1"}`)

	fp2, err := LockfileFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 == fp2 {
		t.Fatalf("fingerprint did not change after edit: %q", fp1)
	}
}

func TestLockfileFingerprint_ChangesOnNewLockfile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{}`)
	fp1, err := LockfileFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join(root, "yarn.lock"), "# yarn lockfile\n")
	fp2, err := LockfileFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 == fp2 {
		t.Fatalf("fingerprint did not change after adding yarn.lock")
	}
}

func TestLockfileFingerprint_IgnoresNonLockfiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{}`)
	fp1, err := LockfileFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	// Adding a random text file shouldn't move the fingerprint — the
	// scanner only cares about manifest files.
	writeFile(t, filepath.Join(root, "README.md"), "hi")
	writeFile(t, filepath.Join(root, "src", "index.js"), "console.log(1)")
	fp2, err := LockfileFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 {
		t.Fatalf("non-lockfile additions changed fingerprint: %q → %q", fp1, fp2)
	}
}

func TestLockfileFingerprint_SkipsIgnoredDirs(t *testing.T) {
	// Snapshot the fingerprint before and after dropping a manifest
	// inside an ignored directory. If scanignore's exclusion list is
	// being respected during the walk, the second fingerprint must
	// match the first.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{}`)
	fpBefore, err := LockfileFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join(root, "node_modules", "foo", "package.json"), `{"name":"foo"}`)
	fpAfter, err := LockfileFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	if fpBefore != fpAfter {
		t.Fatalf("node_modules leaked into fingerprint: %q vs %q", fpBefore, fpAfter)
	}
}

func TestLockfileFingerprint_EmptyWhenNoLockfiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "README.md"), "no manifests here")
	fp, err := LockfileFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	if fp != "" {
		t.Fatalf("expected empty fingerprint, got %q", fp)
	}
}

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
