package daemon

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPIDLockAcquireWritesPID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.pid")
	lock, err := AcquirePIDLock(path)
	if err != nil {
		t.Fatalf("AcquirePIDLock: %v", err)
	}
	defer lock.Release()

	if lock.PID() != os.Getpid() {
		t.Errorf("lock.PID() = %d, want %d", lock.PID(), os.Getpid())
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pid file: %v", err)
	}
	got, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("parse pid file %q: %v", raw, err)
	}
	if got != os.Getpid() {
		t.Errorf("pid file contains %d, want %d", got, os.Getpid())
	}
}

func TestPIDLockReleaseRemovesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.pid")
	lock, err := AcquirePIDLock(path)
	if err != nil {
		t.Fatalf("AcquirePIDLock: %v", err)
	}
	lock.Release()

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected pid file removed after Release; stat err = %v", err)
	}

	// Release is idempotent: calling it again must not panic.
	lock.Release()
}

// TestPIDLockReleaseLeavesOtherDaemonsLockFileAlone is a regression
// test for the 2026-05-14 observation: a stale daemon's Release()
// can nuke a live daemon's PID file when both have raced to claim
// the same path (path-vs-inode flock race).
//
// Scenario: process A acquires the lock at path /tmp/daemon.pid and
// writes its own PID. Later, somehow process B also claims the lock
// at the same path (different inode after a delete/recreate, or
// some other path-replacement race) and writes B's PID. When A then
// gracefully exits and calls Release(), it must NOT unlink the file
// because the file now belongs to B.
//
// The test simulates this by:
//   1. A acquires the lock + writes its PID
//   2. Manually overwrite the file with a foreign PID (e.g., PID 1)
//   3. A.Release()
//   4. Assert the file still exists (Release should have noticed the
//      mismatch and left it alone)
func TestPIDLockReleaseLeavesOtherDaemonsLockFileAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.pid")
	lockA, err := AcquirePIDLock(path)
	if err != nil {
		t.Fatalf("AcquirePIDLock A: %v", err)
	}
	// Simulate a concurrent daemon B writing its own PID over the
	// file. (Use PID 1 — guaranteed to exist on Unix; won't match
	// the test's PID.)
	if err := os.WriteFile(path, []byte("1\n"), 0o600); err != nil {
		t.Fatalf("simulate foreign PID: %v", err)
	}

	lockA.Release()

	if _, err := os.Stat(path); err != nil {
		t.Errorf("Release deleted foreign-PID file (should have left it alone): %v", err)
	}
	// And the file still contains B's PID, not removed/truncated.
	b, _ := os.ReadFile(path)
	if got := strings.TrimSpace(string(b)); got != "1" {
		t.Errorf("foreign PID file mutated by Release: %q (want %q)", got, "1")
	}
}

func TestPIDLockSecondAcquireFailsWithAlreadyRunning(t *testing.T) {
	// We can't acquire the same lock twice from the same process — flock
	// is per-process on Linux (the second call would succeed!) — so test
	// contention from a child process instead.
	path := filepath.Join(t.TempDir(), "daemon.pid")

	// Start a child that acquires the lock and sleeps until killed.
	helper := buildPIDLockHelper(t)
	child := exec.Command(helper, path)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if err := child.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})

	// Wait for the child to signal "lock acquired" by writing a line.
	buf := make([]byte, 32)
	n, err := stdout.Read(buf)
	if err != nil || n == 0 {
		t.Fatalf("child did not signal ready: n=%d err=%v", n, err)
	}
	if !strings.HasPrefix(string(buf[:n]), "ready") {
		t.Fatalf("unexpected child ready line: %q", buf[:n])
	}

	// Now the parent attempts to acquire — expect AlreadyRunningError.
	if _, err := AcquirePIDLock(path); err == nil {
		t.Fatalf("expected AlreadyRunningError, got nil")
	} else {
		var already *AlreadyRunningError
		if !errors.As(err, &already) {
			t.Fatalf("expected *AlreadyRunningError, got %T: %v", err, err)
		}
		if already.PID <= 0 {
			t.Errorf("AlreadyRunningError PID = %d, want >0", already.PID)
		}
		if already.PID != child.Process.Pid {
			t.Errorf("AlreadyRunningError PID = %d, want child PID %d", already.PID, child.Process.Pid)
		}
		if already.Path != path {
			t.Errorf("AlreadyRunningError Path = %q, want %q", already.Path, path)
		}
	}
}

func TestPIDLockReclaimAfterStaleFile(t *testing.T) {
	// Simulate kill -9: write a stale PID, no lock held. AcquirePIDLock
	// should successfully claim the lock and overwrite the stale PID.
	path := filepath.Join(t.TempDir(), "daemon.pid")
	if err := os.WriteFile(path, []byte("999999\n"), 0o600); err != nil {
		t.Fatalf("seed stale pid: %v", err)
	}
	lock, err := AcquirePIDLock(path)
	if err != nil {
		t.Fatalf("AcquirePIDLock after stale file: %v", err)
	}
	defer lock.Release()

	raw, _ := os.ReadFile(path)
	got, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	if got != os.Getpid() {
		t.Errorf("pid file = %d, want our pid %d", got, os.Getpid())
	}
}

// buildPIDLockHelper builds a tiny helper binary that acquires the PID lock
// and blocks. It lives in a sibling test main package below.
func buildPIDLockHelper(t *testing.T) string {
	t.Helper()
	src := filepath.Join("testdata", "pidlock_helper", "main.go")
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("helper source missing at %s: %v", src, err)
	}
	bin := filepath.Join(t.TempDir(), "pidlock_helper")
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/pidlock_helper")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build helper: %v", err)
	}
	return bin
}
