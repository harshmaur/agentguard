package daemon

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// PIDLock holds an exclusive OS-level lock on the daemon's PID file. The
// underlying file descriptor lives inside the lock; releasing happens via
// Release(), typically deferred from the caller.
//
// Two layers of safety:
//
//  1. flock (Unix) / LockFileEx (Windows) holds an exclusive advisory
//     lock on the open fd. While this process lives, no other process
//     can acquire the lock.
//  2. The file contents are the PID of the holding process. On startup,
//     if the lock is held, we read the PID and surface "another daemon
//     is running, pid=N" to the user. If the lock is NOT held (e.g.,
//     after kill -9), we claim it cleanly even though a stale PID may
//     still be in the file.
//
// This handles the three real-world scenarios:
//
//   - graceful shutdown: Release() removes the file (best-effort).
//   - kill -9: file remains, but the OS releases the fd lock; next start
//     re-acquires cleanly.
//   - concurrent install: only one daemon ever holds the lock.
type PIDLock struct {
	path string
	file *os.File
}

// AcquirePIDLock takes the daemon's exclusive lock at path. Returns:
//
//   - (*PIDLock, nil)            — lock acquired; daemon may run
//   - (nil, *AlreadyRunningError) — another daemon holds the lock
//   - (nil, err)                 — IO error (permission, missing dir, etc.)
//
// The caller MUST defer pidLock.Release() so the lock is freed on exit
// (graceful or panic).
func AcquirePIDLock(path string) (*PIDLock, error) {
	// Open with O_CREATE so the first daemon ever doesn't need pre-seed.
	// O_RDWR so we can both read the stale PID (on contention) and
	// rewrite our own PID after acquiring.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("pidlock: open %s: %w", path, err)
	}

	if err := tryLockFile(f); err != nil {
		// Another process holds the lock. Read its PID for the error.
		var alreadyRunning *AlreadyRunningError
		if errors.As(err, &alreadyRunning) {
			// tryLockFile already populated path + read the file; we
			// just need to release our open handle before returning.
			_ = f.Close()
			return nil, alreadyRunning
		}
		_ = f.Close()
		return nil, fmt.Errorf("pidlock: lock %s: %w", path, err)
	}

	// We hold the lock. Truncate any stale content and write our PID.
	if err := f.Truncate(0); err != nil {
		_ = unlockFile(f)
		_ = f.Close()
		return nil, fmt.Errorf("pidlock: truncate %s: %w", path, err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		_ = unlockFile(f)
		_ = f.Close()
		return nil, fmt.Errorf("pidlock: seek %s: %w", path, err)
	}
	if _, err := fmt.Fprintf(f, "%d\n", os.Getpid()); err != nil {
		_ = unlockFile(f)
		_ = f.Close()
		return nil, fmt.Errorf("pidlock: write %s: %w", path, err)
	}
	// Sync so a crash after this point still leaves a readable PID for
	// the next start's contention message.
	_ = f.Sync()

	return &PIDLock{path: path, file: f}, nil
}

// Release frees the lock and removes the PID file IF and only if the
// file's contents still match our own PID. Safe to call multiple
// times. Best-effort on file removal: failures are silent — the lock
// is what matters, not the file.
//
// The PID-match check prevents a stale daemon's Release() from
// clobbering a fresh daemon's lock file. Observed in the wild on
// 2026-05-14: a stale `/tmp/audr` daemon (whose lock somehow got
// lost) was killed via SIGTERM, its deferred Release ran, and
// os.Remove(path) deleted the live daemon's PID file out from under
// it. The live daemon's flock survived (kernel keeps the fd-based
// lock until the live process dies), but `audr daemon status` and
// any future PID lookup broke.
func (p *PIDLock) Release() {
	if p == nil || p.file == nil {
		return
	}
	_ = unlockFile(p.file)
	_ = p.file.Close()
	if p.fileMatchesOurPID() {
		_ = os.Remove(p.path)
	}
	p.file = nil
}

// fileMatchesOurPID returns true when the file at p.path contains
// our own process's PID. Used by Release to avoid unlinking another
// daemon's lock file. A missing file (already removed) returns
// false — nothing to unlink.
func (p *PIDLock) fileMatchesOurPID() bool {
	b, err := os.ReadFile(p.path)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return false
	}
	return pid == os.Getpid()
}

// PID returns the PID written into the file. Useful for `audr daemon
// status`.
func (p *PIDLock) PID() int { return os.Getpid() }

// AlreadyRunningError reports that another audr daemon already holds the
// PID lock. It carries the stale-file PID and path so the CLI can print
// a helpful message: "another audr daemon is already running (pid=1234)".
type AlreadyRunningError struct {
	Path string
	PID  int // 0 if the file existed but couldn't be parsed
}

func (e *AlreadyRunningError) Error() string {
	if e.PID > 0 {
		return fmt.Sprintf("another audr daemon is already running (pid=%d, lock=%s)", e.PID, e.Path)
	}
	return fmt.Sprintf("another audr daemon is already running (lock=%s)", e.Path)
}

// readPIDFromFile reads "12345\n" from f and returns 12345. Returns 0 on
// any parse error — the caller surfaces "unknown PID" rather than crashing.
// Used by tryLockFile on the failure branch.
func readPIDFromFile(f *os.File) int {
	if _, err := f.Seek(0, 0); err != nil {
		return 0
	}
	buf := make([]byte, 32)
	n, _ := f.Read(buf)
	if n == 0 {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(buf[:n])))
	if err != nil {
		return 0
	}
	return pid
}
