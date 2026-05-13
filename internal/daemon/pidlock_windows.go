//go:build windows

package daemon

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// tryLockFile attempts a non-blocking exclusive lock on f via LockFileEx.
// Windows file locking is mandatory (not advisory like Unix flock), but
// the behavior for our purposes is equivalent: while one process holds
// the lock, no other process can acquire it.
func tryLockFile(f *os.File) error {
	handle := windows.Handle(f.Fd())
	// LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY = non-blocking
	// exclusive lock; ERROR_LOCK_VIOLATION (33) if held by someone else.
	var overlapped windows.Overlapped
	err := windows.LockFileEx(
		handle,
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, // reserved, must be 0
		^uint32(0), ^uint32(0), // lock entire file (low/high DWORDs of length)
		&overlapped,
	)
	if err == nil {
		return nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
		return &AlreadyRunningError{
			Path: f.Name(),
			PID:  readPIDFromFile(f),
		}
	}
	return err
}

func unlockFile(f *os.File) error {
	handle := windows.Handle(f.Fd())
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(handle, 0, ^uint32(0), ^uint32(0), &overlapped)
}
