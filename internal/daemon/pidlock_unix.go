//go:build !windows

package daemon

import (
	"errors"
	"os"
	"syscall"
)

// tryLockFile attempts a non-blocking exclusive flock on f. Returns:
//
//   - nil on success (we now hold the lock)
//   - *AlreadyRunningError if another process holds the lock
//   - some other error for unexpected I/O failures
func tryLockFile(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		return nil
	}
	// EWOULDBLOCK (and EAGAIN, which is the same value on Linux) means
	// the lock is held by another process. Anything else is an I/O
	// surprise we want to surface as-is.
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return &AlreadyRunningError{
			Path: f.Name(),
			PID:  readPIDFromFile(f),
		}
	}
	return err
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
