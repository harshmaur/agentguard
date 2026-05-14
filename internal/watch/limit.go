package watch

// InotifyLimit reports the system's inotify watch budget on Linux:
// max watches per user and the current daemon's usage estimate.
// Both fields zero on non-Linux platforms (no inotify, no limit).
//
// The daemon uses this at startup to decide whether to demote the
// less-critical tight watches to poll-only so a popular per-user
// limit (8192 by default on many distros) doesn't get exhausted by
// audr's scope alone.
type InotifyLimit struct {
	// MaxUserWatches is the kernel's fs.inotify.max_user_watches.
	// Zero on non-Linux or when the sysctl can't be read.
	MaxUserWatches int

	// CurrentUsage is the number of inotify watches we've added so
	// far. Approximation: we know how many AddWatch calls succeeded,
	// not how many watches other processes on the same uid hold.
	CurrentUsage int
}

// LimitReader is the per-OS interface. Linux reads
// /proc/sys/fs/inotify/max_user_watches; other OSes return zero.
type LimitReader interface {
	ReadMaxUserWatches() int
}

// DefaultLimitReader returns the per-OS reader. See limit_linux.go.
func DefaultLimitReader() LimitReader { return defaultLimitReader() }
