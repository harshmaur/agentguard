//go:build !linux

package watch

// macOS + Windows: no inotify equivalent, so no user-watch budget
// for audr to manage. The limit-aware fallback code paths are no-ops
// here.

type otherLimitReader struct{}

func defaultLimitReader() LimitReader { return otherLimitReader{} }

func (otherLimitReader) ReadMaxUserWatches() int { return 0 }
