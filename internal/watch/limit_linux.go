//go:build linux

package watch

import (
	"os"
	"strconv"
	"strings"
)

type linuxLimitReader struct{}

func defaultLimitReader() LimitReader { return linuxLimitReader{} }

// ReadMaxUserWatches reads /proc/sys/fs/inotify/max_user_watches.
// Returns 0 if the file can't be read OR parsed — the daemon then
// treats the budget as "unknown" and doesn't preemptively demote
// watches.
func (linuxLimitReader) ReadMaxUserWatches() int {
	raw, err := os.ReadFile("/proc/sys/fs/inotify/max_user_watches")
	if err != nil {
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0
	}
	return v
}
