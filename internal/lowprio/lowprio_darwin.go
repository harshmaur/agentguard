//go:build darwin

package lowprio

// applyIOPriority is a no-op on macOS. Darwin doesn't expose an
// ioprio_set equivalent through Go's syscall package — the closest
// equivalent is taskpolicy / setpriority, but those operate at
// task-class granularity. The nice 19 priority drop from
// lowprio_unix.go's applyPostStart is the practical equivalent for
// our needs (CPU pressure, not IO contention, is the user's
// observed pain point).
func applyIOPriority(_ int) {}
