//go:build !windows

package lowprio

import (
	"os/exec"
	"syscall"
)

// applyPreStart is a no-op on Unix — the priority drop happens after
// Start via setpriority(2). Spawning with a setpriority via the
// parent process doesn't help because the child inherits the
// parent's priority by default; we need to actively reduce it once
// the child PID exists.
func applyPreStart(_ *exec.Cmd) {}

// applyPostStart lowers the child process's scheduling priority.
// Niceness 19 is the lowest non-realtime value (range -20..19);
// the kernel preempts a nice-19 process for any normal-priority
// task, so the user's interactive work never feels the scan.
//
// On Linux, also calls ioprio_set to put the process in the IDLE
// IO class — disk-bound scanners (osv-scanner walking $HOME, dpkg
// reading package metadata) only get IO time when nothing else
// needs the disk. ioprio_set is Linux-specific; macOS doesn't have
// an equivalent in Go's syscall package, so we settle for the
// CPU-priority drop alone there.
//
// Errors are silently ignored: if we can't drop priority for some
// reason (sandbox, permission, missing syscall), the scan still
// runs. The dashboard's perf budget is "should not feel laggy"
// not "must succeed in dropping priority."
func applyPostStart(pid int) {
	// PRIO_PROCESS = 0. Constant not exported by all platforms
	// uniformly so we hardcode it.
	const PRIO_PROCESS = 0
	_ = syscall.Setpriority(PRIO_PROCESS, pid, 19)
	applyIOPriority(pid)
}
