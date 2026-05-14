//go:build linux

package lowprio

import "syscall"

// applyIOPriority calls ioprio_set(IOPRIO_CLASS_IDLE) on pid. The
// idle class only schedules disk IO when no other class has work
// pending — perfect for background scanners walking $HOME while
// the user's IDE is reading files normally.
//
// Constants per linux/ioprio.h:
//
//	#define IOPRIO_CLASS_IDLE 3
//	#define IOPRIO_WHO_PROCESS 1
//	#define IOPRIO_PRIO_VALUE(class, data) (((class) << 13) | (data))
//
// syscall number 251 = ioprio_set on x86_64 / arm64 (Linux ABI).
func applyIOPriority(pid int) {
	const (
		IOPRIO_CLASS_IDLE   = 3
		IOPRIO_WHO_PROCESS  = 1
		SYS_IOPRIO_SET      = 251
	)
	// IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0) = (3 << 13) | 0
	val := IOPRIO_CLASS_IDLE << 13
	_, _, _ = syscall.Syscall(SYS_IOPRIO_SET, uintptr(IOPRIO_WHO_PROCESS), uintptr(pid), uintptr(val))
}
