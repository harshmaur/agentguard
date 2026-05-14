//go:build windows

package lowprio

import (
	"os/exec"
	"syscall"
)

// applyPreStart sets the BELOW_NORMAL priority class via Windows
// process creation flags. Per Microsoft docs:
//
//	IDLE_PRIORITY_CLASS          = 0x00000040 (too aggressive — most processes preempt)
//	BELOW_NORMAL_PRIORITY_CLASS  = 0x00004000 (preempted by normal but runs in background)
//
// The spec calls for BELOW_NORMAL; IDLE would starve scans entirely
// during light user activity. BELOW_NORMAL strikes the same balance
// nice 19 + ionice idle does on Linux (lowest practical priority
// that still makes progress).
func applyPreStart(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	const BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
	cmd.SysProcAttr.CreationFlags |= BELOW_NORMAL_PRIORITY_CLASS
}

// applyPostStart is a no-op on Windows — the priority class is set
// at process creation time via SysProcAttr.CreationFlags. No
// additional adjustment needed.
func applyPostStart(_ int) {}
