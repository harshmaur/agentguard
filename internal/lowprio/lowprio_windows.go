//go:build windows

package lowprio

import (
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
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

// applyPostStart applies the IO-priority half of the lowprio pair on
// Windows. The CPU half is handled by applyPreStart (BELOW_NORMAL
// process creation flag). This is the IO-class analogue: lowering
// the process's IO scheduling hint via NtSetInformationProcess so
// the scanner only gets disk time when nothing else is queued.
//
// Maps to Linux's ioprio_set(IOPRIO_CLASS_IDLE) — same shape:
// CPU drop + IO drop. Without this, the CPU drop alone would let a
// disk-bound betterleaks scan thrash the user's IDE / browser IO.
//
// NT internal API surface (not documented as stable but used widely
// since Vista — Process Hacker, Process Explorer, IIS Compression
// Worker, etc.):
//
//	NTSTATUS NtSetInformationProcess(
//	    HANDLE ProcessHandle,
//	    PROCESS_INFORMATION_CLASS ProcessInformationClass,
//	    PVOID ProcessInformation,
//	    ULONG ProcessInformationLength)
//
//	ProcessIoPriority = 33   (the magic class number)
//
//	IO_PRIORITY_HINT enum values:
//	    IoPriorityVeryLow  = 0
//	    IoPriorityLow      = 1  ← what we want (Linux IDLE-class equivalent)
//	    IoPriorityNormal   = 2
//	    IoPriorityHigh     = 3
//	    IoPriorityCritical = 4
//
// Failure is logged-and-skipped per lowprio's documented contract
// ("Failure to apply the priority drop is NOT fatal"). Older Windows
// builds where ProcessIoPriority isn't recognized return
// STATUS_INVALID_PARAMETER — same handling.
func applyPostStart(pid int) {
	if pid <= 0 {
		return
	}
	// We need a PROCESS_SET_INFORMATION handle on the child. The
	// child was created with our access rights via CreateProcess; we
	// have to re-open it explicitly because exec.Cmd.Process.Handle
	// is the limited handle Go retained for Wait().
	const PROCESS_SET_INFORMATION = 0x0200
	hProc, err := windows.OpenProcess(PROCESS_SET_INFORMATION, false, uint32(pid))
	if err != nil {
		return
	}
	defer windows.CloseHandle(hProc)

	const (
		processIoPriority = 33
		ioPriorityLow     = uint32(1) // IoPriorityHintLow
	)

	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	proc := ntdll.NewProc("NtSetInformationProcess")
	// Skip the syscall when ntdll doesn't expose
	// NtSetInformationProcess (e.g. heavily-stripped Server Core
	// images). Find() returns an error in that case; the syscall
	// would panic.
	if err := proc.Find(); err != nil {
		return
	}

	hint := ioPriorityLow
	// NtSetInformationProcess(handle, class, &hint, sizeof(hint))
	// SyscallN return triple: r1=NTSTATUS, r2=unused, lastErr=0
	// when the call dispatched. NTSTATUS 0 = STATUS_SUCCESS; any
	// other value is non-fatal here.
	_, _, _ = proc.Call(
		uintptr(hProc),
		uintptr(processIoPriority),
		uintptr(unsafe.Pointer(&hint)),
		unsafe.Sizeof(hint),
	)
}
