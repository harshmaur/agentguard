// Package lowprio runs child processes at low scheduling priority so
// the daemon's sidecar scans (Betterleaks, OSV-Scanner, dpkg-query)
// don't compete with the user's interactive work for CPU + IO.
//
// Per the v1 design spec:
//
//	"First-run is a deep sweep that surfaces every pre-existing issue,
//	runs for hours if needed, but never hogs the laptop (nice -n 19
//	+ ionice -c idle on Linux/macOS, BELOW_NORMAL on Windows, plus
//	GOMAXPROCS=1 for OSV-Scanner shells)."
//
// Observed in the wild 2026-05-14: the legacy secret scanner at 80% CPU + OSV-Scanner
// at 56% CPU during a first-run scan against $HOME. The user couldn't
// use their machine while the scan ran.
//
// What this package does:
//
//   - Run(ctx, name, args) starts the named binary at nice 19
//     (lowest non-realtime priority). The OS scheduler preempts it
//     instantly for any normal-priority task — interactive work stays
//     snappy even while a long scan runs.
//   - On Linux, additionally lowers the IO scheduling class via
//     ioprio_set(IOPRIO_CLASS_IDLE) so disk-bound scanners don't
//     contend with the user's open IDE / browser.
//   - On Windows, sets PROCESS_PRIORITY_CLASS to BELOW_NORMAL.
//
// Idle scanning means scans take longer in absolute terms — that's
// the trade. The spec accepts this explicitly: "Hours acceptable;
// resource hogging is not."
package lowprio

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// Runner wraps exec.Command with low-priority setup. Its Run method
// has the same signature as the CommandRunner interfaces used by
// secretscan / depscan / ospkg so it slots in as a drop-in
// replacement for execRunner.
type Runner struct{}

// Run executes name with args under low CPU + IO priority and
// returns the process's stdout. Stderr is captured and folded into
// the returned error on failure. ctx cancellation kills the child.
//
// Priority drop policy by OS:
//   - Linux: nice 19 (via SysProcAttr.Setpriority equivalent) plus
//     ioprio_set IDLE post-start (defined in lowprio_linux.go).
//   - macOS: nice 19 via setpriority(2) post-start.
//   - Windows: BELOW_NORMAL_PRIORITY_CLASS via creation flags
//     (defined in lowprio_windows.go).
//
// Failure to apply the priority drop is NOT fatal — the scan still
// runs at default priority. We don't bubble these errors up because
// the user-facing concern is "the scan ran, did it find anything?",
// not "did the priority adjustment succeed?".
func (Runner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// applyPreStart is per-OS — sets SysProcAttr fields the OS uses
	// when spawning the process (Linux: nothing today; Windows:
	// CREATE_BELOW_NORMAL_PRIORITY_CLASS).
	applyPreStart(cmd)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("lowprio: start %s: %w", name, err)
	}
	// Post-start adjustments where the PID is available. Linux uses
	// this to call setpriority(PRIO_PROCESS, pid, 19) and the
	// ioprio_set syscall. macOS uses it for setpriority only.
	if cmd.Process != nil {
		applyPostStart(cmd.Process.Pid)
	}
	if err := cmd.Wait(); err != nil {
		return stdout.Bytes(), formatErr(name, err, stderr.Bytes())
	}
	return stdout.Bytes(), nil
}

func formatErr(name string, err error, stderr []byte) error {
	if len(stderr) == 0 {
		return fmt.Errorf("%s: %w", name, err)
	}
	const maxStderr = 4 << 10
	if len(stderr) > maxStderr {
		stderr = append(stderr[:maxStderr], []byte("... [truncated]")...)
	}
	return fmt.Errorf("%s: %w: %s", name, err, bytes.TrimSpace(stderr))
}
