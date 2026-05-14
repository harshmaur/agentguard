//go:build !linux

package runtimeenv

// collectLinuxSignals is a no-op on non-Linux platforms. macOS and Windows
// detection comes from gopsutil; the /proc-based supplementary signals
// don't apply.
func collectLinuxSignals() []signal { return nil }
