//go:build !linux && !darwin && !windows

package main

// preflightNotifications is a no-op on BSDs, Solaris, and other
// non-mainline targets. Each mainline platform has its own preflight
// file: notify_preflight_linux.go, notify_preflight_darwin.go,
// notify_preflight_windows.go. Returns empty slice so the --test
// command behaves identically on un-instrumented platforms.
func preflightNotifications() []string {
	return nil
}
