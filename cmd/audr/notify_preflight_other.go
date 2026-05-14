//go:build !linux && !darwin

package main

// preflightNotifications is a no-op on platforms we haven't yet
// written preflight detection for (Windows + BSDs). Returns empty
// slice so the test command behaves identically to pre-v0.5.8 on
// those platforms — fires the toast, prints success or error.
//
// Windows-specific checks (Focus Assist, AppUserModelID
// registration) can land here when we have a tested example.
func preflightNotifications() []string {
	return nil
}
