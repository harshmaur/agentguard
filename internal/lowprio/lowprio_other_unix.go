//go:build !linux && !darwin && !windows

package lowprio

// applyIOPriority on other Unixes (BSDs) is a no-op. The nice 19
// priority drop in applyPostStart still applies.
func applyIOPriority(_ int) {}
