//go:build windows

package watch

// Windows signal reader: Phase 3 ships the stub (all signals
// unknown → state machine defaults to RUN). The eng-review noted
// GetSystemTimes deltas + GetSystemPowerStatus as the Windows
// signals to wire later; that's v1.1 polish.
func DefaultSignalReader() SignalReader { return stubReader{} }
