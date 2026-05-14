//go:build linux

package watch

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// linuxSignals reads load avg from /proc/loadavg and battery status
// from /sys/class/power_supply. Both are nearly free to query and
// don't require root.
type linuxSignals struct{}

// DefaultSignalReader returns the per-OS reader. On Linux this hits
// /proc and /sys; on macOS it shells to sysctl/pmset; on Windows it
// returns the stub reader (signals unavailable).
func DefaultSignalReader() SignalReader { return linuxSignals{} }

// LoadAvg returns the 1-minute load average. Format of /proc/loadavg
// is well-known: "<1m> <5m> <15m> <running>/<total> <last-pid>\n".
func (linuxSignals) LoadAvg() (float64, bool) {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, false
	}
	parts := strings.Fields(string(raw))
	if len(parts) < 1 {
		return 0, false
	}
	v, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// OnBattery scans /sys/class/power_supply/* for entries with a
// `status` file (the canonical "this is a battery" marker on Linux)
// and reports whether any such battery's status is "Discharging".
//
// We treat (no battery found) as "ok = false" (the machine is a
// desktop / VM with no power-supply info exposed). The state machine
// then defaults to RUN on the unknown signal.
func (linuxSignals) OnBattery() (bool, bool) {
	const root = "/sys/class/power_supply"
	entries, err := os.ReadDir(root)
	if err != nil {
		// Most VMs / minimal Linux installs have no /sys/class/power_supply.
		// That's not a battery problem; it's an absent signal.
		if errors.Is(err, fs.ErrNotExist) {
			return false, false
		}
		return false, false
	}

	foundBattery := false
	discharging := false
	for _, e := range entries {
		statusFile := filepath.Join(root, e.Name(), "status")
		raw, err := os.ReadFile(statusFile)
		if err != nil {
			// AC adapters have an `online` file, not `status`; skip
			// silently.
			continue
		}
		foundBattery = true
		st := strings.TrimSpace(string(raw))
		// On Linux, Battery.status is one of: Unknown / Charging /
		// Discharging / Not charging / Full. We treat Discharging as
		// the unambiguous "on battery" signal. Charging counts as
		// AC; Full also counts as AC.
		if strings.EqualFold(st, "Discharging") {
			discharging = true
			break
		}
	}
	if !foundBattery {
		return false, false
	}
	return discharging, true
}
