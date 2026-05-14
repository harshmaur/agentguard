//go:build darwin

package watch

import (
	"os/exec"
	"strconv"
	"strings"
)

// darwinSignals reads load avg from `sysctl vm.loadavg` and battery
// state from `pmset -g batt`. Both are shell-out costs (~2-3ms each),
// fine at the 5s sample cadence.
type darwinSignals struct{}

func DefaultSignalReader() SignalReader { return darwinSignals{} }

// LoadAvg parses `sysctl -n vm.loadavg` output, which on macOS prints
// "{ 1.23 0.98 0.76 }". We extract the first number.
func (darwinSignals) LoadAvg() (float64, bool) {
	out, err := exec.Command("sysctl", "-n", "vm.loadavg").Output()
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(out))
	// Strip the literal braces if present.
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	parts := strings.Fields(s)
	if len(parts) < 1 {
		return 0, false
	}
	v, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// OnBattery parses `pmset -g batt`. Output starts with one of two
// lines:
//
//   Now drawing from 'AC Power'
//   Now drawing from 'Battery Power'
//
// We match the literal substring "Battery Power". Anything else
// (including the AC Power case, and weird states like "InternalBattery
// not present") reports "false, false" — unknown signal, default to RUN.
func (darwinSignals) OnBattery() (bool, bool) {
	out, err := exec.Command("pmset", "-g", "batt").Output()
	if err != nil {
		return false, false
	}
	body := string(out)
	if strings.Contains(body, "Battery Power") {
		return true, true
	}
	if strings.Contains(body, "AC Power") {
		return false, true
	}
	return false, false
}
