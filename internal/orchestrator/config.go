package orchestrator

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ScannerConfig is the user-controllable enable/disable for each
// scanner category. Persists at ${state_dir}/scanner.config.json
// (mode 0600). Read by the orchestrator at the top of every scan
// cycle, so the toggle takes effect within one cycle without a
// daemon restart.
//
// Distinction from "unavailable":
//   - "disabled" means the user explicitly turned the category off
//     (audr daemon scanners --off=secrets, or dashboard click).
//     The scanner sidecar may still be installed and working.
//   - "unavailable" means the sidecar isn't installed or isn't
//     supported on this OS (e.g., OS-pkg on macOS).
//
// Dashboard banners differentiate the two so the user knows whether
// they need to run `audr update-scanners` (install) or
// `audr daemon scanners --on=<cat>` (re-enable).
type ScannerConfig struct {
	AIAgent bool `json:"ai_agent"`
	Deps    bool `json:"deps"`
	Secrets bool `json:"secrets"`
	OSPkg   bool `json:"os_pkg"`
}

// DefaultScannerConfig returns the config a fresh install starts
// with: all four categories enabled. The actual run-or-skip
// decision then comes down to sidecar availability per category.
func DefaultScannerConfig() ScannerConfig {
	return ScannerConfig{
		AIAgent: true,
		Deps:    true,
		Secrets: true,
		OSPkg:   true,
	}
}

// Enabled reports whether the named category is on. Unknown
// categories return false (defensive: future categories show
// "off" by default until user-config catches up).
func (c ScannerConfig) Enabled(category string) bool {
	switch category {
	case "ai-agent":
		return c.AIAgent
	case "deps":
		return c.Deps
	case "secrets":
		return c.Secrets
	case "os-pkg":
		return c.OSPkg
	}
	return false
}

// SetEnabled returns a copy of c with the named category set. Used
// by the CLI / HTTP handler to flip individual categories. Returns
// an error on unknown category name so typos at the CLI surface as
// errors rather than silent no-ops.
func (c ScannerConfig) SetEnabled(category string, enabled bool) (ScannerConfig, error) {
	switch category {
	case "ai-agent":
		c.AIAgent = enabled
	case "deps":
		c.Deps = enabled
	case "secrets":
		c.Secrets = enabled
	case "os-pkg":
		c.OSPkg = enabled
	default:
		return c, fmt.Errorf("orchestrator: unknown scanner category %q (valid: ai-agent, deps, secrets, os-pkg)", category)
	}
	return c, nil
}

// ScannerCategories lists the canonical category identifiers in
// stable order. Used by CLI output + tests that iterate them.
func ScannerCategories() []string {
	return []string{"ai-agent", "deps", "secrets", "os-pkg"}
}

// scannerConfigFilename is the on-disk filename. Centralized so
// the CLI helpers and orchestrator never disagree.
const scannerConfigFilename = "scanner.config.json"

// ReadScannerConfig returns the persisted config for stateDir, or
// DefaultScannerConfig + nil error when the file doesn't exist
// (fresh install).
func ReadScannerConfig(stateDir string) (ScannerConfig, error) {
	cfg := DefaultScannerConfig()
	if stateDir == "" {
		return cfg, errors.New("orchestrator: stateDir is required")
	}
	b, err := os.ReadFile(filepath.Join(stateDir, scannerConfigFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("orchestrator: read scanner config: %w", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		// Don't fail catastrophically on a malformed config file —
		// the daemon should keep scanning. Log-and-default would be
		// the ideal but we don't have a logger here; return error
		// and let the caller decide.
		return DefaultScannerConfig(), fmt.Errorf("orchestrator: parse scanner config: %w", err)
	}
	return cfg, nil
}

// WriteScannerConfig persists cfg atomically (temp + rename). Used
// by the `audr daemon scanners` CLI subcommand and the POST
// /api/scanners HTTP handler.
func WriteScannerConfig(stateDir string, cfg ScannerConfig) error {
	if stateDir == "" {
		return errors.New("orchestrator: stateDir is required")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("orchestrator: create state dir: %w", err)
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(stateDir, scannerConfigFilename)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
