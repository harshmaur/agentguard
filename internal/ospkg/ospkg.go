package ospkg

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
)

// Package is a single installed OS package: the manager it lives in,
// its canonical name, and its installed version. Multiple packages
// from different managers can co-exist (e.g., dpkg base + a brew
// install on macOS, though we don't enumerate brew for CVEs yet).
type Package struct {
	Manager Manager
	Name    string
	Version string
}

// Vulnerability is one CVE reported by OSV against an installed
// package. A single package may produce multiple Vulnerabilities;
// the orchestrator emits each as a separate state.Finding so they
// can be resolved independently (some fix in 1.2.3, others in 1.2.4).
type Vulnerability struct {
	Package Package

	// AdvisoryID is the canonical identifier — prefers CVE-XXXX-NNNN
	// when one is available; falls back to the OSV ID (e.g.,
	// DSA-5677-1) or first non-empty alias otherwise.
	AdvisoryID string

	// Severity is the OSV-reported severity normalized to one of
	// audr's four levels ("critical" / "high" / "medium" / "low").
	Severity string

	// Summary is a one-line human description from OSV's database.
	Summary string

	// FixedIn is the package version that resolves the vulnerability,
	// when known. Empty when OSV reports an unfixed vuln.
	FixedIn string
}

// Available reports whether OS-package CVE detection is supported on
// the current OS. Linux with a recognized distro + osv-scanner on
// PATH returns true; macOS / Windows / unknown distros return false.
//
// Callers use this to decide whether to surface the os-pkg category
// as "ok" (run + report findings) vs "unavailable" (record scanner
// status + dashboard banner).
func Available() (bool, string) {
	info, err := detectDistro()
	if err != nil {
		return false, fmt.Sprintf("detect distro: %v", err)
	}
	if info.ID == "" {
		return false, "OS-package CVE detection is Linux-only in v1; brew/winget rendering coming in v1.1"
	}
	if _, err := exec.LookPath(OSVScannerBinary); err != nil {
		return false, fmt.Sprintf("%s not on $PATH; run `audr update-scanners` to install", OSVScannerBinary)
	}
	return true, ""
}

// EnumerateAndScan is the orchestrator's entrypoint: enumerate
// installed packages on this machine, run them through OSV-Scanner,
// return the list of vulnerabilities. Each step is bounded by ctx;
// passing a context with a deadline lets the daemon abort if a scan
// runs too long.
//
// On unsupported platforms (macOS, Windows, unknown distro) returns
// ErrUnsupported.
func EnumerateAndScan(ctx context.Context) ([]Vulnerability, error) {
	info, err := detectDistro()
	if err != nil {
		return nil, fmt.Errorf("ospkg: detect distro: %w", err)
	}
	if info.ID == "" {
		return nil, ErrUnsupported
	}
	pkgs, err := enumerate(ctx, info)
	if err != nil {
		return nil, fmt.Errorf("ospkg: enumerate %s: %w", info.Manager, err)
	}
	if len(pkgs) == 0 {
		return nil, nil
	}
	return ScanPackages(ctx, info, pkgs)
}

// ErrUnsupported is returned by EnumerateAndScan when the current OS
// or distro isn't covered. Surfaced by the orchestrator as the
// "unavailable" scanner status with a friendly error_text.
var ErrUnsupported = errors.New("ospkg: OS-package CVE detection unsupported on this platform")

// CommandRunner is the shell-out injection point. Tests pass a fake
// that returns canned output; the real daemon uses execRunner which
// calls exec.CommandContext.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

// defaultRunner is used by callers who don't override. exec-based,
// the production codepath.
var defaultRunner CommandRunner = execRunner{}
