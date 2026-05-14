package ospkg

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// OSVScannerBinary is the executable name we shell out to. Resolved
// via $PATH at invocation time.
const OSVScannerBinary = "osv-scanner"

// ScanPackages runs OSV-Scanner against the given enumerated packages
// and returns the resulting vulnerabilities. The SBOM is written to
// a tempfile, OSV-Scanner reads it, the tempfile is cleaned up on
// return.
//
// Returns nil + nil error when OSV finds no vulnerabilities. Returns
// a non-nil error only on infrastructure failures (tempfile creation,
// JSON parse). A non-zero exit from osv-scanner is NOT an error —
// the tool exits 1 when it finds vulnerabilities (its CI semantics),
// so we look at stdout JSON content rather than the exit code.
func ScanPackages(ctx context.Context, info DistroInfo, pkgs []Package) ([]Vulnerability, error) {
	return scanPackages(ctx, info, pkgs, defaultRunner)
}

func scanPackages(ctx context.Context, info DistroInfo, pkgs []Package, runner CommandRunner) ([]Vulnerability, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}
	body, err := buildSBOM(info, pkgs)
	if err != nil {
		return nil, fmt.Errorf("build sbom: %w", err)
	}

	// Tempfile naming matters: osv-scanner v2 requires the filename
	// follow a recognized SBOM convention (e.g., *.cdx.json for
	// CycloneDX) or it refuses to parse with "Invalid SBOM filename".
	tmp, err := os.CreateTemp("", "audr-ospkg-*.cdx.json")
	if err != nil {
		return nil, fmt.Errorf("create sbom tempfile: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("write sbom tempfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("close sbom tempfile: %w", err)
	}

	// osv-scanner v2 deprecated `--sbom` in favor of `-L`
	// (lockfile flag, which auto-detects CycloneDX from the *.cdx.json
	// extension). We use -L so we don't trigger the deprecation warning
	// on every scan cycle.
	args := []string{
		"scan", "source",
		"-L", tmp.Name(),
		"--format", "json",
		"--verbosity", "error",
	}
	out, err := runner.Run(ctx, OSVScannerBinary, args...)
	// We accept "exit status 1" as a non-error here — that's OSV's
	// "vulnerabilities found" signal. The orchestrator's category
	// status only goes to "error" if the stdout is empty or unparseable.
	if err != nil && !isOSVFindingsExitError(err) {
		// If we got SOMETHING on stdout despite the error, still try
		// to parse — better to surface findings than to drop them.
		if len(out) == 0 {
			return nil, fmt.Errorf("osv-scanner: %w", err)
		}
	}
	return parseOSVOutput(out)
}

// isOSVFindingsExitError reports whether err is the synthetic
// "exit status 1" osv-scanner returns when it has matched findings.
// On Unix this is *exec.ExitError with code 1; we don't want to
// treat that as a real failure.
func isOSVFindingsExitError(err error) bool {
	if err == nil {
		return false
	}
	var exitErr *exec.ExitError
	if asErr(err, &exitErr) {
		return exitErr.ExitCode() == 1
	}
	return false
}

// asErr is errors.As without pulling in the errors import — same
// behavior, different name to keep the import surface tight.
func asErr(err error, target any) bool {
	type unwrapper interface{ Unwrap() error }
	for err != nil {
		if ptr, ok := target.(**exec.ExitError); ok {
			if e, ok := err.(*exec.ExitError); ok {
				*ptr = e
				return true
			}
		}
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// osvReport is the subset of OSV-Scanner JSON output we care about.
// Mirrored manually rather than imported from depscan to keep the
// two parsers independent (their finding shapes diverge).
type osvReport struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Source   osvSource    `json:"source"`
	Packages []osvPackage `json:"packages"`
}

type osvSource struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type osvPackage struct {
	Package struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Ecosystem string `json:"ecosystem"`
		PURL      string `json:"purl"`
	} `json:"package"`
	Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
}

type osvVulnerability struct {
	ID               string   `json:"id"`
	Aliases          []string `json:"aliases"`
	Summary          string   `json:"summary"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Ranges []struct {
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// parseOSVOutput maps OSV-Scanner JSON to our Vulnerability shape.
// One Vulnerability per (package, advisory) pair so the orchestrator
// can emit each as its own state.Finding (independently resolvable).
//
// Severity normalization: OSV's database_specific.severity is
// uppercase ("CRITICAL", "HIGH", "MEDIUM"/"MODERATE", "LOW") with
// occasional "UNKNOWN". We map to audr's lowercase severity vocab,
// defaulting unknown to "medium" (better to surface than swallow).
func parseOSVOutput(raw []byte) ([]Vulnerability, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, nil
	}
	var report osvReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("parse osv-scanner json: %w", err)
	}
	var out []Vulnerability
	for _, res := range report.Results {
		for _, pkg := range res.Packages {
			manager := purlEcosystemToManager(pkg.Package.Ecosystem)
			if manager == "" {
				continue // an ecosystem we don't model as a Manager
			}
			for _, vuln := range pkg.Vulnerabilities {
				out = append(out, Vulnerability{
					Package: Package{
						Manager: manager,
						Name:    pkg.Package.Name,
						Version: pkg.Package.Version,
					},
					AdvisoryID: chooseAdvisoryID(vuln.ID, vuln.Aliases),
					Severity:   normalizeSeverity(vuln.DatabaseSpecific.Severity),
					Summary:    vuln.Summary,
					FixedIn:    firstFixedVersion(vuln),
				})
			}
		}
	}
	return out, nil
}

func purlEcosystemToManager(eco string) Manager {
	switch strings.ToLower(eco) {
	case "debian", "ubuntu":
		return ManagerDpkg
	case "redhat", "rhel", "rocky", "almalinux", "centos", "fedora":
		return ManagerRpm
	case "alpine":
		return ManagerApk
	default:
		return ""
	}
}

func chooseAdvisoryID(id string, aliases []string) string {
	// Prefer CVE-XXXX-NNNN when one of the aliases is one.
	for _, a := range aliases {
		if strings.HasPrefix(strings.ToUpper(a), "CVE-") {
			return a
		}
	}
	if id != "" {
		return id
	}
	if len(aliases) > 0 {
		return aliases[0]
	}
	return "vulnerability"
}

func normalizeSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM", "MODERATE":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "medium"
	}
}

func firstFixedVersion(v osvVulnerability) string {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}
