package depscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"sort"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
)

const (
	RuleOSVVulnerability   = "dependency-osv-vulnerability"
	RuleTrivyVulnerability = "dependency-trivy-vulnerability"
)

type Backend string

const (
	BackendOSVScanner Backend = "osv-scanner"
	BackendTrivy      Backend = "trivy"
)

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type CommandRunnerFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

func (f CommandRunnerFunc) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f(ctx, name, args...)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

type RunOptions struct {
	Backend Backend
	Roots   []string
	Runner  CommandRunner
}

type Status struct {
	Backend   Backend
	Binary    string
	Installed bool
	Path      string
}

type InstallerPlan struct {
	Name     string
	Commands []string
	Notes    []string
}

type ScannerUpdatePlan struct {
	Name             string
	BinaryCommands   []string
	DatabaseCommands []string
	Notes            []string
}

type UpdateOptions struct {
	Runner CommandRunner
	DBOnly bool
}

func BackendStatus(backend Backend) Status {
	bin := binaryName(backend)
	p, err := exec.LookPath(bin)
	return Status{Backend: backend, Binary: bin, Installed: err == nil, Path: p}
}

func InstallPlan(backend Backend) InstallerPlan {
	switch backend {
	case BackendOSVScanner:
		plan := InstallerPlan{Name: "OSV-Scanner"}
		switch runtime.GOOS {
		case "darwin":
			plan.Commands = []string{"brew install osv-scanner"}
		case "windows":
			plan.Commands = []string{"go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"}
		default:
			plan.Commands = []string{"go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"}
			plan.Notes = []string{"Requires Go on PATH; alternatively install an official OSV-Scanner release for your platform."}
		}
		return plan
	case BackendTrivy:
		plan := InstallerPlan{Name: "Trivy"}
		switch runtime.GOOS {
		case "darwin":
			plan.Commands = []string{"brew install trivy"}
		case "windows":
			plan.Commands = []string{"winget install AquaSecurity.Trivy"}
		default:
			plan.Commands = []string{"brew install trivy", "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"}
			plan.Notes = []string{"Use the package-manager command you trust for this machine; Audr asks before running installs."}
		}
		return plan
	default:
		return InstallerPlan{Name: string(backend)}
	}
}

func UpdatePlan(backend Backend) ScannerUpdatePlan {
	switch backend {
	case BackendOSVScanner:
		plan := ScannerUpdatePlan{Name: "OSV-Scanner"}
		switch runtime.GOOS {
		case "darwin":
			plan.BinaryCommands = []string{"brew upgrade osv-scanner || brew install osv-scanner"}
		case "windows":
			plan.BinaryCommands = []string{"go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"}
		default:
			plan.BinaryCommands = []string{"go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"}
			plan.Notes = []string{"OSV-Scanner has no separate local vulnerability DB to refresh; updating the binary is enough."}
		}
		return plan
	case BackendTrivy:
		plan := ScannerUpdatePlan{
			Name:             "Trivy",
			DatabaseCommands: []string{"trivy --download-db-only --quiet"},
		}
		switch runtime.GOOS {
		case "darwin":
			plan.BinaryCommands = []string{"brew upgrade trivy || brew install trivy"}
		case "windows":
			plan.BinaryCommands = []string{"winget upgrade AquaSecurity.Trivy || winget install AquaSecurity.Trivy"}
		default:
			plan.BinaryCommands = []string{"brew upgrade trivy || brew install trivy", "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"}
			plan.Notes = []string{"Trivy auto-refreshes its vulnerability DB during scans by default; `audr update-scanners --db-only` refreshes it explicitly."}
		}
		return plan
	default:
		return ScannerUpdatePlan{Name: string(backend)}
	}
}

func RunUpdatePlan(ctx context.Context, plan ScannerUpdatePlan, opts UpdateOptions) error {
	runner := opts.Runner
	if runner == nil {
		runner = execRunner{}
	}
	commands := append([]string(nil), plan.DatabaseCommands...)
	if !opts.DBOnly {
		commands = append(append([]string(nil), plan.BinaryCommands...), plan.DatabaseCommands...)
	}
	for _, command := range commands {
		command = strings.TrimSpace(command)
		if command == "" {
			continue
		}
		if _, err := runner.Run(ctx, shellName(), shellFlag(), command); err != nil {
			return err
		}
	}
	return nil
}

func RunBackend(ctx context.Context, opts RunOptions) ([]finding.Finding, error) {
	runner := opts.Runner
	if runner == nil {
		runner = execRunner{}
	}
	roots := opts.Roots
	if len(roots) == 0 {
		roots = []string{"."}
	}
	switch opts.Backend {
	case BackendOSVScanner:
		args := append([]string{"--format", "json"}, roots...)
		out, err := runner.Run(ctx, binaryName(opts.Backend), args...)
		findings, parseErr := ParseOSVScannerJSON(out)
		if parseErr == nil && len(out) > 0 {
			return findings, nil
		}
		if err != nil {
			return nil, err
		}
		return findings, parseErr
	case BackendTrivy:
		var all []finding.Finding
		for _, root := range roots {
			out, err := runner.Run(ctx, binaryName(opts.Backend), "fs", "--format", "json", "--quiet", root)
			findings, parseErr := ParseTrivyJSON(out)
			if parseErr == nil && len(out) > 0 {
				all = append(all, findings...)
				continue
			}
			if err != nil {
				return nil, err
			}
			if parseErr != nil {
				return nil, parseErr
			}
		}
		return all, nil
	default:
		return nil, fmt.Errorf("unknown dependency scanner backend %q", opts.Backend)
	}
}

func shellName() string {
	if runtime.GOOS == "windows" {
		return "cmd"
	}
	return "sh"
}

func shellFlag() string {
	if runtime.GOOS == "windows" {
		return "/C"
	}
	return "-c"
}

func binaryName(backend Backend) string {
	switch backend {
	case BackendOSVScanner:
		return "osv-scanner"
	case BackendTrivy:
		return "trivy"
	default:
		return string(backend)
	}
}

type osvReport struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Version         string             `json:"version"`
			Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

type osvVulnerability struct {
	ID               string   `json:"id"`
	Aliases          []string `json:"aliases"`
	Summary          string   `json:"summary"`
	Details          string   `json:"details"`
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

func ParseOSVScannerJSON(raw []byte) ([]finding.Finding, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, nil
	}
	var report osvReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("parse osv-scanner json: %w", err)
	}
	var out []finding.Finding
	for _, res := range report.Results {
		for _, pkg := range res.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				id := advisoryID(vuln.ID, vuln.Aliases)
				fixed := osvFixedVersion(vuln)
				desc := firstNonEmpty(vuln.Summary, vuln.Details, "OSV reported a vulnerable dependency.")
				fix := "Upgrade the package to a non-vulnerable version and regenerate the lockfile."
				if fixed != "" {
					fix = fmt.Sprintf("Upgrade %s to %s or later and regenerate the lockfile.", pkg.Package.Name, fixed)
				}
				out = append(out, finding.New(finding.Args{
					RuleID:       RuleOSVVulnerability,
					Severity:     severityFromString(vuln.DatabaseSpecific.Severity),
					Taxonomy:     finding.TaxAdvisory,
					Title:        fmt.Sprintf("Vulnerable dependency: %s", pkg.Package.Name),
					Description:  fmt.Sprintf("%s: %s", id, desc),
					Path:         res.Source.Path,
					Match:        fmt.Sprintf("%s %s@%s", pkg.Package.Ecosystem, pkg.Package.Name, pkg.Version),
					Context:      fmt.Sprintf("advisory=%s fixed=%s", id, fixed),
					SuggestedFix: fix,
					Tags:         []string{"dependency", "vulnerability", "osv", strings.ToLower(pkg.Package.Ecosystem)},
				}))
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return finding.Less(out[i], out[j]) })
	return out, nil
}

func osvFixedVersion(v osvVulnerability) string {
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

type trivyReport struct {
	Results []struct {
		Target          string `json:"Target"`
		Class           string `json:"Class"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			Description      string `json:"Description"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func ParseTrivyJSON(raw []byte) ([]finding.Finding, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, nil
	}
	var report trivyReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("parse trivy json: %w", err)
	}
	var out []finding.Finding
	for _, res := range report.Results {
		for _, vuln := range res.Vulnerabilities {
			desc := firstNonEmpty(vuln.Title, vuln.Description, "Trivy reported a vulnerable dependency or package.")
			fix := "Upgrade the package to a non-vulnerable version."
			if vuln.FixedVersion != "" {
				fix = fmt.Sprintf("Upgrade %s to %s or later.", vuln.PkgName, vuln.FixedVersion)
			}
			out = append(out, finding.New(finding.Args{
				RuleID:       RuleTrivyVulnerability,
				Severity:     severityFromString(vuln.Severity),
				Taxonomy:     finding.TaxAdvisory,
				Title:        fmt.Sprintf("Vulnerable package: %s", vuln.PkgName),
				Description:  fmt.Sprintf("%s: %s", vuln.VulnerabilityID, desc),
				Path:         res.Target,
				Match:        fmt.Sprintf("%s %s@%s", res.Type, vuln.PkgName, vuln.InstalledVersion),
				Context:      fmt.Sprintf("advisory=%s fixed=%s class=%s", vuln.VulnerabilityID, vuln.FixedVersion, res.Class),
				SuggestedFix: fix,
				Tags:         []string{"dependency", "vulnerability", "trivy", strings.ToLower(res.Type)},
			}))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return finding.Less(out[i], out[j]) })
	return out, nil
}

func advisoryID(id string, aliases []string) string {
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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func severityFromString(s string) finding.Severity {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "CRITICAL":
		return finding.SeverityCritical
	case "HIGH":
		return finding.SeverityHigh
	case "MEDIUM", "MODERATE":
		return finding.SeverityMedium
	case "LOW":
		return finding.SeverityLow
	default:
		return finding.SeverityMedium
	}
}

func IsBackendMissing(err error) bool {
	var e *exec.Error
	return errors.As(err, &e)
}
