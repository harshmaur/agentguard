package depscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/remediate"
	"github.com/harshmaur/audr/internal/scanignore"
)

const RuleOSVVulnerability = "dependency-osv-vulnerability"

type Backend string

const BackendOSVScanner Backend = "osv-scanner"

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
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
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
			// Linux: prefer brew when available (works on linuxbrew),
			// fall back to go install. The fallback runs only when
			// brew isn't present — the loop in RunUpdatePlan stops on
			// the first success. Without the brew option here,
			// brew-installed users hit go install, which can fail with
			// disk-out-of-space (go-build cache) or with replace-
			// directive errors on osv-scanner's go.mod.
			plan.BinaryCommands = []string{
				"brew upgrade osv-scanner || brew install osv-scanner",
				"go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest",
			}
			plan.Notes = []string{"OSV-Scanner has no separate local vulnerability DB to refresh; updating the binary is enough."}
		}
		return plan
	default:
		return ScannerUpdatePlan{Name: string(backend)}
	}
}

// RunUpdatePlan attempts BinaryCommands as alternatives in preference
// order (first success wins), then runs DatabaseCommands as a
// sequential refresh chain (all must succeed). Without this split,
// brew-installed users would hit the go-install fallback after brew
// succeeded — go install can fail noisily for modules with replace
// directives or run out of disk space building cgo deps.
//
// DBOnly mode skips the binary refresh entirely (used by audr
// update-scanners --db-only when the user only wants to refresh the
// vulnerability DB, not the scanner binary itself).
func RunUpdatePlan(ctx context.Context, plan ScannerUpdatePlan, opts UpdateOptions) error {
	runner := opts.Runner
	if runner == nil {
		runner = execRunner{}
	}
	if !opts.DBOnly {
		if err := runFallbackCommands(ctx, runner, plan.BinaryCommands); err != nil {
			return err
		}
	}
	// DatabaseCommands are sequential — all must succeed. They
	// refresh the local CVE database. OSV-Scanner has none today, so
	// this loop is currently a no-op for the only backend.
	for _, command := range plan.DatabaseCommands {
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

// runFallbackCommands tries each command in order; first success
// wins, remaining commands are skipped. Returns the last error only
// when every command failed. Empty list is a no-op.
func runFallbackCommands(ctx context.Context, runner CommandRunner, commands []string) error {
	var lastErr error
	attempted := 0
	for _, command := range commands {
		command = strings.TrimSpace(command)
		if command == "" {
			continue
		}
		attempted++
		if _, err := runner.Run(ctx, shellName(), shellFlag(), command); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if attempted == 0 {
		return nil
	}
	return lastErr
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
	projectRoots, err := DiscoverProjectRoots(roots)
	if err != nil {
		return nil, err
	}
	if len(projectRoots) == 0 {
		return nil, nil
	}
	switch opts.Backend {
	case BackendOSVScanner:
		args := append([]string{"scan", "source", "--format", "json", "--recursive", "--allow-no-lockfiles", "--verbosity", "error"}, projectRoots...)
		out, err := runner.Run(ctx, binaryName(opts.Backend), args...)
		findings, parseErr := ParseOSVScannerJSON(out)
		if parseErr == nil && len(out) > 0 {
			return findings, nil
		}
		if err != nil {
			return nil, err
		}
		return findings, parseErr
	default:
		return nil, fmt.Errorf("unknown dependency scanner backend %q", opts.Backend)
	}
}

func DiscoverProjectRoots(roots []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, root := range roots {
		if strings.TrimSpace(root) == "" {
			continue
		}
		info, err := os.Stat(root)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			if isDependencySourceFile(filepath.Base(root)) {
				dir := filepath.Dir(root)
				if !seen[dir] {
					seen[dir] = true
					out = append(out, dir)
				}
			}
			continue
		}
		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if path == root {
					return nil
				}
				// Fast path: basename match against single-segment
				// entries (node_modules, .git, .bun, etc.).
				if shouldSkipDir(d.Name()) {
					return filepath.SkipDir
				}
				// Slow path: multi-segment cache subtrees (go/pkg,
				// .npm/_cacache, .gradle/caches, Library/Caches).
				// Without this, a $HOME walk discovers thousands of
				// stale package.json files inside tool caches.
				if shouldSkipPath(path) {
					return filepath.SkipDir
				}
				return nil
			}
			if !isDependencySourceFile(d.Name()) {
				return nil
			}
			dir := filepath.Dir(path)
			if !seen[dir] {
				seen[dir] = true
				out = append(out, dir)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return pruneNestedProjectRoots(out), nil
}

func pruneNestedProjectRoots(roots []string) []string {
	if len(roots) < 2 {
		return roots
	}
	var pruned []string
	for _, root := range roots {
		covered := false
		for _, parent := range pruned {
			rel, err := filepath.Rel(parent, root)
			if err == nil && rel != "." && !strings.HasPrefix(rel, "..") && rel != "" {
				covered = true
				break
			}
		}
		if !covered {
			pruned = append(pruned, root)
		}
	}
	return pruned
}

func isDependencySourceFile(name string) bool {
	switch name {
	case "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb",
		"requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock", "Pipfile.lock",
		"go.mod", "go.sum", "Cargo.lock", "Cargo.toml", "Gemfile.lock", "Gemfile", "composer.lock", "composer.json":
		return true
	default:
		return false
	}
}

// shouldSkipDir reports whether a directory should be excluded during
// project-root discovery. Delegates to scanignore so the canonical
// exclude list (build artifacts + VCS + per-language tool caches +
// per-OS cache roots) lives in one place. See scanignore.Defaults().
func shouldSkipDir(name string) bool {
	return scanignore.IsExcludedBaseName(name)
}

// shouldSkipPath is the multi-segment version: true iff the given
// path contains any cache subpath like "go/pkg" or ".npm/_cacache".
// Used by callers that have the full path available (the WalkDir
// callback passes `path`, so we can do better than basename match).
func shouldSkipPath(path string) bool {
	return scanignore.PathExcluded(path)
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
				Version   string `json:"version"`
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

	// v1.3: a package can have multiple CVEs, each with its own
	// `fixed` version. From the user's POV they're ONE problem
	// (upgrade the package), so we dedup by (ecosystem, package) and
	// pin the snippet to the MAXIMUM fixed version across CVEs —
	// upgrading to max(fixed) resolves all known CVEs for that
	// package. First pass collects max-fixed per (eco, pkg); second
	// pass emits findings sharing that package-level dedup key.
	type pkgKey struct{ ecosystem, name string }
	maxFixed := map[pkgKey]string{}
	for _, res := range report.Results {
		for _, pkg := range res.Packages {
			k := pkgKey{pkg.Package.Ecosystem, pkg.Package.Name}
			for _, vuln := range pkg.Vulnerabilities {
				f := osvFixedVersion(vuln)
				if f == "" {
					continue
				}
				cur := maxFixed[k]
				if cur == "" || compareSemver(f, cur) > 0 {
					maxFixed[k] = f
				}
			}
		}
	}

	var out []finding.Finding
	for _, res := range report.Results {
		for _, pkg := range res.Packages {
			version := firstNonEmpty(pkg.Version, pkg.Package.Version)
			pkgMaxFixed := maxFixed[pkgKey{pkg.Package.Ecosystem, pkg.Package.Name}]
			for _, vuln := range pkg.Vulnerabilities {
				id := advisoryID(vuln.ID, vuln.Aliases)
				fixed := osvFixedVersion(vuln)
				desc := firstNonEmpty(vuln.Summary, vuln.Details, "OSV reported a vulnerable dependency.")
				fix := "Upgrade the package to a non-vulnerable version and regenerate the lockfile."
				if pkgMaxFixed != "" {
					fix = fmt.Sprintf("Upgrade %s to %s or later and regenerate the lockfile.", pkg.Package.Name, pkgMaxFixed)
				} else if fixed != "" {
					fix = fmt.Sprintf("Upgrade %s to %s or later and regenerate the lockfile.", pkg.Package.Name, fixed)
				}
				// v1.3 dedup key: collapses ALL CVEs for the same
				// (ecosystem, package) into one row. The "fixed" segment
				// of the key carries max(fixed) across this package's
				// CVEs so the snippet renderer can pin to it directly.
				// The advisory-id segment is left blank — per-finding CVE
				// info still lives in Description / MatchRedacted.
				dedupKey := remediate.BuildOSVDedupKey(
					pkg.Package.Ecosystem,
					pkg.Package.Name,
					pkgMaxFixed,
					"",
				)
				out = append(out, finding.New(finding.Args{
					RuleID:        RuleOSVVulnerability,
					Severity:      severityFromString(vuln.DatabaseSpecific.Severity),
					Taxonomy:      finding.TaxAdvisory,
					Title:         fmt.Sprintf("Vulnerable dependency: %s", pkg.Package.Name),
					Description:   fmt.Sprintf("%s: %s", id, desc),
					Path:          res.Source.Path,
					Match:         fmt.Sprintf("%s %s@%s", pkg.Package.Ecosystem, pkg.Package.Name, version),
					Context:       fmt.Sprintf("advisory=%s fixed=%s", id, fixed),
					SuggestedFix:  fix,
					Tags:          []string{"dependency", "vulnerability", "osv", strings.ToLower(pkg.Package.Ecosystem)},
					DedupGroupKey: dedupKey,
					// FixAuthority + SecondaryNotify are intentionally left blank
					// here. The path-class classifier in internal/triage owns
					// authority resolution; the OSV rule shouldn't second-guess
					// it because the same CVE on the same package can land in
					// YOU / MAINTAINER / UPSTREAM depending on which lockfile
					// detected it.
				}))
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return finding.Less(out[i], out[j]) })
	return out, nil
}

// compareSemver returns -1, 0, +1 like strings.Compare, with semver-
// aware numeric segment comparison. Strips a leading "v" on either
// side. Falls back to lexicographic compare for non-numeric segments
// or malformed input — good enough for the v1.3 use-case of picking
// the max fixed-version across CVEs for a single package, where all
// candidates almost always share a canonical version vocabulary.
func compareSemver(a, b string) int {
	a = strings.TrimPrefix(strings.TrimSpace(a), "v")
	b = strings.TrimPrefix(strings.TrimSpace(b), "v")
	if a == b {
		return 0
	}
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) < n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		ai, errA := strconv.Atoi(stripNonDigits(as[i]))
		bi, errB := strconv.Atoi(stripNonDigits(bs[i]))
		if errA == nil && errB == nil {
			if ai != bi {
				if ai < bi {
					return -1
				}
				return 1
			}
			continue
		}
		// Lexicographic fallback for non-numeric segments.
		if as[i] != bs[i] {
			if as[i] < bs[i] {
				return -1
			}
			return 1
		}
	}
	if len(as) != len(bs) {
		if len(as) < len(bs) {
			return -1
		}
		return 1
	}
	return 0
}

func stripNonDigits(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return "0"
	}
	return string(out)
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
