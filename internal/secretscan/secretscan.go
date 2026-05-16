package secretscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"sort"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/redact"
	"github.com/harshmaur/audr/internal/scanignore"
)

const (
	RuleBetterleaksValid      = "secret-betterleaks-valid"
	RuleBetterleaksUnverified = "secret-betterleaks-unverified"
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
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, formatCommandError(name, err, stderr.Bytes())
	}
	return out, nil
}

func formatCommandError(name string, err error, stderr []byte) error {
	msg := strings.TrimSpace(redact.String(string(stderr)))
	if msg != "" {
		return fmt.Errorf("%s: %w: %s", name, err, msg)
	}
	return fmt.Errorf("%s: %w", name, err)
}

type RunOptions struct {
	Roots  []string
	Runner CommandRunner

	// Jobs caps Betterleaks' validation worker pool via its
	// --validation-workers flag. Behavior:
	//
	//   Jobs > 0  → passes --validation-workers=Jobs to betterleaks
	//   Jobs == 0 → caller wants Betterleaks' default (10)
	//   Jobs < 0  → treated as 0 (defensive; CLI validates earlier)
	//
	// Semantic note: trufflehog's --concurrency capped the file-walk
	// + detector worker pool. Betterleaks' file walk is uncapped (the
	// dir subcommand exposes no worker flag) and finishes in ~2s on a
	// realistic $HOME corpus. The dominant cost shifted to validation
	// HTTP roundtrips, which IS configurable. So --scanner-jobs now
	// caps that — same flag name, different mechanism. Lowprio still
	// limits OS-level scheduling pressure.
	Jobs int
}

// DefaultJobs returns the Betterleaks --validation-workers value
// audr uses for one-shot `audr scan` runs. Matches betterleaks's own
// default. Exported so the CLI's --scanner-jobs flag can print the
// computed default in its help text.
func DefaultJobs() int {
	return 5
}

// DefaultDaemonJobs returns the Betterleaks --validation-workers
// value audr's daemon uses for its periodic background scan.
//
// Conservative (2) because the daemon runs continuously while the
// user is doing real work. Validation hits provider APIs over the
// network, so the bottleneck isn't local CPU — it's bursty outbound
// connections. 2 concurrent HTTP roundtrips keeps the connection
// pool small and the daemon's network footprint quiet.
//
// Trade: first-time daemon scans with many findings to validate take
// longer than the CLI default. v1 spec accepts this: "Hours
// acceptable; resource hogging is not." Lowprio plus this cap is the
// daemon's defense-in-depth.
func DefaultDaemonJobs() int {
	return 2
}

type Status struct {
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
}

func BackendStatus() Status {
	bin := binaryName()
	p, err := exec.LookPath(bin)
	return Status{Binary: bin, Installed: err == nil, Path: p}
}

func InstallPlan() InstallerPlan {
	plan := InstallerPlan{Name: "Betterleaks"}
	switch runtime.GOOS {
	case "darwin":
		plan.Commands = []string{"brew install betterleaks"}
	case "windows":
		// Betterleaks ships a Windows binary via GitHub Releases.
		// winget package id may not be registered yet; the manual
		// release-download path is the reliable one.
		plan.Commands = []string{"see https://github.com/betterleaks/betterleaks/releases for the Windows binary"}
		plan.Notes = []string{"Betterleaks does not yet ship via winget; download the latest betterleaks_*_windows_*.zip from GitHub Releases and add it to PATH."}
	default:
		plan.Commands = []string{"brew install betterleaks", "sudo dnf install betterleaks"}
		plan.Notes = []string{"Use the package-manager command you trust for this machine; Audr asks before running installs."}
	}
	return plan
}

func UpdatePlan() ScannerUpdatePlan {
	plan := ScannerUpdatePlan{Name: "Betterleaks"}
	switch runtime.GOOS {
	case "darwin":
		plan.BinaryCommands = []string{"brew upgrade betterleaks || brew install betterleaks"}
	case "windows":
		plan.BinaryCommands = []string{"see https://github.com/betterleaks/betterleaks/releases for the Windows binary"}
		plan.Notes = []string{"Betterleaks does not yet ship via winget; download the latest release zip and replace betterleaks.exe on PATH."}
	default:
		plan.BinaryCommands = []string{"brew upgrade betterleaks || brew install betterleaks", "sudo dnf upgrade betterleaks || sudo dnf install betterleaks"}
		plan.Notes = []string{"Betterleaks has no separate local vulnerability database cache."}
	}
	return plan
}

// RunUpdatePlan attempts each BinaryCommand in order, treating them
// as ALTERNATIVES not sequential steps. The first command that
// succeeds wins; the rest are skipped. Returns the last error only
// when every command fails.
//
// Why fallbacks vs. steps: package-manager availability is per-host.
// A user with brew gets brew; a user with dnf gets dnf. Iterating
// past the first success would then trip the fallback installer on a
// system where it isn't usable (no dnf on macOS, no brew on Fedora
// minimal). The fallback-style loop fixes that.
func RunUpdatePlan(ctx context.Context, plan ScannerUpdatePlan, opts UpdateOptions) error {
	runner := opts.Runner
	if runner == nil {
		runner = execRunner{}
	}
	var lastErr error
	attempted := 0
	for _, command := range plan.BinaryCommands {
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

	configFile, cleanupConfig, err := scanignore.WriteBetterleaksConfig()
	if err != nil {
		return nil, fmt.Errorf("prepare betterleaks config file: %w", err)
	}
	defer cleanupConfig()

	args := []string{
		"dir",
		"--report-format=json",
		"--report-path=-",
		"--config", configFile,
		"--no-banner",
		"--log-level=error",
		"--validation",
		"--validation-timeout=10s",
	}
	if opts.Jobs > 0 {
		args = append(args, fmt.Sprintf("--validation-workers=%d", opts.Jobs))
	}
	args = append(args, roots...)
	out, err := runner.Run(ctx, binaryName(), args...)

	// Betterleaks exits with code 1 when leaks are found. That's a
	// successful scan with findings, not a backend failure — the
	// runner's exit-error wrapper still gives us stdout, which is
	// what we parse. Distinguish "no stdout at all" (a real failure)
	// from "non-zero exit with valid JSON output" (findings emitted).
	if len(bytes.TrimSpace(out)) > 0 {
		findings, parseErr := ParseBetterleaksJSON(out)
		if parseErr == nil {
			return findings, nil
		}
		if err == nil {
			return nil, parseErr
		}
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// betterleaksFinding mirrors the JSON shape emitted by
// `betterleaks dir --report-format=json`. Source of truth:
// https://github.com/betterleaks/betterleaks/blob/main/report/finding.go
//
// Critical: Match and Secret carry the RAW credential value. The
// normalizer below MUST NOT propagate them into any audr-emitted
// field — only the rule-id, path, line, and validation status make
// it into the user-visible output.
type betterleaksFinding struct {
	RuleID           string            `json:"RuleID"`
	Description      string            `json:"Description"`
	StartLine        int               `json:"StartLine"`
	EndLine          int               `json:"EndLine"`
	StartColumn      int               `json:"StartColumn"`
	EndColumn        int               `json:"EndColumn"`
	Match            string            `json:"Match"`
	Secret           string            `json:"Secret"`
	Attributes       map[string]string `json:"Attributes"`
	Tags             []string          `json:"Tags"`
	Fingerprint      string            `json:"Fingerprint"`
	File             string            `json:"File"`
	Entropy          float64           `json:"Entropy"`
	ValidationStatus string            `json:"ValidationStatus"`
	ValidationReason string            `json:"ValidationReason"`
}

func ParseBetterleaksJSON(raw []byte) ([]finding.Finding, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	var items []betterleaksFinding
	if err := json.Unmarshal(trimmed, &items); err != nil {
		return nil, fmt.Errorf("parse betterleaks json: %w", err)
	}
	out := make([]finding.Finding, 0, len(items))
	for _, item := range items {
		// Drop confirmed-dead secrets — they're no longer exposed
		// and would just be noise on the dashboard.
		status := strings.ToLower(strings.TrimSpace(item.ValidationStatus))
		if status == "invalid" || status == "revoked" {
			continue
		}
		out = append(out, normalizeFinding(item))
	}
	sort.SliceStable(out, func(i, j int) bool { return finding.Less(out[i], out[j]) })
	return out, nil
}

func normalizeFinding(item betterleaksFinding) finding.Finding {
	status := strings.ToLower(strings.TrimSpace(item.ValidationStatus))
	ruleID := RuleBetterleaksUnverified
	severity := finding.SeverityMedium
	if status == "valid" {
		ruleID = RuleBetterleaksValid
		severity = finding.SeverityHigh
	}
	rule := firstNonEmpty(item.RuleID, "unknown")
	path := firstNonEmpty(item.File, item.Attributes["path"])
	line := item.StartLine
	verifiedLabel := "false"
	if status == "valid" {
		verifiedLabel = "true"
	} else if status != "" && status != "none" {
		verifiedLabel = status
	}
	return finding.New(finding.Args{
		RuleID:       ruleID,
		Severity:     severity,
		Taxonomy:     finding.TaxDetectable,
		Title:        fmt.Sprintf("Secret detected by Betterleaks: %s", rule),
		Description:  fmt.Sprintf("Betterleaks rule %s matched (validation=%s).", rule, verifiedLabel),
		Path:         path,
		Line:         line,
		Match:        fmt.Sprintf("rule=%s secret=[REDACTED]", rule),
		Context:      fmt.Sprintf("source=betterleaks validation=%s entropy=%.2f", verifiedLabel, item.Entropy),
		SuggestedFix: "Rotate or revoke the secret, remove it from local files and git history, then rescan.",
		Tags:         []string{"secret", "betterleaks", "developer-machine", strings.ToLower(rule)},
	})
}

func binaryName() string { return "betterleaks" }

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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func IsBackendMissing(err error) bool {
	var e *exec.Error
	return errors.As(err, &e)
}
