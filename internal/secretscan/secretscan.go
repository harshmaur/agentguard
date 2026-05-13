package secretscan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/redact"
	"github.com/harshmaur/audr/internal/scanignore"
)

const (
	RuleTruffleHogVerified   = "secret-trufflehog-verified"
	RuleTruffleHogUnverified = "secret-trufflehog-unverified"
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
	plan := InstallerPlan{Name: "TruffleHog"}
	switch runtime.GOOS {
	case "darwin":
		plan.Commands = []string{"brew install trufflehog"}
	case "windows":
		plan.Commands = []string{"winget install TruffleSecurity.TruffleHog"}
	default:
		plan.Commands = []string{"brew install trufflehog", "go install github.com/trufflesecurity/trufflehog/v3@latest"}
		plan.Notes = []string{"Use the package-manager command you trust for this machine; Audr asks before running installs."}
	}
	return plan
}

func UpdatePlan() ScannerUpdatePlan {
	plan := ScannerUpdatePlan{Name: "TruffleHog"}
	switch runtime.GOOS {
	case "darwin":
		plan.BinaryCommands = []string{"brew upgrade trufflehog || brew install trufflehog"}
	case "windows":
		plan.BinaryCommands = []string{"winget upgrade TruffleSecurity.TruffleHog || winget install TruffleSecurity.TruffleHog"}
	default:
		plan.BinaryCommands = []string{"brew upgrade trufflehog || brew install trufflehog", "go install github.com/trufflesecurity/trufflehog/v3@latest"}
		plan.Notes = []string{"TruffleHog has no separate local vulnerability database cache."}
	}
	return plan
}

func RunUpdatePlan(ctx context.Context, plan ScannerUpdatePlan, opts UpdateOptions) error {
	runner := opts.Runner
	if runner == nil {
		runner = execRunner{}
	}
	for _, command := range plan.BinaryCommands {
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

	excludeFile, cleanupExcludes, err := scanignore.WriteTruffleHogExcludeFile()
	if err != nil {
		return nil, fmt.Errorf("prepare trufflehog exclude file: %w", err)
	}
	defer cleanupExcludes()

	args := []string{
		"filesystem",
		"--json",
		"--no-update",
		"--exclude-paths", excludeFile,
		fmt.Sprintf("--concurrency=%d", concurrency()),
	}
	args = append(args, roots...)
	out, err := runner.Run(ctx, binaryName(), args...)
	findings, parseErr := ParseTruffleHogJSONL(out)
	if parseErr == nil && len(out) > 0 {
		return findings, nil
	}
	if err != nil {
		return nil, err
	}
	return findings, parseErr
}

// concurrency returns the TruffleHog --concurrency value: half the logical
// CPUs, never below 1. Keeps the scan from monopolizing every core.
func concurrency() int {
	n := runtime.NumCPU() / 2
	if n < 1 {
		return 1
	}
	return n
}

type truffleHogFinding struct {
	SourceName     string `json:"SourceName"`
	DetectorName   string `json:"DetectorName"`
	DetectorType   int    `json:"DetectorType"`
	Verified       bool   `json:"Verified"`
	Raw            string `json:"Raw"`
	RawV2          string `json:"RawV2"`
	Redacted       string `json:"Redacted"`
	SourceMetadata struct {
		Data struct {
			Filesystem struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"Filesystem"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
	ExtraData map[string]string `json:"ExtraData"`
}

func ParseTruffleHogJSONL(raw []byte) ([]finding.Finding, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, nil
	}
	var out []finding.Finding
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var item truffleHogFinding
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			return nil, fmt.Errorf("parse trufflehog jsonl: %w", err)
		}
		out = append(out, normalizeFinding(item))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan trufflehog jsonl: %w", err)
	}
	sort.SliceStable(out, func(i, j int) bool { return finding.Less(out[i], out[j]) })
	return out, nil
}

func normalizeFinding(item truffleHogFinding) finding.Finding {
	ruleID := RuleTruffleHogUnverified
	severity := finding.SeverityMedium
	verified := "false"
	if item.Verified {
		ruleID = RuleTruffleHogVerified
		severity = finding.SeverityHigh
		verified = "true"
	}
	detector := firstNonEmpty(item.DetectorName, fmt.Sprintf("detector-%d", item.DetectorType), "unknown")
	path := item.SourceMetadata.Data.Filesystem.File
	line := item.SourceMetadata.Data.Filesystem.Line
	if line == 0 {
		line = lineFromExtraData(item.ExtraData)
	}
	redacted := firstNonEmpty(item.Redacted, "[REDACTED]")
	return finding.New(finding.Args{
		RuleID:       ruleID,
		Severity:     severity,
		Taxonomy:     finding.TaxDetectable,
		Title:        fmt.Sprintf("Secret detected by TruffleHog: %s", detector),
		Description:  fmt.Sprintf("TruffleHog reported a secret-like value from detector %s (verified=%s).", detector, verified),
		Path:         path,
		Line:         line,
		Match:        fmt.Sprintf("detector=%s secret=%s", detector, redacted),
		Context:      fmt.Sprintf("source=%s verified=%s detector_type=%d", item.SourceName, verified, item.DetectorType),
		SuggestedFix: "Rotate or revoke the secret, remove it from local files and git history, then rescan.",
		Tags:         []string{"secret", "trufflehog", "developer-machine", strings.ToLower(detector)},
	})
}

func lineFromExtraData(extra map[string]string) int {
	if len(extra) == 0 {
		return 0
	}
	for _, key := range []string{"line", "Line", "line_number"} {
		if raw := strings.TrimSpace(extra[key]); raw != "" {
			line, err := strconv.Atoi(raw)
			if err == nil {
				return line
			}
		}
	}
	return 0
}

func binaryName() string { return "trufflehog" }

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
