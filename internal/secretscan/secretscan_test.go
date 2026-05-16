package secretscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/scanignore"
)

const rawSecret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890SECRET"

// betterleaksJSON wraps one or more JSON-formatted findings in the array
// shape betterleaks emits.
func betterleaksJSON(inner string) []byte {
	return []byte("[\n" + inner + "\n]")
}

func TestParseBetterleaksJSONRedactsValidFinding(t *testing.T) {
	input := betterleaksJSON(`{
		"RuleID": "github-pat",
		"Description": "GitHub Personal Access Token",
		"StartLine": 12,
		"EndLine": 12,
		"StartColumn": 1,
		"EndColumn": 50,
		"Match": "GITHUB_TOKEN=` + rawSecret + `",
		"Secret": "` + rawSecret + `",
		"Attributes": {"path": "/repo/.env", "resource": "fs.content"},
		"Tags": [],
		"Fingerprint": "/repo/.env:github-pat:12",
		"File": "/repo/.env",
		"Entropy": 5.12,
		"ValidationStatus": "valid",
		"ValidationReason": "200 OK from api.github.com"
	}`)

	findings, err := ParseBetterleaksJSON(input)
	if err != nil {
		t.Fatalf("ParseBetterleaksJSON err: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	got := findings[0]
	if got.RuleID != RuleBetterleaksValid {
		t.Fatalf("RuleID = %q, want %q", got.RuleID, RuleBetterleaksValid)
	}
	if got.Severity != finding.SeverityHigh {
		t.Fatalf("Severity = %s, want high", got.Severity)
	}
	if got.Path != "/repo/.env" || got.Line != 12 {
		t.Fatalf("location = %s:%d, want /repo/.env:12", got.Path, got.Line)
	}
	for _, want := range []string{"github-pat", "validation=true"} {
		if !strings.Contains(got.Match+got.Context+got.Description, want) {
			t.Fatalf("finding missing %q: %+v", want, got)
		}
	}
	assertNoRawSecret(t, got)
}

func TestParseBetterleaksJSONRedactsUnverifiedFinding(t *testing.T) {
	input := betterleaksJSON(`{
		"RuleID": "slack-bot-token",
		"StartLine": 0,
		"Match": "SLACK=` + rawSecret + `",
		"Secret": "` + rawSecret + `",
		"Attributes": {"path": "/repo/config.yml"},
		"File": "/repo/config.yml",
		"ValidationStatus": "unknown"
	}`)

	findings, err := ParseBetterleaksJSON(input)
	if err != nil {
		t.Fatalf("ParseBetterleaksJSON err: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	got := findings[0]
	if got.RuleID != RuleBetterleaksUnverified {
		t.Fatalf("RuleID = %q, want %q", got.RuleID, RuleBetterleaksUnverified)
	}
	if got.Severity != finding.SeverityMedium {
		t.Fatalf("Severity = %s, want medium", got.Severity)
	}
	if !strings.Contains(got.Match, "[REDACTED]") {
		t.Fatalf("Match = %q, want redaction token", got.Match)
	}
	assertNoRawSecret(t, got)
}

// TestParseBetterleaksJSONDropsConfirmedDeadSecrets: validation
// statuses "invalid" and "revoked" mean the secret was checked and
// is no longer active. Those are historical noise, not exposures —
// the parser drops them so the dashboard doesn't carry phantom
// "your old, dead key was found in a backup" findings.
func TestParseBetterleaksJSONDropsConfirmedDeadSecrets(t *testing.T) {
	input := betterleaksJSON(`{
		"RuleID": "github-pat",
		"Match": "X",
		"Secret": "Y",
		"File": "/repo/old.env",
		"ValidationStatus": "invalid"
	},
	{
		"RuleID": "github-pat",
		"Match": "X",
		"Secret": "Y",
		"File": "/repo/older.env",
		"ValidationStatus": "revoked"
	},
	{
		"RuleID": "github-pat",
		"Match": "GH=` + rawSecret + `",
		"Secret": "` + rawSecret + `",
		"File": "/repo/current.env",
		"ValidationStatus": "valid"
	}`)

	findings, err := ParseBetterleaksJSON(input)
	if err != nil {
		t.Fatalf("ParseBetterleaksJSON err: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1 (invalid+revoked filtered)", len(findings))
	}
	if findings[0].Path != "/repo/current.env" {
		t.Fatalf("kept wrong finding: %+v", findings[0])
	}
}

func TestParseBetterleaksJSONHandlesEmptyOutputs(t *testing.T) {
	for _, in := range [][]byte{nil, []byte(""), []byte("   \n"), []byte("null"), []byte("[]")} {
		findings, err := ParseBetterleaksJSON(in)
		if err != nil {
			t.Fatalf("empty input %q errored: %v", in, err)
		}
		if len(findings) != 0 {
			t.Fatalf("empty input %q returned findings: %+v", in, findings)
		}
	}
}

func TestRunBackendUsesInjectedRunner(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("TOKEN=x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var called string
	runner := CommandRunnerFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		called = name + " " + strings.Join(args, " ")
		return betterleaksJSON(`{
			"RuleID": "github-pat",
			"StartLine": 1,
			"Match": "TOKEN=x",
			"Secret": "x",
			"Attributes": {"path": "` + filepath.Join(dir, ".env") + `"},
			"File": "` + filepath.Join(dir, ".env") + `",
			"ValidationStatus": "valid"
		}`), nil
	})

	findings, err := RunBackend(context.Background(), RunOptions{Roots: []string{dir}, Runner: runner, Jobs: DefaultJobs()})
	if err != nil {
		t.Fatalf("RunBackend err: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	for _, want := range []string{"betterleaks", "dir", "--report-format=json", "--config", "--validation", "--validation-workers=", dir} {
		if !strings.Contains(called, want) {
			t.Fatalf("called = %q, missing %q", called, want)
		}
	}
}

// TestRunBackendPassesScanignoreConfigFile asserts the wiring: the
// Betterleaks invocation must include --config pointing at a file
// whose contents include audr's scanignore.Defaults() segments as
// allowlist paths. Without this, betterleaks walks node_modules etc.
// and the daemon emits noise.
//
// The config file is captured + inspected inside the runner callback
// because RunBackend defers cleanup that removes the file before
// returning.
func TestRunBackendPassesScanignoreConfigFile(t *testing.T) {
	var (
		capturedArgs       []string
		capturedConfigBody string
		readErr            error
	)
	runner := CommandRunnerFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		capturedArgs = append([]string(nil), args...)
		for i, a := range args {
			if a == "--config" && i+1 < len(args) {
				raw, err := os.ReadFile(args[i+1])
				if err != nil {
					readErr = err
				} else {
					capturedConfigBody = string(raw)
				}
				break
			}
		}
		return nil, nil
	})

	_, err := RunBackend(context.Background(), RunOptions{Roots: []string{t.TempDir()}, Runner: runner, Jobs: DefaultJobs()})
	if err != nil {
		t.Fatalf("RunBackend err: %v", err)
	}
	if readErr != nil {
		t.Fatalf("read config file inside runner: %v", readErr)
	}

	hasConfigFlag := false
	for _, a := range capturedArgs {
		if a == "--config" {
			hasConfigFlag = true
			break
		}
	}
	if !hasConfigFlag {
		t.Fatalf("--config not in args: %v", capturedArgs)
	}
	if capturedConfigBody == "" {
		t.Fatalf("config file body was empty")
	}

	for _, segment := range scanignore.Defaults() {
		if !strings.Contains(capturedConfigBody, segment) {
			t.Fatalf("config file missing segment %q; body:\n%s", segment, capturedConfigBody)
		}
	}

	// Confirm --validation-workers= is set to a positive integer.
	var workersArg string
	for _, a := range capturedArgs {
		if strings.HasPrefix(a, "--validation-workers=") {
			workersArg = a
			break
		}
	}
	if workersArg == "" {
		t.Fatalf("--validation-workers=<n> not in args: %v", capturedArgs)
	}
	if workersArg == "--validation-workers=0" {
		t.Fatalf("validation-workers must be >= 1, got %q", workersArg)
	}
}

// TestRunBackendJobsZeroOmitsValidationWorkersFlag pins the
// semantic: Jobs == 0 means "uncapped — let betterleaks use its own
// default (10)." --validation-workers= is omitted entirely so the
// user can opt into the engine default via `--scanner-jobs 0`.
func TestRunBackendJobsZeroOmitsValidationWorkersFlag(t *testing.T) {
	var captured []string
	runner := CommandRunnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		captured = append([]string(nil), args...)
		return nil, nil
	})
	_, _ = RunBackend(context.Background(), RunOptions{Roots: []string{t.TempDir()}, Runner: runner, Jobs: 0})
	for _, a := range captured {
		if strings.HasPrefix(a, "--validation-workers=") {
			t.Fatalf("Jobs=0 must not pass --validation-workers; got %q in args: %v", a, captured)
		}
	}
}

// TestRunBackendJobsPositivePassesValidationWorkers: explicit Jobs > 0
// → `--validation-workers=N` lands at the expected position (before
// the scan roots so betterleaks parses it as a flag, not a target).
func TestRunBackendJobsPositivePassesValidationWorkers(t *testing.T) {
	var captured []string
	runner := CommandRunnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		captured = append([]string(nil), args...)
		return nil, nil
	})
	root := t.TempDir()
	_, _ = RunBackend(context.Background(), RunOptions{Roots: []string{root}, Runner: runner, Jobs: 7})

	wantFlag := "--validation-workers=7"
	flagIdx, rootIdx := -1, -1
	for i, a := range captured {
		if a == wantFlag {
			flagIdx = i
		}
		if a == root {
			rootIdx = i
		}
	}
	if flagIdx < 0 {
		t.Fatalf("missing %s in args: %v", wantFlag, captured)
	}
	if rootIdx < 0 || flagIdx >= rootIdx {
		t.Fatalf("--validation-workers must come before root path; flagIdx=%d rootIdx=%d args=%v",
			flagIdx, rootIdx, captured)
	}
}

// TestDefaultJobsIsAtLeastOne — DefaultJobs() must never return zero
// (would silently disable validation parallelism entirely).
func TestDefaultJobsIsAtLeastOne(t *testing.T) {
	if got := DefaultJobs(); got < 1 {
		t.Errorf("DefaultJobs() = %d, want >= 1", got)
	}
}

// TestDefaultDaemonJobsIsConservative pins the daemon's quiet
// validation cap. Bumping this back up silently regresses the
// "background scan ate my network connections" failure mode.
func TestDefaultDaemonJobsIsConservative(t *testing.T) {
	if got := DefaultDaemonJobs(); got < 1 || got > 3 {
		t.Errorf("DefaultDaemonJobs() = %d, want a small (1-3) value — daemon must not flood validation endpoints", got)
	}
}

func TestRunUpdatePlanTreatsCommandsAsFallbacks(t *testing.T) {
	t.Run("first command succeeds, rest are skipped", func(t *testing.T) {
		var calls []string
		runner := CommandRunnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(args, " "))
			return nil, nil
		})
		plan := ScannerUpdatePlan{
			Name: "Betterleaks",
			BinaryCommands: []string{
				"brew upgrade betterleaks",
				"sudo dnf upgrade betterleaks",
			},
		}
		if err := RunUpdatePlan(context.Background(), plan, UpdateOptions{Runner: runner}); err != nil {
			t.Fatalf("RunUpdatePlan: %v", err)
		}
		if len(calls) != 1 {
			t.Errorf("commands run = %d, want 1 (first success should stop iteration)\n  got: %v", len(calls), calls)
		}
	})
	t.Run("first command fails, falls back to second", func(t *testing.T) {
		var calls []string
		runner := CommandRunnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(args, " "))
			if len(calls) == 1 {
				return nil, errBoom{}
			}
			return nil, nil
		})
		plan := ScannerUpdatePlan{
			Name:           "Betterleaks",
			BinaryCommands: []string{"brew upgrade betterleaks", "sudo dnf upgrade betterleaks"},
		}
		if err := RunUpdatePlan(context.Background(), plan, UpdateOptions{Runner: runner}); err != nil {
			t.Fatalf("RunUpdatePlan should have succeeded via fallback: %v", err)
		}
		if len(calls) != 2 {
			t.Errorf("commands run = %d, want 2 (fallback after first fails)", len(calls))
		}
	})
	t.Run("all commands fail, returns last error", func(t *testing.T) {
		runner := CommandRunnerFunc(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return nil, errBoom{}
		})
		plan := ScannerUpdatePlan{
			Name:           "Betterleaks",
			BinaryCommands: []string{"x", "y"},
		}
		if err := RunUpdatePlan(context.Background(), plan, UpdateOptions{Runner: runner}); err == nil {
			t.Fatal("RunUpdatePlan should have errored when every command fails")
		}
	})
}

func TestInstallAndUpdatePlans(t *testing.T) {
	install := InstallPlan()
	if install.Name != "Betterleaks" || len(install.Commands) == 0 {
		t.Fatalf("InstallPlan = %+v, want commands", install)
	}
	update := UpdatePlan()
	if update.Name != "Betterleaks" || len(update.BinaryCommands) == 0 {
		t.Fatalf("UpdatePlan = %+v, want binary update commands", update)
	}
	if len(update.DatabaseCommands) != 0 {
		t.Fatalf("UpdatePlan DB commands = %v, want none", update.DatabaseCommands)
	}
}

func assertNoRawSecret(t *testing.T, f finding.Finding) {
	t.Helper()
	joined := strings.Join([]string{f.Title, f.Description, f.Match, f.Context, f.SuggestedFix}, "\n")
	if strings.Contains(joined, rawSecret) {
		t.Fatalf("finding leaked raw secret: %+v", f)
	}
}

func TestFormatCommandErrorRedactsStderr(t *testing.T) {
	err := formatCommandError("betterleaks", errBoom{}, []byte("leaked ghp_abcdefghijklmnopqrstuvwxyz1234567890SECRETZZZ"))
	msg := err.Error()
	if strings.Contains(msg, "ghp_abcdefghijklmnopqrstuvwxyz1234567890SECRETZZZ") {
		t.Fatalf("error leaked raw secret: %s", msg)
	}
	if !strings.Contains(msg, "<redacted:github-token>") {
		t.Fatalf("error did not include redaction marker: %s", msg)
	}
}

type errBoom struct{}

func (errBoom) Error() string { return "boom" }
