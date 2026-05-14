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

func TestParseTruffleHogJSONLRedactsVerifiedFinding(t *testing.T) {
	input := []byte(`{"SourceMetadata":{"Data":{"Filesystem":{"file":"/repo/.env","line":12}}},"SourceName":"trufflehog - filesystem","DetectorName":"Github","DetectorType":8,"Verified":true,"Raw":"` + rawSecret + `","RawV2":"` + rawSecret + `","Redacted":"ghp_********SECRET","ExtraData":{"line":"12"}}` + "\n")

	findings, err := ParseTruffleHogJSONL(input)
	if err != nil {
		t.Fatalf("ParseTruffleHogJSONL err: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	got := findings[0]
	if got.RuleID != RuleTruffleHogVerified {
		t.Fatalf("RuleID = %q, want %q", got.RuleID, RuleTruffleHogVerified)
	}
	if got.Severity != finding.SeverityHigh {
		t.Fatalf("Severity = %s, want high", got.Severity)
	}
	if got.Path != "/repo/.env" || got.Line != 12 {
		t.Fatalf("location = %s:%d, want /repo/.env:12", got.Path, got.Line)
	}
	for _, want := range []string{"Github", "verified=true", "ghp_********SECRET"} {
		if !strings.Contains(got.Match+got.Context+got.Description, want) {
			t.Fatalf("finding missing %q: %+v", want, got)
		}
	}
	assertNoRawSecret(t, got)
}

func TestParseTruffleHogJSONLRedactsUnverifiedFindingWithoutRedactedField(t *testing.T) {
	input := []byte(`{"SourceMetadata":{"Data":{"Filesystem":{"file":"/repo/config.yml"}}},"DetectorName":"Slack","Verified":false,"Raw":"` + rawSecret + `"}` + "\n")

	findings, err := ParseTruffleHogJSONL(input)
	if err != nil {
		t.Fatalf("ParseTruffleHogJSONL err: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	got := findings[0]
	if got.RuleID != RuleTruffleHogUnverified {
		t.Fatalf("RuleID = %q, want %q", got.RuleID, RuleTruffleHogUnverified)
	}
	if got.Severity != finding.SeverityMedium {
		t.Fatalf("Severity = %s, want medium", got.Severity)
	}
	if !strings.Contains(got.Match, "[REDACTED]") {
		t.Fatalf("Match = %q, want fallback redaction token", got.Match)
	}
	assertNoRawSecret(t, got)
}

func TestRunBackendUsesInjectedRunner(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("TOKEN=x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var called string
	runner := CommandRunnerFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		called = name + " " + strings.Join(args, " ")
		return []byte(`{"SourceMetadata":{"Data":{"Filesystem":{"file":"` + filepath.Join(dir, ".env") + `","line":1}}},"DetectorName":"Test","Verified":true,"Redacted":"TOKEN=***"}` + "\n"), nil
	})

	// Pass Jobs explicitly so --concurrency is present in argv —
	// the v0.5.6 default (Jobs zero-value) is "uncapped, no flag."
	findings, err := RunBackend(context.Background(), RunOptions{Roots: []string{dir}, Runner: runner, Jobs: DefaultJobs()})
	if err != nil {
		t.Fatalf("RunBackend err: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	for _, want := range []string{"trufflehog", "filesystem", "--json", "--no-update", "--exclude-paths", "--concurrency=", dir} {
		if !strings.Contains(called, want) {
			t.Fatalf("called = %q, missing %q", called, want)
		}
	}
}

// TestRunBackendPassesScanignoreExcludeFile asserts the stopgap wiring: the
// TruffleHog invocation must include --exclude-paths pointing at a file
// whose contents match scanignore.Defaults() patterns. Without this, the
// scan walks node_modules and friends and pegs the laptop (the bug this
// stopgap fixes).
//
// The exclude file is captured + inspected inside the runner callback
// because RunBackend defers cleanup that removes the file before returning.
func TestRunBackendPassesScanignoreExcludeFile(t *testing.T) {
	var (
		capturedArgs        []string
		capturedExcludeBody string
		readErr             error
	)
	runner := CommandRunnerFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		capturedArgs = append([]string(nil), args...)
		// Find --exclude-paths value and slurp it while the file still exists.
		for i, a := range args {
			if a == "--exclude-paths" && i+1 < len(args) {
				raw, err := os.ReadFile(args[i+1])
				if err != nil {
					readErr = err
				} else {
					capturedExcludeBody = string(raw)
				}
				break
			}
		}
		return nil, nil
	})

	// Pass Jobs explicitly to verify --concurrency is wired through.
	_, err := RunBackend(context.Background(), RunOptions{Roots: []string{t.TempDir()}, Runner: runner, Jobs: DefaultJobs()})
	if err != nil {
		t.Fatalf("RunBackend err: %v", err)
	}
	if readErr != nil {
		t.Fatalf("read exclude file inside runner: %v", readErr)
	}

	// --exclude-paths must be present in args.
	hasExcludePathsFlag := false
	for _, a := range capturedArgs {
		if a == "--exclude-paths" {
			hasExcludePathsFlag = true
			break
		}
	}
	if !hasExcludePathsFlag {
		t.Fatalf("--exclude-paths not in args: %v", capturedArgs)
	}
	if capturedExcludeBody == "" {
		t.Fatalf("exclude file body was empty")
	}

	for _, segment := range scanignore.Defaults() {
		if !strings.Contains(capturedExcludeBody, segment) {
			t.Fatalf("exclude file missing segment %q; body:\n%s", segment, capturedExcludeBody)
		}
	}

	// Confirm --concurrency= is set to a positive integer.
	var concurrencyArg string
	for _, a := range capturedArgs {
		if strings.HasPrefix(a, "--concurrency=") {
			concurrencyArg = a
			break
		}
	}
	if concurrencyArg == "" {
		t.Fatalf("--concurrency=<n> not in args: %v", capturedArgs)
	}
	if concurrencyArg == "--concurrency=0" {
		t.Fatalf("concurrency must be >= 1, got %q", concurrencyArg)
	}
}

// TestRunBackendJobsZeroOmitsConcurrencyFlag pins the semantic
// introduced in PR #9 (Alex Umrysh): Jobs == 0 means "uncapped —
// let TruffleHog use its own default (NumCPU)." The
// --concurrency= flag is omitted entirely in that case so the user
// can opt into TruffleHog's full-throttle mode via `--scanner-jobs 0`.
func TestRunBackendJobsZeroOmitsConcurrencyFlag(t *testing.T) {
	var captured []string
	runner := CommandRunnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		captured = append([]string(nil), args...)
		return nil, nil
	})
	_, _ = RunBackend(context.Background(), RunOptions{Roots: []string{t.TempDir()}, Runner: runner, Jobs: 0})
	for _, a := range captured {
		if strings.HasPrefix(a, "--concurrency=") {
			t.Fatalf("Jobs=0 must not pass --concurrency; got %q in args: %v", a, captured)
		}
	}
}

// TestRunBackendJobsPositivePassesConcurrency: explicit Jobs > 0
// → `--concurrency=N` lands at the expected position (before the
// scan roots so trufflehog parses it as a flag, not a target).
func TestRunBackendJobsPositivePassesConcurrency(t *testing.T) {
	var captured []string
	runner := CommandRunnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		captured = append([]string(nil), args...)
		return nil, nil
	})
	root := t.TempDir()
	_, _ = RunBackend(context.Background(), RunOptions{Roots: []string{root}, Runner: runner, Jobs: 7})

	wantFlag := "--concurrency=7"
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
		t.Fatalf("--concurrency must come before root path; flagIdx=%d rootIdx=%d args=%v",
			flagIdx, rootIdx, captured)
	}
}

// TestDefaultJobsIsAtLeastOne — DefaultJobs() must never return
// zero (would silently disable the cap). On a 1-CPU machine, half
// would round to 0; the helper has a min-1 floor.
func TestDefaultJobsIsAtLeastOne(t *testing.T) {
	if got := DefaultJobs(); got < 1 {
		t.Errorf("DefaultJobs() = %d, want >= 1", got)
	}
}

// TestRunUpdatePlanTreatsCommandsAsFallbacks pins the semantic that
// BinaryCommands are alternatives, not sequential steps. A user
// with a working brew install of trufflehog would otherwise hit the
// go-install fallback (which fails because TruffleHog's go.mod has
// replace directives) right after brew succeeded.
func TestRunUpdatePlanTreatsCommandsAsFallbacks(t *testing.T) {
	t.Run("first command succeeds, rest are skipped", func(t *testing.T) {
		var calls []string
		runner := CommandRunnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(args, " "))
			return nil, nil // success
		})
		plan := ScannerUpdatePlan{
			Name: "TruffleHog",
			BinaryCommands: []string{
				"brew upgrade trufflehog",
				"go install github.com/trufflesecurity/trufflehog/v3@latest",
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
			return nil, nil // second one succeeds
		})
		plan := ScannerUpdatePlan{
			Name:           "TruffleHog",
			BinaryCommands: []string{"brew upgrade trufflehog", "go install ..."},
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
			Name:           "TruffleHog",
			BinaryCommands: []string{"x", "y"},
		}
		if err := RunUpdatePlan(context.Background(), plan, UpdateOptions{Runner: runner}); err == nil {
			t.Fatal("RunUpdatePlan should have errored when every command fails")
		}
	})
}

func TestInstallAndUpdatePlans(t *testing.T) {
	install := InstallPlan()
	if install.Name != "TruffleHog" || len(install.Commands) == 0 {
		t.Fatalf("InstallPlan = %+v, want commands", install)
	}
	update := UpdatePlan()
	if update.Name != "TruffleHog" || len(update.BinaryCommands) == 0 {
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
	err := formatCommandError("trufflehog", errBoom{}, []byte("leaked ghp_abcdefghijklmnopqrstuvwxyz1234567890SECRETZZZ"))
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
