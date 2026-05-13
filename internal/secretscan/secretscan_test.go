package secretscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/finding"
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

	findings, err := RunBackend(context.Background(), RunOptions{Roots: []string{dir}, Runner: runner})
	if err != nil {
		t.Fatalf("RunBackend err: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	for _, want := range []string{"trufflehog", "filesystem", "--json", "--no-update", dir} {
		if !strings.Contains(called, want) {
			t.Fatalf("called = %q, missing %q", called, want)
		}
	}
	if strings.Contains(called, "--concurrency") {
		t.Fatalf("called = %q, must not pass --concurrency when Jobs is zero", called)
	}
}

func TestRunBackendPassesConcurrencyFlag(t *testing.T) {
	dir := t.TempDir()
	var called string
	runner := CommandRunnerFunc(func(_ context.Context, name string, args ...string) ([]byte, error) {
		called = name + " " + strings.Join(args, " ")
		return nil, nil
	})

	if _, err := RunBackend(context.Background(), RunOptions{Roots: []string{dir}, Jobs: 3, Runner: runner}); err != nil {
		t.Fatalf("RunBackend err: %v", err)
	}
	if !strings.Contains(called, "--concurrency=3") {
		t.Fatalf("called = %q, want --concurrency=3", called)
	}
	// Roots must follow the flag, not get re-ordered ahead of it (TruffleHog
	// treats trailing positional args as scan targets).
	flagIdx := strings.Index(called, "--concurrency=3")
	rootIdx := strings.Index(called, dir)
	if flagIdx < 0 || rootIdx < 0 || flagIdx > rootIdx {
		t.Fatalf("called = %q, expected --concurrency=3 before %s", called, dir)
	}
}

func TestDefaultJobsAtLeastOne(t *testing.T) {
	if got := DefaultJobs(); got < 1 {
		t.Fatalf("DefaultJobs() = %d, want >= 1", got)
	}
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
