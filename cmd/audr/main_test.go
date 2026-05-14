package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/harshmaur/audr/internal/updater"
)

func TestResolveOutput(t *testing.T) {
	tests := []struct {
		name  string
		flags scanFlags
		// We cannot meaningfully assert browser-open or summary-dest from a
		// test environment without a TTY. Instead we assert on:
		// - format
		// - reportToStdout (the easy-to-verify slug of the routing decision)
		// - reportPath emptiness ("non-empty" when expecting a temp file)
		wantFormat         string
		wantReportToStdout bool
		wantReportPath     string // "" = don't care, "tmp" = expects /tmp/audr-...
		wantErr            bool
	}{
		{
			name:               "default html: temp file path",
			flags:              scanFlags{format: "html", openMode: "auto"},
			wantFormat:         "html",
			wantReportToStdout: false,
			wantReportPath:     "tmp",
		},
		{
			name:               "html with explicit -o path",
			flags:              scanFlags{format: "html", output: "/tmp/x.html", openMode: "auto"},
			wantFormat:         "html",
			wantReportToStdout: false,
			wantReportPath:     "/tmp/x.html",
		},
		{
			name:               "html with -o - forces stdout",
			flags:              scanFlags{format: "html", output: "-", openMode: "auto"},
			wantFormat:         "html",
			wantReportToStdout: true,
		},
		{
			name:               "sarif default goes to stdout",
			flags:              scanFlags{format: "sarif", openMode: "auto"},
			wantFormat:         "sarif",
			wantReportToStdout: true,
		},
		{
			name:               "sarif with -o file",
			flags:              scanFlags{format: "sarif", output: "/tmp/r.sarif", openMode: "auto"},
			wantFormat:         "sarif",
			wantReportToStdout: false,
			wantReportPath:     "/tmp/r.sarif",
		},
		{
			name:               "json default goes to stdout",
			flags:              scanFlags{format: "json", openMode: "auto"},
			wantFormat:         "json",
			wantReportToStdout: true,
		},
		{
			name:    "unknown format fails",
			flags:   scanFlags{format: "yaml", openMode: "auto"},
			wantErr: true,
		},
		{
			name:    "invalid open mode fails",
			flags:   scanFlags{format: "html", openMode: "maybe"},
			wantErr: true,
		},
		{
			name:               "uppercase format normalized",
			flags:              scanFlags{format: "HTML", openMode: "auto"},
			wantFormat:         "html",
			wantReportToStdout: false,
			wantReportPath:     "tmp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveOutput(tt.flags)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got plan=%+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.format != tt.wantFormat {
				t.Errorf("format = %q, want %q", got.format, tt.wantFormat)
			}
			if got.reportToStdout != tt.wantReportToStdout {
				t.Errorf("reportToStdout = %v, want %v", got.reportToStdout, tt.wantReportToStdout)
			}
			switch tt.wantReportPath {
			case "":
				// don't care
			case "tmp":
				if !strings.HasPrefix(got.reportPath, "/tmp/audr-") &&
					!strings.Contains(got.reportPath, "audr-") {
					t.Errorf("reportPath = %q, expected temp path containing 'audr-'", got.reportPath)
				}
			default:
				if got.reportPath != tt.wantReportPath {
					t.Errorf("reportPath = %q, want %q", got.reportPath, tt.wantReportPath)
				}
			}
		})
	}
}

func TestSelectedDependencyBackends(t *testing.T) {
	got, err := selectedDependencyBackends(scanFlags{depsBackend: "auto"})
	if err != nil {
		t.Fatalf("selectedDependencyBackends err: %v", err)
	}
	if len(got) != 1 || string(got[0]) != "osv-scanner" {
		t.Fatalf("auto backends = %v, want osv-scanner", got)
	}

	got, err = selectedDependencyBackends(scanFlags{depsBackend: "auto", deep: true})
	if err != nil {
		t.Fatalf("selectedDependencyBackends deep err: %v", err)
	}
	if len(got) != 1 || string(got[0]) != "osv-scanner" {
		t.Fatalf("deep backends = %v, want osv-scanner", got)
	}

	if _, err := selectedDependencyBackends(scanFlags{depsBackend: "bogus"}); err == nil {
		t.Fatalf("expected invalid backend error")
	}
}

func TestSecretScanSelection(t *testing.T) {
	if selectedSecretScan(scanFlags{}) {
		t.Fatalf("secret scan should be opt-in by default")
	}
	if !selectedSecretScan(scanFlags{secrets: true}) {
		t.Fatalf("--secrets should enable secret scanning")
	}
	if !selectedSecretScan(scanFlags{deep: true}) {
		t.Fatalf("--deep should include secret scanning")
	}
	if selectedSecretScan(scanFlags{deep: true, noSecrets: true}) {
		t.Fatalf("--no-secrets should override --deep")
	}
	if !selectedSecretScan(scanFlags{secretsOnly: true}) {
		t.Fatalf("--secrets-only should enable secret scanning")
	}
	if selectedSecretScan(scanFlags{depsOnly: true, deep: true}) {
		t.Fatalf("--deps-only should not run secret scanning")
	}
}

func TestRunDependencyBackendsSkipsWhenSecretsOnly(t *testing.T) {
	findings, warnings, err := runDependencyBackends(context.Background(), scanFlags{secretsOnly: true}, []string{"/path/that/does/not/exist"}, outPlan{})
	if err != nil {
		t.Fatalf("runDependencyBackends secrets-only err = %v, want nil", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %d, want 0", len(warnings))
	}
}

func TestValidateScanModesRejectsConflicts(t *testing.T) {
	for _, flags := range []scanFlags{
		{secretsOnly: true, noSecrets: true},
		{secretsOnly: true, depsOnly: true},
	} {
		if err := validateScanModes(flags); err == nil {
			t.Fatalf("validateScanModes(%+v) = nil, want conflict error", flags)
		}
	}
}

func TestDoctorCommandPrintsBackendHealth(t *testing.T) {
	cmd := newDoctorCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("doctor err: %v", err)
	}
	got := out.String()
	for _, want := range []string{"Audr doctor", "OSV-Scanner", "TruffleHog", "OSV-Scanner for dependency vulnerabilities", "TruffleHog for secret scanning", "update:"} {
		if !strings.Contains(got, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, got)
		}
	}
}

func TestUpdateScannersCommandDryRunPrintsCommands(t *testing.T) {
	cmd := newUpdateScannersCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	// --force bypasses the new latest-vs-installed check so the dry
	// run actually prints the would-run commands. Without it, this
	// test fails on any machine that has osv-scanner / trufflehog
	// already at the latest GitHub-release version (skip path
	// short-circuits before the dry-run print).
	cmd.SetArgs([]string{"--ci", "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("update-scanners dry run err: %v", err)
	}
	got := out.String()
	for _, want := range []string{"OSV-Scanner", "TruffleHog", "update:", "rerun with --yes"} {
		if !strings.Contains(got, want) {
			t.Fatalf("update-scanners output missing %q:\n%s", want, got)
		}
	}
}

func TestUpdateScannersCommandSupportsTruffleHogBackend(t *testing.T) {
	cmd := newUpdateScannersCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--backend", "trufflehog", "--ci", "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("update-scanners trufflehog dry run err: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "TruffleHog") {
		t.Fatalf("update-scanners output missing TruffleHog:\n%s", got)
	}
	if strings.Contains(got, "OSV-Scanner") {
		t.Fatalf("--backend trufflehog should not update OSV-Scanner:\n%s", got)
	}
}

// TestUpdateScannersSkipsWhenAlreadyAtLatest exercises the new
// installed-vs-latest check directly. Stubs the network probe via
// the actual binary version probe — when osv-scanner / trufflehog
// happen to be at GitHub's latest, the dry-run print is REPLACED
// by an "already up to date" message and the flow short-circuits.
// Failures on this test should report the actual installed + latest
// pair so the user knows whether to bump the test's expectation or
// fix the skip logic.
func TestUpdateScannersSkipsWhenAlreadyAtLatest(t *testing.T) {
	// This test only meaningfully runs when both scanners are
	// installed locally at GitHub's latest. Skip in the common case
	// where they aren't — leaves the assertion focused.
	osvLatest, _ := updaterLatestForTest("google", "osv-scanner")
	truffleLatest, _ := updaterLatestForTest("trufflesecurity", "trufflehog")
	if osvLatest == "" || truffleLatest == "" {
		t.Skip("GitHub API unreachable; skipping installed-vs-latest test")
	}
	osvInstalled := probeBinaryVersion(context.Background(), "osv-scanner")
	truffleInstalled := probeBinaryVersion(context.Background(), "trufflehog")
	if osvInstalled == "" || truffleInstalled == "" {
		t.Skip("scanner binaries not installed; skipping installed-vs-latest test")
	}

	cmd := newUpdateScannersCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--ci"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("update-scanners err: %v", err)
	}
	got := out.String()
	// When already-at-latest, output is the skip message rather
	// than the would-run "update:" lines.
	if !strings.Contains(got, "already up to date") {
		t.Fatalf("expected 'already up to date' in output when scanners are at latest, got:\n%s", got)
	}
	if !strings.Contains(got, "--force to reinstall") {
		t.Fatalf("output should mention --force escape hatch:\n%s", got)
	}
}

// updaterLatestForTest is a tiny wrapper around updater.LatestReleaseTag
// for tests. Kept local to avoid making the helper public.
func updaterLatestForTest(owner, repo string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return updater.LatestReleaseTag(ctx, owner, repo)
}

func TestUpdateScannersCommandRejectsInvalidBackend(t *testing.T) {
	cmd := newUpdateScannersCmd()
	cmd.SetArgs([]string{"--backend", "bogus", "--ci"})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected invalid backend error")
	}
}

func TestResolveOutput_NeverDisablesBrowser(t *testing.T) {
	// --open never must override even when stdout-TTY would otherwise open.
	plan, err := resolveOutput(scanFlags{format: "html", openMode: "never"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if plan.openBrowser {
		t.Errorf("--open never should disable openBrowser, got true")
	}
}

// TestVerifyCmd_TamperedExitsWithVerifyFailedSentinel exercises the
// verify subcommand against a tarball whose recorded SHA-256 doesn't match.
// The cobra RunE must return errVerifyFailed (not a generic error) so
// main()'s sentinel check exits 1 without prefixing "audr:" on stderr.
//
// Without this test, a future refactor could quietly drop errVerifyFailed
// from the sentinel branch and we'd only notice via the noisier stderr.
func TestVerifyCmd_TamperedExitsWithVerifyFailedSentinel(t *testing.T) {
	dir := t.TempDir()

	tarball := filepath.Join(dir, "audr-vTEST-linux-arm64.tar.gz")
	body := []byte("genuine release bytes")
	if err := os.WriteFile(tarball, body, 0o644); err != nil {
		t.Fatal(err)
	}

	// Sums file claims a hash that won't match — the verify subcommand
	// must surface this as errVerifyFailed.
	bogus := strings.Repeat("0", 64)
	sums := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(sums, []byte(bogus+"  "+filepath.Base(tarball)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := newVerifyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{tarball})

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected errVerifyFailed, got nil; output:\n%s", out.String())
	}
	if !errors.Is(err, errVerifyFailed) {
		t.Fatalf("expected errVerifyFailed sentinel, got %v (type %T)", err, err)
	}

	got := out.String()
	if !strings.Contains(got, "FAIL") {
		t.Errorf("expected output to contain a FAIL marker, got:\n%s", got)
	}
	if !strings.Contains(got, "verify: FAIL") {
		t.Errorf("expected 'verify: FAIL' verdict line, got:\n%s", got)
	}
}

// TestVerifyCmd_HappyPathExitsCleanly is the positive companion: when the
// SHA-256 matches, the subcommand returns nil and prints PASS.
func TestVerifyCmd_HappyPathExitsCleanly(t *testing.T) {
	dir := t.TempDir()

	tarball := filepath.Join(dir, "audr-vTEST-linux-arm64.tar.gz")
	body := []byte("genuine release bytes")
	if err := os.WriteFile(tarball, body, 0o644); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(body)
	sum := hex.EncodeToString(h[:])

	sums := filepath.Join(dir, "SHA256SUMS")
	line := fmt.Sprintf("%s  %s\n", sum, filepath.Base(tarball))
	if err := os.WriteFile(sums, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := newVerifyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{tarball})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v\noutput:\n%s", err, out.String())
	}
	got := out.String()
	if !strings.Contains(got, "verify: PASS") {
		t.Errorf("expected 'verify: PASS' verdict line, got:\n%s", got)
	}
}
