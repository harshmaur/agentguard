package depscan

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

func TestParseOSVScannerJSON_NormalizesFindings(t *testing.T) {
	input := []byte(`{
		"results": [{
			"source": {"path": "package-lock.json"},
			"packages": [{
				"package": {"name": "lodash", "ecosystem": "npm"},
				"version": "4.17.20",
				"vulnerabilities": [{
					"id": "GHSA-xxxx-yyyy-zzzz",
					"aliases": ["CVE-2021-23337"],
					"summary": "Command Injection in lodash",
					"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
					"database_specific": {"severity": "HIGH"},
					"affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]
				}]
			}]
		}]
	}`)

	findings, err := ParseOSVScannerJSON(input)
	if err != nil {
		t.Fatalf("ParseOSVScannerJSON err: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	got := findings[0]
	if got.RuleID != RuleOSVVulnerability {
		t.Fatalf("RuleID = %q", got.RuleID)
	}
	for _, want := range []string{"lodash", "4.17.20", "npm", "CVE-2021-23337"} {
		if !strings.Contains(got.Match, want) && !strings.Contains(got.Description, want) && !strings.Contains(got.Context, want) {
			t.Errorf("finding does not mention %q: %+v", want, got)
		}
	}
	if !strings.Contains(got.SuggestedFix, "4.17.21") {
		t.Errorf("SuggestedFix = %q, want fixed version", got.SuggestedFix)
	}
}

func TestParseTrivyJSON_NormalizesFindings(t *testing.T) {
	input := []byte(`{
		"Results": [{
			"Target": "poetry.lock",
			"Class": "lang-pkgs",
			"Type": "poetry",
			"Vulnerabilities": [{
				"VulnerabilityID": "CVE-2022-31129",
				"PkgName": "moment",
				"InstalledVersion": "2.29.1",
				"FixedVersion": "2.29.4",
				"Severity": "HIGH",
				"Title": "Path traversal"
			}]
		}]
	}`)

	findings, err := ParseTrivyJSON(input)
	if err != nil {
		t.Fatalf("ParseTrivyJSON err: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	got := findings[0]
	if got.RuleID != RuleTrivyVulnerability {
		t.Fatalf("RuleID = %q", got.RuleID)
	}
	for _, want := range []string{"moment", "2.29.1", "CVE-2022-31129"} {
		if !strings.Contains(got.Match, want) && !strings.Contains(got.Description, want) && !strings.Contains(got.Context, want) {
			t.Errorf("finding does not mention %q: %+v", want, got)
		}
	}
	if !strings.Contains(got.SuggestedFix, "2.29.4") {
		t.Errorf("SuggestedFix = %q, want fixed version", got.SuggestedFix)
	}
}

func TestInstallPlanIncludesOpenSourceScannerCommands(t *testing.T) {
	for _, backend := range []Backend{BackendOSVScanner, BackendTrivy} {
		plan := InstallPlan(backend)
		if plan.Name == "" || len(plan.Commands) == 0 {
			t.Fatalf("InstallPlan(%s) = %+v, want command", backend, plan)
		}
		if runtime.GOOS != "windows" && strings.Contains(strings.Join(plan.Commands, "\n"), "powershell") {
			t.Fatalf("unexpected windows-only command on %s: %+v", runtime.GOOS, plan)
		}
	}
}

func TestUpdatePlanIncludesBinaryAndDatabaseRefreshCommands(t *testing.T) {
	osv := UpdatePlan(BackendOSVScanner)
	if osv.Name == "" || len(osv.BinaryCommands) == 0 {
		t.Fatalf("UpdatePlan(OSV) = %+v, want binary update command", osv)
	}
	trivy := UpdatePlan(BackendTrivy)
	if trivy.Name == "" || len(trivy.BinaryCommands) == 0 || len(trivy.DatabaseCommands) == 0 {
		t.Fatalf("UpdatePlan(Trivy) = %+v, want binary and database update commands", trivy)
	}
	if !strings.Contains(strings.Join(trivy.DatabaseCommands, "\n"), "--download-db-only") {
		t.Fatalf("Trivy DB update commands = %v, want --download-db-only", trivy.DatabaseCommands)
	}
}

func TestRunUpdatePlanUsesInjectedRunner(t *testing.T) {
	var calls []string
	runner := CommandRunnerFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return []byte("ok"), nil
	})
	plan := ScannerUpdatePlan{Name: "Example", BinaryCommands: []string{"example upgrade"}, DatabaseCommands: []string{"example db"}}
	if err := RunUpdatePlan(context.Background(), plan, UpdateOptions{Runner: runner}); err != nil {
		t.Fatalf("RunUpdatePlan err: %v", err)
	}
	if len(calls) != 2 || !strings.Contains(calls[0], "example upgrade") || !strings.Contains(calls[1], "example db") {
		t.Fatalf("calls = %v, want binary then db update", calls)
	}
}

func TestRunUpdatePlanDBOnlySkipsBinaryCommands(t *testing.T) {
	var calls []string
	runner := CommandRunnerFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return []byte("ok"), nil
	})
	plan := ScannerUpdatePlan{Name: "Example", BinaryCommands: []string{"example upgrade"}, DatabaseCommands: []string{"example db"}}
	if err := RunUpdatePlan(context.Background(), plan, UpdateOptions{Runner: runner, DBOnly: true}); err != nil {
		t.Fatalf("RunUpdatePlan err: %v", err)
	}
	if len(calls) != 1 || !strings.Contains(calls[0], "example db") {
		t.Fatalf("calls = %v, want only db update", calls)
	}
}

func TestRunBackendUsesInjectedRunner(t *testing.T) {
	var called string
	runner := CommandRunnerFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		called = name + " " + strings.Join(args, " ")
		return []byte(`{"results": []}`), nil
	})
	findings, err := RunBackend(context.Background(), RunOptions{Backend: BackendOSVScanner, Roots: []string{"."}, Runner: runner})
	if err != nil {
		t.Fatalf("RunBackend err: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
	if !strings.Contains(called, "osv-scanner") || !strings.Contains(called, "--format") {
		t.Fatalf("called = %q, want osv-scanner --format json", called)
	}
}
