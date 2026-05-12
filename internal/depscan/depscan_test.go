package depscan

import (
	"context"
	"os"
	"path/filepath"
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

func TestInstallPlanIncludesOpenSourceScannerCommands(t *testing.T) {
	plan := InstallPlan(BackendOSVScanner)
	if plan.Name == "" || len(plan.Commands) == 0 {
		t.Fatalf("InstallPlan(OSV) = %+v, want command", plan)
	}
	if runtime.GOOS != "windows" && strings.Contains(strings.Join(plan.Commands, "\n"), "powershell") {
		t.Fatalf("unexpected windows-only command on %s: %+v", runtime.GOOS, plan)
	}
}

func TestUpdatePlanIncludesBinaryUpdateCommand(t *testing.T) {
	osv := UpdatePlan(BackendOSVScanner)
	if osv.Name == "" || len(osv.BinaryCommands) == 0 {
		t.Fatalf("UpdatePlan(OSV) = %+v, want binary update command", osv)
	}
	if len(osv.DatabaseCommands) != 0 {
		t.Fatalf("UpdatePlan(OSV) database commands = %v, want none", osv.DatabaseCommands)
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

func TestParseOSVScannerJSON_NormalizesV2PackageVersion(t *testing.T) {
	input := []byte(`{
		"results": [{
			"source": {"path": "pnpm-lock.yaml", "type": "lockfile"},
			"packages": [{
				"package": {"name": "@anthropic-ai/sdk", "version": "0.79.0", "ecosystem": "npm"},
				"vulnerabilities": [{
					"id": "GHSA-p7fg-763f-g4gf",
					"aliases": ["CVE-2026-41686"],
					"summary": "Unsafe file modes",
					"database_specific": {"severity": "HIGH"},
					"affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "0.91.1"}]}]}]
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
	if !strings.Contains(findings[0].Match, "@anthropic-ai/sdk@0.79.0") {
		t.Fatalf("Match = %q, want nested package version", findings[0].Match)
	}
}

func TestDiscoverProjectRootsFindsLockfileDirsAndSkipsHeavyDirs(t *testing.T) {
	dir := t.TempDir()
	project := filepath.Join(dir, "project")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	skipped := filepath.Join(dir, "node_modules", "nested")
	if err := os.MkdirAll(skipped, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skipped, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	roots, err := DiscoverProjectRoots([]string{dir})
	if err != nil {
		t.Fatalf("DiscoverProjectRoots err: %v", err)
	}
	if len(roots) != 1 || roots[0] != project {
		t.Fatalf("roots = %v, want [%s]", roots, project)
	}
}

func TestDiscoverProjectRootsFindsPackageJSONOnlyProjectsAndPrunesNestedRoots(t *testing.T) {
	dir := t.TempDir()
	project := filepath.Join(dir, "project")
	child := filepath.Join(project, "packages", "child")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"dependencies":{"lodash":"4.17.20"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(child, "requirements.txt"), []byte("praisonai==4.6.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	roots, err := DiscoverProjectRoots([]string{dir})
	if err != nil {
		t.Fatalf("DiscoverProjectRoots err: %v", err)
	}
	if len(roots) != 1 || roots[0] != project {
		t.Fatalf("roots = %v, want only parent package.json project %s", roots, project)
	}
}

func TestRunBackendUsesInjectedRunner(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	var called string
	runner := CommandRunnerFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		called = name + " " + strings.Join(args, " ")
		return []byte(`{"results": []}`), nil
	})
	findings, err := RunBackend(context.Background(), RunOptions{Backend: BackendOSVScanner, Roots: []string{dir}, Runner: runner})
	if err != nil {
		t.Fatalf("RunBackend err: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
	if !strings.Contains(called, "osv-scanner") || !strings.Contains(called, "scan source") || !strings.Contains(called, "--format json") {
		t.Fatalf("called = %q, want osv-scanner scan source --format json", called)
	}
}
