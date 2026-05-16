package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// scratchHome forces audr's cache to land under a test-owned directory
// so the test doesn't pollute the real ~/.local/state/audr/. On Linux
// (where these E2E tests run via CI) daemon.Resolve consults
// XDG_STATE_HOME first, so overriding that alone is enough.
//
// Deliberately does NOT override HOME — doing so would redirect Go's
// own module cache to the temp dir, which (a) re-downloads every
// dependency per test and (b) leaves read-only mod-cache files behind
// that t.TempDir's cleanup can't remove on Linux.
//
// On non-Linux platforms daemon.Resolve uses ~/Library or %LOCALAPPDATA%
// directly without XDG, so these tests skip there. Cache wiring is
// platform-shared code; Linux coverage is sufficient for v1.1.
//
// Returns the path where audr.db will be written.
func scratchHome(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("scan cache E2E tests target Linux (XDG_STATE_HOME); other OSes covered by unit tests")
	}
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)
	return filepath.Join(dir, "audr", "audr.db")
}

// fixtureRepoWithOneFinding writes a small tree with exactly one
// MCP-plaintext-secret finding. Returns the tree root.
func fixtureRepoWithOneFinding(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mcp := filepath.Join(root, ".mcp.json")
	if err := os.WriteFile(mcp, []byte(`{
  "mcpServers": {
    "prod-gh": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }
    }
  }
}
`), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return root
}

// TestScanCache_WarmRunCreatesDBFile is the smallest cache-on-by-default
// check: after one scan, the audr.db SQLite file exists at the expected
// path. Confirms the default-on wiring fires.
func TestScanCache_WarmRunCreatesDBFile(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E binary build")
	}
	dbPath := scratchHome(t)
	bin := buildAudr(t)
	root := fixtureRepoWithOneFinding(t)

	_, _, err := runAudr(t, bin, "scan", root, "--no-deps", "--no-secrets", "-q")
	if err != nil && !isFindingsPresentExit(err) {
		t.Fatalf("scan: %v", err)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected audr.db at %s, stat err: %v", dbPath, err)
	}
}

// TestScanCache_NoCacheFlagSkipsDB asserts --no-cache does NOT
// materialize ~/.audr/audr.db. A user who never runs the daemon and
// passes --no-cache should leave no on-disk state.
func TestScanCache_NoCacheFlagSkipsDB(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E binary build")
	}
	dbPath := scratchHome(t)
	bin := buildAudr(t)
	root := fixtureRepoWithOneFinding(t)

	_, _, err := runAudr(t, bin, "scan", root, "--no-deps", "--no-secrets", "-q", "--no-cache")
	if err != nil && !isFindingsPresentExit(err) {
		t.Fatalf("scan: %v", err)
	}
	if _, err := os.Stat(dbPath); err == nil {
		t.Fatalf("--no-cache should NOT create %s; but it did", dbPath)
	} else if !os.IsNotExist(err) {
		t.Fatalf("unexpected stat error: %v", err)
	}
}

// TestScanCache_FindingsIdenticalAcrossRuns asserts the cache does not
// silently change scan output. Cold run, warm run, --no-cache run — all
// must produce the same list of finding ids.
func TestScanCache_FindingsIdenticalAcrossRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E binary build")
	}
	scratchHome(t)
	bin := buildAudr(t)
	root := fixtureRepoWithOneFinding(t)

	cold := captureFindingIDs(t, bin, root, false)
	warm := captureFindingIDs(t, bin, root, false)
	noCache := captureFindingIDs(t, bin, root, true)

	if !sameSet(cold, warm) {
		t.Errorf("cold vs warm cache diverged: cold=%v warm=%v", cold, warm)
	}
	if !sameSet(cold, noCache) {
		t.Errorf("cold vs --no-cache diverged: cold=%v noCache=%v", cold, noCache)
	}
	if len(cold) == 0 {
		t.Errorf("fixture expected at least one finding")
	}
}

// captureFindingIDs runs audr scan -f json -o - and returns the list of
// 12-char finding ids. Output goes through the new audr binary so the
// cache wiring is the real path.
func captureFindingIDs(t *testing.T, bin, root string, noCache bool) []string {
	t.Helper()
	args := []string{"scan", root, "-f", "json", "--no-deps", "--no-secrets"}
	if noCache {
		args = append(args, "--no-cache")
	}
	stdout, _, err := runAudr(t, bin, args...)
	if err != nil && !isFindingsPresentExit(err) {
		t.Fatalf("scan: %v", err)
	}
	jr, parseErr := parseReportFromMixed(stdout)
	if parseErr != nil {
		t.Fatalf("parse: %v\nOUT:\n%s", parseErr, stdout)
	}
	ids := make([]string, 0, len(jr.Findings))
	for _, f := range jr.Findings {
		ids = append(ids, f.StableID())
	}
	return ids
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	count := map[string]int{}
	for _, s := range a {
		count[s]++
	}
	for _, s := range b {
		count[s]--
	}
	for _, n := range count {
		if n != 0 {
			return false
		}
	}
	return true
}

// TestScanCache_StaleCacheInvalidatedOnMtimeChange asserts the
// (mtime, size, version) cache-key correctness: editing a file BUSTS
// the cache for that file (so a previously-clean row that's now
// vulnerable, or vice versa, is re-scanned).
func TestScanCache_StaleCacheInvalidatedOnMtimeChange(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E binary build")
	}
	scratchHome(t)
	bin := buildAudr(t)
	root := t.TempDir()
	target := filepath.Join(root, ".mcp.json")

	// Step 1: write a CLEAN config — no findings.
	if err := os.WriteFile(target, []byte(`{
  "mcpServers": {
    "ok": {
      "command": "/usr/local/bin/my-mcp-server"
    }
  }
}
`), 0o644); err != nil {
		t.Fatalf("write clean: %v", err)
	}
	clean := captureFindingIDs(t, bin, root, false)
	if len(clean) > 0 {
		// Some rules may still fire (e.g., absolute-path advisory). Doesn't
		// matter for this test — what matters is the SET that fires now
		// must be different from the set after we edit the file.
		t.Logf("clean fixture produced %d advisory findings: %v", len(clean), clean)
	}

	// Step 2: rewrite the file with a SECRET. Cache must invalidate
	// because mtime/size differ from the row we just wrote.
	if err := os.WriteFile(target, []byte(`{
  "mcpServers": {
    "prod-gh": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }
    }
  }
}
`), 0o644); err != nil {
		t.Fatalf("write dirty: %v", err)
	}

	dirty := captureFindingIDs(t, bin, root, false)
	if len(dirty) <= len(clean) {
		t.Errorf("expected MORE findings after introducing secret; clean=%d, dirty=%d (cache likely served stale row)",
			len(clean), len(dirty))
	}
	// Make sure the dirty set isn't a subset of clean (i.e., new ids appeared)
	cleanSet := map[string]struct{}{}
	for _, id := range clean {
		cleanSet[id] = struct{}{}
	}
	newCount := 0
	for _, id := range dirty {
		if _, ok := cleanSet[id]; !ok {
			newCount++
		}
	}
	if newCount == 0 {
		t.Errorf("dirty scan produced no NEW findings; cache may not have invalidated.\nclean=%v\ndirty=%v",
			clean, dirty)
	}
}

// TestScanCache_NoCacheAndBaselineCompose — combining --no-cache and
// --baseline must not crash and must still produce a baseline_diff
// section. The two flags address different concerns (one is about file
// parsing caching, the other is about scan-to-scan diffing); they're
// orthogonal.
func TestScanCache_NoCacheAndBaselineCompose(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E binary build")
	}
	scratchHome(t)
	bin := buildAudr(t)
	root := fixtureRepoWithOneFinding(t)

	before := filepath.Join(t.TempDir(), "before.json")
	if _, _, err := runAudr(t, bin, "scan", root, "-f", "json", "--no-deps", "--no-secrets", "--no-cache", "-o", before); err != nil && !isFindingsPresentExit(err) {
		t.Fatalf("baseline scan: %v", err)
	}
	stdout, _, err := runAudr(t, bin, "scan", root, "-f", "json", "--no-deps", "--no-secrets", "--no-cache", "--baseline="+before)
	if err != nil && !isFindingsPresentExit(err) {
		t.Fatalf("rescan: %v", err)
	}
	if !strings.Contains(stdout, "baseline_diff") {
		t.Fatalf("baseline_diff section missing when --no-cache + --baseline combined.\nOUT:\n%s", stdout)
	}
}
