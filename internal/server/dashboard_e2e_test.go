package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/harshmaur/audr/internal/daemon"
	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/state"
)

// E2E suite for the v1.3 rolled-up dashboard. Integration tests run
// against the actual HTTP server with a real state.Store backing it.
// Each test corresponds to one row in the eng-review coverage diagram.
//
// Flows that REQUIRE a real browser (E2E-4 "paste + npm i", E2E-6
// "30d snooze persists across scans") are documented in the v1.3 CHANGELOG
// as manual-QA steps — they're behavioral rather than wire-shape, and
// faking a Chrome session for them is more brittle than valuable.

// e2eTestServer seeds N rolled-up rows so the dashboard endpoints have
// realistic shape to assert against. Returns the live server + a
// per-test sample finding the maintainer/snippet endpoints can target.
func e2eTestServer(t *testing.T) (*Server, state.Finding) {
	t.Helper()
	dir := t.TempDir()
	p := daemon.Paths{
		State: filepath.Join(dir, "state"),
		Logs:  filepath.Join(dir, "logs"),
	}
	if err := p.Ensure(); err != nil {
		t.Fatalf("ensure paths: %v", err)
	}
	store, err := state.Open(state.Options{Path: filepath.Join(p.State, "audr.db")})
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel() })
	go func() { _ = store.Run(ctx) }()
	time.Sleep(5 * time.Millisecond)
	t.Cleanup(func() { _ = store.Close() })

	scanID, err := store.OpenScan("all")
	if err != nil {
		t.Fatalf("OpenScan: %v", err)
	}

	// Seed three vulnerability scenarios that cover all three
	// fix-authority buckets exactly once.
	sample := state.Finding{
		Fingerprint:   "fp-undici-user",
		RuleID:        "osv-npm-package",
		Severity:      finding.SeverityHigh.String(),
		Category:      "deps",
		Kind:          "dep-package",
		Locator:       []byte(`{"manifest_path":"/home/u/projects/audr/package-lock.json","ecosystem":"npm","name":"undici"}`),
		Title:         "Vulnerable dependency: undici",
		Description:   "CVE-2025-1: prototype pollution",
		MatchRedacted: "CVE-2025-1",
		DedupGroupKey: "osv:npm:undici:5.28.4:",
		FixAuthority:  "you",
		FirstSeenScan: scanID,
		LastSeenScan:  scanID,
	}
	if _, err := store.UpsertFinding(sample); err != nil {
		t.Fatalf("UpsertFinding sample: %v", err)
	}
	if _, err := store.UpsertFinding(state.Finding{
		Fingerprint:     "fp-undici-vercel",
		RuleID:          "osv-npm-package",
		Severity:        finding.SeverityHigh.String(),
		Category:        "deps",
		Kind:            "dep-package",
		Locator:         []byte(`{"manifest_path":"/home/u/.claude/plugins/cache/vercel/0.42.1/bun.lock","ecosystem":"npm","name":"undici"}`),
		Title:           "Vulnerable dependency: undici",
		Description:     "CVE-2025-1: prototype pollution",
		MatchRedacted:   "CVE-2025-1",
		DedupGroupKey:   "osv:npm:undici:5.28.4:",
		FixAuthority:    "maintainer",
		SecondaryNotify: "vercel",
		FirstSeenScan:   scanID,
		LastSeenScan:    scanID,
	}); err != nil {
		t.Fatalf("UpsertFinding maintainer: %v", err)
	}
	if _, err := store.UpsertFinding(state.Finding{
		Fingerprint:   "fp-undici-upstream",
		RuleID:        "osv-npm-package",
		Severity:      finding.SeverityHigh.String(),
		Category:      "deps",
		Kind:          "dep-package",
		Locator:       []byte(`{"manifest_path":"/home/u/.claude/plugins/marketplaces/foo/external_plugins/discord/bun.lock","ecosystem":"npm","name":"undici"}`),
		Title:         "Vulnerable dependency: undici",
		Description:   "CVE-2025-1: prototype pollution",
		MatchRedacted: "CVE-2025-1",
		DedupGroupKey: "osv:npm:undici:5.28.4:",
		FixAuthority:  "upstream",
		FirstSeenScan: scanID,
		LastSeenScan:  scanID,
	}); err != nil {
		t.Fatalf("UpsertFinding upstream: %v", err)
	}

	rem, err := NewDemoRemediation()
	if err != nil {
		t.Fatalf("NewDemoRemediation: %v", err)
	}
	s, err := NewServer(Options{
		Paths:       p,
		Store:       store,
		Remediation: rem,
		ListenHost:  "127.0.0.1",
		Version:     "v1.3-test",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := s.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	go func() { _ = s.Run(context.Background()) }()
	t.Cleanup(func() { _ = s.Close() })
	return s, sample
}

// E2E-1: scan → dashboard returns rolled-up rows. The seeded scenario
// has 3 findings sharing one dedup key → exactly 1 rolled-up row.
func TestE2E_RollupReturnsAggregatedRows(t *testing.T) {
	s, _ := e2eTestServer(t)
	resp := mustDo(t, s, "GET", "/api/findings/rollup?t="+s.Token(), "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body RolledUpResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Rows) != 1 {
		t.Fatalf("expected 1 rolled-up row, got %d", len(body.Rows))
	}
	row := body.Rows[0]
	if row.PathCount != 3 {
		t.Errorf("PathCount = %d, want 3 (one per fix-authority)", row.PathCount)
	}
	if !strings.Contains(row.Title, "undici") {
		t.Errorf("title %q missing 'undici'", row.Title)
	}
}

// E2E-2: rolled-up row has the three fix-authority sub-groups in the
// canonical order (you → maintainer → upstream).
func TestE2E_RollupExposesThreeFixAuthorityGroups(t *testing.T) {
	s, _ := e2eTestServer(t)
	resp := mustDo(t, s, "GET", "/api/findings/rollup?t="+s.Token(), "")
	defer resp.Body.Close()
	var body RolledUpResponse
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if len(body.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(body.Rows))
	}
	groups := body.Rows[0].Groups
	if len(groups) != 3 {
		t.Fatalf("expected 3 fix-authority groups, got %d", len(groups))
	}
	wantOrder := []string{"you", "maintainer", "upstream"}
	for i, want := range wantOrder {
		if groups[i].FixAuthority != want {
			t.Errorf("groups[%d].FixAuthority = %q, want %q", i, groups[i].FixAuthority, want)
		}
		if groups[i].PathCount != 1 {
			t.Errorf("groups[%d].PathCount = %d, want 1", i, groups[i].PathCount)
		}
	}
	// MAINTAINER bucket should surface the vendor hint.
	if groups[1].SecondaryNotify != "vercel" {
		t.Errorf("MAINTAINER SecondaryNotify = %q, want vercel", groups[1].SecondaryNotify)
	}
}

// E2E-3: copy-snippet endpoint returns a format-appropriate override
// snippet for a YOU-bucket dep finding.
func TestE2E_CopySnippetRendersForUserPath(t *testing.T) {
	s, sample := e2eTestServer(t)
	resp := mustDo(t, s, "GET", "/api/remediate/snippet/"+sample.Fingerprint+"?t="+s.Token(), "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body RemediateSnippetResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(body.Snippet, `"undici"`) {
		t.Errorf("snippet missing package name: %s", body.Snippet)
	}
	if !strings.Contains(body.Snippet, `"^5.28.4"`) {
		t.Errorf("snippet missing fixed-version pin: %s", body.Snippet)
	}
	if !strings.Contains(body.Snippet, `"overrides"`) {
		t.Errorf("snippet missing npm 'overrides' key: %s", body.Snippet)
	}
	if body.Disclaimer == "" {
		t.Error("Disclaimer empty — F3 mitigation MUST always render alongside non-empty snippets")
	}
	if body.LockfileFmt != "npm" {
		t.Errorf("LockfileFmt = %q, want npm", body.LockfileFmt)
	}
}

// E2E-5: file-issue endpoint returns a pre-filled GitHub URL for a
// known maintainer + a copy-fallback body for clipboard pasting.
func TestE2E_FileIssueReturnsPrefilledURL(t *testing.T) {
	s, _ := e2eTestServer(t)
	resp := mustDo(t, s, "GET", "/api/remediate/maintainer/fp-undici-vercel?t="+s.Token(), "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body RemediateMaintainerResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(body.IssueURL, "github.com/vercel/claude-plugins-official") {
		t.Errorf("IssueURL points at wrong repo: %q", body.IssueURL)
	}
	if !strings.Contains(body.IssueURL, "title=") || !strings.Contains(body.IssueURL, "body=") {
		t.Errorf("IssueURL missing prefill query: %q", body.IssueURL)
	}
	if body.LabelHint != "Vercel" {
		t.Errorf("LabelHint = %q, want Vercel", body.LabelHint)
	}
	if !strings.Contains(body.BodyMarkdown, "undici") {
		t.Errorf("body missing package name: %s", body.BodyMarkdown)
	}
	if !strings.Contains(body.BodyMarkdown, "5.28.4") {
		t.Errorf("body missing fixed version: %s", body.BodyMarkdown)
	}
}

// E2E-7: the dashboard index page is the rolled-up landing — no
// parallel page, no /audit alias. (We removed the parallel page in
// the design-feedback cycle.)
func TestE2E_RootServesDashboardWithExpectedAssets(t *testing.T) {
	s, _ := e2eTestServer(t)
	resp := mustDo(t, s, "GET", "/?t="+s.Token(), "")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	for _, want := range []string{"audr", "dashboard.js", "dashboard.css"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("/ body missing %q", want)
		}
	}
	for _, mustNotHave := range []string{"rollup.js", "rollup.css"} {
		if strings.Contains(string(body), mustNotHave) {
			t.Errorf("/ MUST NOT reference %q (parallel page was removed)", mustNotHave)
		}
	}
}

// E2E-8: schema migration completes cleanly + AppliedMigrationsOnOpen
// surfaces v3 for the daemon CLI to emit the baseline-reset notice.
// This is the integration-level proof for T13 — the cmd/audr handler
// only PRINTS based on what state.Store exposes, so testing the
// exposure point covers the user-visible behavior.
func TestE2E_MigrationSurfacesV3ForBaselineNotice(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(state.Options{Path: filepath.Join(dir, "fresh.db")})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()
	applied := store.AppliedMigrationsOnOpen()
	foundV3 := false
	for _, v := range applied {
		if v == 3 {
			foundV3 = true
		}
	}
	if !foundV3 {
		t.Errorf("AppliedMigrationsOnOpen() = %v; daemon would never emit the v1.3 baseline notice", applied)
	}

	// Second open: migration is no-op, slice is empty — notice must
	// not fire twice.
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened, err := state.Open(state.Options{Path: filepath.Join(dir, "fresh.db")})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if got := reopened.AppliedMigrationsOnOpen(); len(got) != 0 {
		t.Errorf("re-Open applied = %v, want empty (notice must not fire twice)", got)
	}
}

// E2E-4 ("paste snippet → npm i → rescan clears finding") and
// E2E-6 ("track-upstream 30d snooze persists across scans") are
// covered by manual QA — they require a real package manager and a
// real time-machine for the snooze deadline. See CHANGELOG.md v1.3
// for the manual-QA script.
