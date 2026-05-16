package state

import (
	"context"
	"testing"
)

func TestListRolledUp_GroupsByDedupKey(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	scanID, err := s.OpenScan("all")
	if err != nil {
		t.Fatalf("OpenScan: %v", err)
	}

	// Two findings of the same vulnerability across two paths in
	// different fix-authority buckets — exactly the design's "23 rows
	// collapse to 1 row with 3 sub-groups" case, in miniature.
	mustUpsert(t, s, Finding{
		Fingerprint:     "fp-user-path",
		RuleID:          "dependency-osv-vulnerability",
		Severity:        "high",
		Category:        "deps",
		Kind:            "dep-package",
		Locator:         []byte(`{"path":"/home/alice/projects/audr/package-lock.json"}`),
		Title:           "Vulnerable dependency: undici",
		Description:     "undici < 5.28.4",
		DedupGroupKey:   "osv:npm:undici:5.28.4:CVE-2025-1",
		FixAuthority:    "you",
		SecondaryNotify: "",
		FirstSeenScan:   scanID,
		LastSeenScan:    scanID,
		FirstSeenAt:     1000,
	})
	mustUpsert(t, s, Finding{
		Fingerprint:     "fp-plugin-cache-path",
		RuleID:          "dependency-osv-vulnerability",
		Severity:        "high",
		Category:        "deps",
		Kind:            "dep-package",
		Locator:         []byte(`{"path":"/home/alice/.claude/plugins/cache/vercel/0.42.1/bun.lock"}`),
		Title:           "Vulnerable dependency: undici",
		Description:     "undici < 5.28.4",
		DedupGroupKey:   "osv:npm:undici:5.28.4:CVE-2025-1",
		FixAuthority:    "maintainer",
		SecondaryNotify: "vercel",
		FirstSeenScan:   scanID,
		LastSeenScan:    scanID,
		FirstSeenAt:     1100,
	})
	// A second unrelated vuln to confirm the result is multi-row.
	mustUpsert(t, s, Finding{
		Fingerprint:   "fp-second-vuln",
		RuleID:        "claude-hook-shell-rce",
		Severity:      "critical",
		Category:      "ai-agent",
		Kind:          "file",
		Locator:       []byte(`{"path":"/home/alice/projects/audr/.claude/settings.json"}`),
		Title:         "Hook executes shell command",
		Description:   "settings.json hook ships RCE",
		DedupGroupKey: "claude-hook-shell-rce:abcdef",
		FixAuthority:  "you",
		FirstSeenScan: scanID,
		LastSeenScan:  scanID,
		FirstSeenAt:   900,
	})

	rows, err := s.ListRolledUp(ctx, 0)
	if err != nil {
		t.Fatalf("ListRolledUp: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rolled-up rows (1 undici + 1 hook), got %d", len(rows))
	}

	// Sort order: critical hook row first, then high undici row.
	if rows[0].WorstSeverity != "critical" {
		t.Errorf("row[0] worst severity = %q, want critical", rows[0].WorstSeverity)
	}
	if rows[1].DedupGroupKey != "osv:npm:undici:5.28.4:CVE-2025-1" {
		t.Errorf("row[1] dedup key = %q, want undici osv key", rows[1].DedupGroupKey)
	}

	// The undici row must show PathCount=2 and have BOTH groups (YOU + MAINTAINER).
	undici := rows[1]
	if undici.PathCount != 2 {
		t.Errorf("undici PathCount = %d, want 2", undici.PathCount)
	}
	if len(undici.Groups) != 2 {
		t.Fatalf("undici should have 2 fix-authority groups, got %d", len(undici.Groups))
	}
	// YOU bucket comes first in orderedAuthorities().
	if undici.Groups[0].FixAuthority != "you" {
		t.Errorf("first group = %q, want 'you'", undici.Groups[0].FixAuthority)
	}
	if undici.Groups[0].PathCount != 1 {
		t.Errorf("YOU bucket PathCount = %d, want 1", undici.Groups[0].PathCount)
	}
	if undici.Groups[1].FixAuthority != "maintainer" {
		t.Errorf("second group = %q, want 'maintainer'", undici.Groups[1].FixAuthority)
	}
	if undici.Groups[1].SecondaryNotify != "vercel" {
		t.Errorf("MAINTAINER bucket SecondaryNotify = %q, want 'vercel'", undici.Groups[1].SecondaryNotify)
	}
	// Earliest first_seen wins.
	if undici.WorstFirstSeen != 1000 {
		t.Errorf("WorstFirstSeen = %d, want 1000", undici.WorstFirstSeen)
	}
}

func TestListRolledUp_HidesResolved(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	scanID, _ := s.OpenScan("all")

	mustUpsert(t, s, Finding{
		Fingerprint:   "fp-open",
		RuleID:        "rx",
		Severity:      "high",
		Category:      "deps",
		Kind:          "dep-package",
		Locator:       []byte(`{"path":"/x/a"}`),
		Title:         "open vuln",
		DedupGroupKey: "rx:open",
		FixAuthority:  "you",
		FirstSeenScan: scanID,
		LastSeenScan:  scanID,
		FirstSeenAt:   1,
	})
	mustUpsert(t, s, Finding{
		Fingerprint:   "fp-resolved",
		RuleID:        "rx",
		Severity:      "high",
		Category:      "deps",
		Kind:          "dep-package",
		Locator:       []byte(`{"path":"/x/b"}`),
		Title:         "soon-resolved vuln",
		DedupGroupKey: "rx:will-resolve",
		FixAuthority:  "you",
		FirstSeenScan: scanID,
		LastSeenScan:  scanID,
		FirstSeenAt:   2,
	})
	if _, err := s.ResolveFinding("fp-resolved"); err != nil {
		t.Fatalf("ResolveFinding: %v", err)
	}

	rows, err := s.ListRolledUp(ctx, 0)
	if err != nil {
		t.Fatalf("ListRolledUp: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected only the open finding's group, got %d rows", len(rows))
	}
	if rows[0].DedupGroupKey != "rx:open" {
		t.Errorf("got group %q, want 'rx:open'", rows[0].DedupGroupKey)
	}
}

func TestListRolledUp_PathsPerGroupCap(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	scanID, _ := s.OpenScan("all")

	// 5 paths in one bucket; cap at 2.
	for i := 0; i < 5; i++ {
		mustUpsert(t, s, Finding{
			Fingerprint:   "fp" + string(rune('a'+i)),
			RuleID:        "rx",
			Severity:      "medium",
			Category:      "deps",
			Kind:          "dep-package",
			Locator:       []byte(`{"path":"/x/p` + string(rune('a'+i)) + `"}`),
			Title:         "same vuln",
			DedupGroupKey: "rx:samekey",
			FixAuthority:  "you",
			FirstSeenScan: scanID,
			LastSeenScan:  scanID,
			FirstSeenAt:   int64(i + 1),
		})
	}
	rows, err := s.ListRolledUp(ctx, 2)
	if err != nil {
		t.Fatalf("ListRolledUp: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].PathCount != 5 {
		t.Errorf("PathCount (full) = %d, want 5", rows[0].PathCount)
	}
	if len(rows[0].Groups) != 1 {
		t.Fatalf("want 1 group, got %d", len(rows[0].Groups))
	}
	if rows[0].Groups[0].PathCount != 5 {
		t.Errorf("group total PathCount = %d, want 5", rows[0].Groups[0].PathCount)
	}
	if len(rows[0].Groups[0].Paths) != 2 {
		t.Errorf("group Paths slice length = %d, want cap=2", len(rows[0].Groups[0].Paths))
	}
}

func TestListRolledUp_PathFromLocator(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	scanID, _ := s.OpenScan("all")

	mustUpsert(t, s, Finding{
		Fingerprint:   "fp1",
		RuleID:        "rx",
		Severity:      "low",
		Category:      "deps",
		Kind:          "dep-package",
		Locator:       []byte(`{"path":"/some/escaped\\path","kind":"file"}`),
		Title:         "x",
		DedupGroupKey: "rx:1",
		FixAuthority:  "you",
		FirstSeenScan: scanID,
		LastSeenScan:  scanID,
	})

	rows, err := s.ListRolledUp(ctx, 0)
	if err != nil {
		t.Fatalf("ListRolledUp: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	got := rows[0].Groups[0].Paths[0].Path
	if got != `/some/escaped\path` {
		t.Errorf("path extraction got %q, want %q", got, `/some/escaped\path`)
	}
}

// Regression: dep-package locators store the lockfile path under
// "manifest_path", not "path". An earlier rollup-query bug only
// matched the "path" key, so the dashboard rendered every dep
// finding's path as "(no path)". Caught by dogfood; this test
// pins the fix so it can't slip back.
func TestListRolledUp_DepPackageManifestPath(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	scanID, _ := s.OpenScan("all")

	mustUpsert(t, s, Finding{
		Fingerprint: "fp-dep",
		RuleID:      "osv-npm-package",
		Severity:    "high",
		Category:    "deps",
		Kind:        "dep-package",
		Locator: []byte(`{
			"ecosystem": "npm",
			"name": "undici",
			"version": "5.27.0",
			"manifest_path": "/home/alice/projects/audr/web/package-lock.json"
		}`),
		Title:         "Vulnerable dependency: undici",
		DedupGroupKey: "osv:npm:undici:5.28.4:CVE-2025-1",
		FixAuthority:  "you",
		FirstSeenScan: scanID,
		LastSeenScan:  scanID,
	})

	rows, err := s.ListRolledUp(ctx, 0)
	if err != nil {
		t.Fatalf("ListRolledUp: %v", err)
	}
	if len(rows) != 1 || len(rows[0].Groups) != 1 || len(rows[0].Groups[0].Paths) != 1 {
		t.Fatalf("unexpected row shape: %+v", rows)
	}
	got := rows[0].Groups[0].Paths[0].Path
	want := "/home/alice/projects/audr/web/package-lock.json"
	if got != want {
		t.Errorf("dep-package path = %q, want %q (manifest_path fallback broken)", got, want)
	}
}

func mustUpsert(t *testing.T, s *Store, f Finding) {
	t.Helper()
	if _, err := s.UpsertFinding(f); err != nil {
		t.Fatalf("UpsertFinding(%s): %v", f.Fingerprint, err)
	}
}
