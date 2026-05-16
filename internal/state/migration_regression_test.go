package state

import (
	"context"
	"path/filepath"
	"testing"
)

// R1 (CRITICAL): the v2 → v3 migration wipes findings AND adds three
// new columns. Post-migration, the fingerprint-based reopen logic
// must still work — UpsertFinding for an existing fingerprint that was
// resolved should mark it opened=true with the new triage fields
// populated, not throw a schema error.
//
// This is the regression bar from the eng-review IRON-RULE list. Any
// change to the v3 migration body or the UpsertFinding SQL must keep
// this test green.
func TestV3MigrationPreservesReopenLogic(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "v3-reopen.db")
	s, err := Open(Options{Path: dbPath})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	go func() { _ = s.Run(context.Background()) }()

	// Sanity: v3 applied. AppliedMigrationsOnOpen returns the slice on
	// first open; on a brand-new DB all migrations run.
	applied := s.AppliedMigrationsOnOpen()
	foundV3 := false
	for _, v := range applied {
		if v == 3 {
			foundV3 = true
		}
	}
	if !foundV3 {
		t.Fatalf("expected v3 in applied migrations, got %v", applied)
	}

	scanID, err := s.OpenScan("all")
	if err != nil {
		t.Fatalf("OpenScan: %v", err)
	}

	f := Finding{
		Fingerprint:     "fp-reopen-test",
		RuleID:          "osv-npm-package",
		Severity:        "high",
		Category:        "deps",
		Kind:            "dep-package",
		Locator:         []byte(`{"manifest_path":"/some/lockfile"}`),
		Title:           "Vulnerable dependency: undici",
		Description:     "CVE-2025-1: prototype pollution",
		MatchRedacted:   "CVE-2025-1",
		DedupGroupKey:   "osv:npm:undici:5.28.4:",
		FixAuthority:    "you",
		SecondaryNotify: "",
		FirstSeenScan:   scanID,
		LastSeenScan:    scanID,
	}

	// First insert: brand-new finding, opened=true.
	opened, err := s.UpsertFinding(f)
	if err != nil {
		t.Fatalf("first UpsertFinding: %v", err)
	}
	if !opened {
		t.Error("first insert: expected opened=true (brand-new fingerprint)")
	}

	// Resolve it.
	changed, err := s.ResolveFinding(f.Fingerprint)
	if err != nil {
		t.Fatalf("ResolveFinding: %v", err)
	}
	if !changed {
		t.Error("ResolveFinding should report changed=true")
	}

	// Re-detect the SAME fingerprint after resolution — must reopen
	// (opened=true). This is the path that historically broke when the
	// UPDATE statements stopped matching the schema column list.
	f.LastSeenScan = scanID
	opened, err = s.UpsertFinding(f)
	if err != nil {
		t.Fatalf("reopen UpsertFinding: %v", err)
	}
	if !opened {
		t.Error("re-detection after resolution: expected opened=true (reopen)")
	}

	// Verify the new triage columns made it back out — the reopen path
	// MUST persist them, otherwise the dashboard's rolled-up view would
	// regress to empty groups.
	got, err := s.FindingByFingerprint(context.Background(), f.Fingerprint)
	if err != nil {
		t.Fatalf("FindingByFingerprint: %v", err)
	}
	if got.DedupGroupKey != f.DedupGroupKey {
		t.Errorf("DedupGroupKey lost across reopen: got %q want %q", got.DedupGroupKey, f.DedupGroupKey)
	}
	if got.FixAuthority != f.FixAuthority {
		t.Errorf("FixAuthority lost across reopen: got %q want %q", got.FixAuthority, f.FixAuthority)
	}
	if got.Open() != true {
		t.Error("finding should be Open() after reopen")
	}

	// Re-detect again WITHOUT resolving in between — opened=false
	// (still-open re-detection). The UPDATE path must also carry the
	// new triage fields forward.
	f.SecondaryNotify = "vercel" // simulate a re-classification on rescan
	opened, err = s.UpsertFinding(f)
	if err != nil {
		t.Fatalf("re-detection UpsertFinding: %v", err)
	}
	if opened {
		t.Error("still-open re-detection: expected opened=false")
	}
	got, err = s.FindingByFingerprint(context.Background(), f.Fingerprint)
	if err != nil {
		t.Fatalf("FindingByFingerprint after update: %v", err)
	}
	if got.SecondaryNotify != "vercel" {
		t.Errorf("SecondaryNotify update not persisted: got %q want %q", got.SecondaryNotify, "vercel")
	}
}

// TestV3MigrationAddsColumnsAndIndexes asserts the v3 migration body
// actually creates the three new columns and the supporting indexes.
// Without these the rollup query has no field to group on.
func TestV3MigrationAddsColumnsAndIndexes(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "v3-schema.db")
	s, err := Open(Options{Path: dbPath})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// Schema introspection via PRAGMA.
	rows, err := s.db.Query(`PRAGMA table_info(findings)`)
	if err != nil {
		t.Fatalf("PRAGMA table_info: %v", err)
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    any
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan PRAGMA row: %v", err)
		}
		columns[name] = true
	}
	for _, c := range []string{"dedup_group_key", "fix_authority", "secondary_notify"} {
		if !columns[c] {
			t.Errorf("findings table missing v3 column %q", c)
		}
	}

	// Indexes for the rollup query.
	idxRows, err := s.db.Query(`PRAGMA index_list(findings)`)
	if err != nil {
		t.Fatalf("PRAGMA index_list: %v", err)
	}
	defer idxRows.Close()
	indexes := map[string]bool{}
	for idxRows.Next() {
		var (
			seq     int
			name    string
			unique  int
			origin  string
			partial int
		)
		if err := idxRows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			t.Fatalf("scan index_list: %v", err)
		}
		indexes[name] = true
	}
	for _, ix := range []string{"findings_dedup_group", "findings_fix_authority"} {
		if !indexes[ix] {
			t.Errorf("findings table missing v3 index %q", ix)
		}
	}
}
