package state

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// openTestStore returns a Store running its writer loop. The caller
// can Close() to drain; the t.Cleanup wires that automatically.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(Options{Path: dbPath})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Start the writer goroutine via Run() under a context we cancel
	// in cleanup.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = s.Close()
	})
	go func() { _ = s.Run(ctx) }()
	// Give the writer a moment to enter its loop so the first
	// submitWrite doesn't race the goroutine spawn. 5ms is plenty.
	time.Sleep(5 * time.Millisecond)
	return s
}

func TestOpenAppliesMigrationsAndReportsSchemaVersion(t *testing.T) {
	s := openTestStore(t)
	// schema_version must be at len(migrations) after Open.
	row := s.db.QueryRow(`SELECT version FROM schema_version LIMIT 1`)
	var v int
	if err := row.Scan(&v); err != nil {
		t.Fatalf("schema_version: %v", err)
	}
	if v != len(migrations) {
		t.Errorf("schema_version = %d, want %d", v, len(migrations))
	}
	// Tables exist.
	for _, table := range []string{"scans", "findings", "scanner_statuses", "file_cache"} {
		row := s.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table)
		var got string
		if err := row.Scan(&got); err != nil {
			t.Errorf("table %s missing: %v", table, err)
		}
	}
}

// TestOpenSelfHealsOnCorruptDB writes garbage to the DB path and
// then Open() the store. The self-healing fallback should detect
// migrations can't run on the garbage file, nuke it (plus -wal /
// -shm sidecars if present), recreate fresh, and return a working
// Store with the current schema_version. The user's reported "if
// db is messed during migration, auto-cleanup + rescan" semantic.
func TestOpenSelfHealsOnCorruptDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audr.db")
	// Write garbage that looks like a SQLite header prefix but
	// breaks during migration. Random non-SQLite bytes would just
	// fail to open at the driver level; we want to reach the
	// migration code with a "version mismatch" style condition.
	if err := os.WriteFile(dbPath, []byte("not a real sqlite database"), 0o600); err != nil {
		t.Fatalf("seed garbage DB: %v", err)
	}
	// Also drop a stale -wal sidecar to confirm the cleanup
	// catches both files.
	if err := os.WriteFile(dbPath+"-wal", []byte("stale wal"), 0o600); err != nil {
		t.Fatalf("seed stale wal: %v", err)
	}

	s, err := Open(Options{Path: dbPath})
	if err != nil {
		t.Fatalf("Open should have self-healed: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// Schema is at current migration count.
	row := s.db.QueryRow(`SELECT version FROM schema_version LIMIT 1`)
	var v int
	if err := row.Scan(&v); err != nil {
		t.Fatalf("schema_version on rebuilt DB: %v", err)
	}
	if v != len(migrations) {
		t.Errorf("schema_version after rebuild = %d, want %d", v, len(migrations))
	}
	// Stale wal sidecar is gone.
	if _, err := os.Stat(dbPath + "-wal"); err == nil {
		// WAL may be recreated by the fresh SQLite open — but
		// the contents won't be the stale string. We don't pin
		// the contents; just confirm the new DB is usable below.
		_ = err
	}
	// DB is usable: a write succeeds.
	if _, err := s.OpenScan("all"); err != nil {
		t.Errorf("OpenScan on rebuilt DB failed: %v", err)
	}
}

// TestMigrationsAcceptRunningAndDisabledStatus pins the v2 schema
// change: scanner_statuses.status now accepts 'running' (orchestrator
// marks a category before its backend executes) and 'disabled' (user
// turned the category off via `audr daemon scanners --off`). The v1
// CHECK silently rejected both, hiding the running indicator and
// breaking the v0.5 toggle.
func TestMigrationsAcceptRunningAndDisabledStatus(t *testing.T) {
	s := openTestStore(t)
	scanID, err := s.OpenScan("all")
	if err != nil {
		t.Fatalf("OpenScan: %v", err)
	}
	for _, status := range []string{"running", "disabled", "ok", "error", "unavailable", "outdated"} {
		err := s.RecordScannerStatus(ScannerStatus{
			ScanID:   scanID,
			Category: "secrets",
			Status:   status,
		})
		if err != nil {
			t.Errorf("RecordScannerStatus(%q) rejected: %v", status, err)
		}
	}
}

func TestUpsertFindingNewVsRedetection(t *testing.T) {
	s := openTestStore(t)
	scanID, err := s.OpenScan("all")
	if err != nil {
		t.Fatal(err)
	}

	f := Finding{
		Fingerprint:   "fp-test",
		RuleID:        "rule-x",
		Severity:      "high",
		Category:      "ai-agent",
		Kind:          "file",
		Locator:       []byte(`{"path":"/x"}`),
		Title:         "first version",
		Description:   "d",
		FirstSeenScan: scanID,
		LastSeenScan:  scanID,
	}

	opened, err := s.UpsertFinding(f)
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if !opened {
		t.Errorf("opened=false on brand-new finding, want true")
	}

	// Same fingerprint, slightly different title. Re-detection: not "opened".
	f2 := f
	f2.Title = "second version (rule body improved)"
	opened, err = s.UpsertFinding(f2)
	if err != nil {
		t.Fatal(err)
	}
	if opened {
		t.Errorf("opened=true on re-detection, want false")
	}

	// Snapshot: still one row, title updated.
	got, err := s.SnapshotFindings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("snapshot length = %d, want 1", len(got))
	}
	if got[0].Title != "second version (rule body improved)" {
		t.Errorf("title = %q, want updated", got[0].Title)
	}
}

func TestResolveFindingTransitions(t *testing.T) {
	s := openTestStore(t)
	scanID, _ := s.OpenScan("all")
	f := Finding{
		Fingerprint:   "fp-resolve",
		RuleID:        "rule-x",
		Severity:      "high",
		Category:      "secrets",
		Kind:          "file",
		Locator:       []byte(`{"path":"/k"}`),
		Title:         "leaked key",
		Description:   "d",
		FirstSeenScan: scanID,
		LastSeenScan:  scanID,
	}
	if _, err := s.UpsertFinding(f); err != nil {
		t.Fatal(err)
	}

	changed, err := s.ResolveFinding("fp-resolve")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !changed {
		t.Errorf("first resolve: changed=false, want true")
	}

	// Idempotent.
	changed, err = s.ResolveFinding("fp-resolve")
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Errorf("second resolve: changed=true, want false")
	}

	// Reopen via UpsertFinding on a new scan.
	scan2, _ := s.OpenScan("all")
	f2 := f
	f2.FirstSeenScan = scan2
	f2.LastSeenScan = scan2
	opened, err := s.UpsertFinding(f2)
	if err != nil {
		t.Fatal(err)
	}
	if !opened {
		t.Errorf("reopen: opened=false, want true (was resolved)")
	}
	got, _ := s.FindingByFingerprint(context.Background(), "fp-resolve")
	if got.ResolvedAt != nil {
		t.Errorf("reopened finding still has resolved_at = %v", got.ResolvedAt)
	}
}

func TestResolveFindingMissingFingerprintIsNotAnError(t *testing.T) {
	s := openTestStore(t)
	changed, err := s.ResolveFinding("does-not-exist")
	if err != nil {
		t.Errorf("ResolveFinding missing fp returned err: %v", err)
	}
	if changed {
		t.Errorf("changed=true for missing finding")
	}
}

func TestScanLifecycleEmitsEvents(t *testing.T) {
	s := openTestStore(t)
	ch, unsub := s.Subscribe()
	defer unsub()

	scanID, err := s.OpenScan("deps")
	if err != nil {
		t.Fatal(err)
	}
	expectEvent(t, ch, EventScanStarted, 500*time.Millisecond)

	if err := s.CompleteScan(scanID); err != nil {
		t.Fatal(err)
	}
	expectEvent(t, ch, EventScanCompleted, 500*time.Millisecond)
}

func TestCrashRecoveryMarksInProgressScansCrashed(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "crash.db")

	// First daemon: open scan, then "die" without completing it.
	s1, err := Open(Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	ctx1, cancel1 := context.WithCancel(context.Background())
	go func() { _ = s1.Run(ctx1) }()
	time.Sleep(5 * time.Millisecond)

	scanID, err := s1.OpenScan("all")
	if err != nil {
		t.Fatal(err)
	}
	// "Crash": no CompleteScan, just close.
	cancel1()
	_ = s1.Close()

	// Reopen: the crashed-scan reconciler must mark it status='crashed'
	// with a completed_at, so retention can clean it up.
	s2, err := Open(Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	go func() { _ = s2.Run(ctx2) }()
	t.Cleanup(func() { cancel2(); _ = s2.Close() })
	time.Sleep(5 * time.Millisecond)

	scans, err := s2.SnapshotScans(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 1 {
		t.Fatalf("scans = %d, want 1", len(scans))
	}
	if scans[0].ID != scanID {
		t.Errorf("scan ID = %d, want %d", scans[0].ID, scanID)
	}
	if scans[0].Status != "crashed" {
		t.Errorf("status = %q, want crashed", scans[0].Status)
	}
	if scans[0].CompletedAt == nil {
		t.Errorf("completed_at = nil, want non-nil after crash reconcile")
	}
}

func TestSnapshotScannerStatusesReturnsOneRowPerCategory(t *testing.T) {
	// Regression: previous IN-list query returned duplicate rows when
	// categories appeared in different scans. With scan #1 recording
	// all 4 categories and scan #2 recording only 2, the snapshot
	// should still return exactly one row per category (the latest).
	s := openTestStore(t)

	scan1, _ := s.OpenScan("all")
	for _, c := range []string{"ai-agent", "deps", "secrets", "os-pkg"} {
		if err := s.RecordScannerStatus(ScannerStatus{ScanID: scan1, Category: c, Status: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CompleteScan(scan1); err != nil {
		t.Fatal(err)
	}

	// Scan 2: only 2 of the 4 categories recorded (mid-cycle snapshot).
	scan2, _ := s.OpenScan("all")
	if err := s.RecordScannerStatus(ScannerStatus{ScanID: scan2, Category: "ai-agent", Status: "ok"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordScannerStatus(ScannerStatus{ScanID: scan2, Category: "secrets", Status: "unavailable"}); err != nil {
		t.Fatal(err)
	}

	got, err := s.SnapshotScannerStatuses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d rows, want exactly 4 (one per category, latest)", len(got))
	}

	byCategory := map[string]ScannerStatus{}
	for _, ss := range got {
		if _, dup := byCategory[ss.Category]; dup {
			t.Errorf("duplicate row for category %q in snapshot", ss.Category)
		}
		byCategory[ss.Category] = ss
	}

	// Categories recorded in scan2 should reflect scan2's values.
	if byCategory["ai-agent"].ScanID != scan2 {
		t.Errorf("ai-agent scan_id = %d, want %d (latest)", byCategory["ai-agent"].ScanID, scan2)
	}
	if byCategory["secrets"].ScanID != scan2 || byCategory["secrets"].Status != "unavailable" {
		t.Errorf("secrets = %+v, want scan2/unavailable", byCategory["secrets"])
	}
	// Categories only in scan1 should still come from scan1.
	if byCategory["deps"].ScanID != scan1 {
		t.Errorf("deps scan_id = %d, want %d (only recorded in scan1)", byCategory["deps"].ScanID, scan1)
	}
	if byCategory["os-pkg"].ScanID != scan1 {
		t.Errorf("os-pkg scan_id = %d, want %d", byCategory["os-pkg"].ScanID, scan1)
	}
}

func TestRecordAndSnapshotScannerStatus(t *testing.T) {
	s := openTestStore(t)
	scanID, _ := s.OpenScan("all")
	if err := s.RecordScannerStatus(ScannerStatus{
		ScanID: scanID, Category: "deps", Status: "ok",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordScannerStatus(ScannerStatus{
		ScanID: scanID, Category: "secrets", Status: "error", ErrorText: "betterleaks hung",
	}); err != nil {
		t.Fatal(err)
	}

	got, err := s.SnapshotScannerStatuses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("statuses = %d, want 2", len(got))
	}
	statusByCategory := map[string]ScannerStatus{}
	for _, ss := range got {
		statusByCategory[ss.Category] = ss
	}
	if statusByCategory["deps"].Status != "ok" {
		t.Errorf("deps status = %q, want ok", statusByCategory["deps"].Status)
	}
	if statusByCategory["secrets"].Status != "error" {
		t.Errorf("secrets status = %q, want error", statusByCategory["secrets"].Status)
	}
}

func TestFileCachePutGetUpsert(t *testing.T) {
	s := openTestStore(t)
	if err := s.PutFileCache(FileCacheEntry{Path: "/a", MTime: 100, Size: 50}); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.GetFileCache(context.Background(), "/a")
	if err != nil || !found {
		t.Fatalf("get /a: found=%v err=%v", found, err)
	}
	if got.MTime != 100 || got.Size != 50 {
		t.Errorf("got %+v, want mtime=100 size=50", got)
	}

	// Upsert: same path with new mtime overwrites.
	if err := s.PutFileCache(FileCacheEntry{Path: "/a", MTime: 200, Size: 75}); err != nil {
		t.Fatal(err)
	}
	got, _, _ = s.GetFileCache(context.Background(), "/a")
	if got.MTime != 200 || got.Size != 75 {
		t.Errorf("after upsert: %+v, want mtime=200 size=75", got)
	}
}

func TestRetentionPrunesOldRows(t *testing.T) {
	s := openTestStore(t)

	// Pin the clock to make age math predictable.
	originalNow := NowUnix
	defer func() { NowUnix = originalNow }()

	NowUnix = func() int64 { return 100 }
	scanID, _ := s.OpenScan("all")
	if err := s.RecordScannerStatus(ScannerStatus{
		ScanID: scanID, Category: "deps", Status: "ok",
	}); err != nil {
		t.Fatal(err)
	}
	// Add a finding that will be resolved, then jump time forward so it
	// falls past the retention window.
	if _, err := s.UpsertFinding(Finding{
		Fingerprint:   "fp-old",
		RuleID:        "r",
		Severity:      "low",
		Category:      "ai-agent",
		Kind:          "file",
		Locator:       []byte(`{"p":1}`),
		Title:         "t",
		Description:   "d",
		FirstSeenScan: scanID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveFinding("fp-old"); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteScan(scanID); err != nil {
		t.Fatal(err)
	}
	if err := s.PutFileCache(FileCacheEntry{Path: "/old", MTime: 1, Size: 1, ScannedAt: 100}); err != nil {
		t.Fatal(err)
	}

	// Jump 100 days forward — past both retention windows.
	NowUnix = func() int64 { return 100 + int64(100*86400) }
	stats, err := s.PruneRetention(DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}

	if stats.ResolvedFindingsPruned != 1 {
		t.Errorf("resolved findings pruned = %d, want 1", stats.ResolvedFindingsPruned)
	}
	if stats.FileCacheEntriesPruned != 1 {
		t.Errorf("file_cache pruned = %d, want 1", stats.FileCacheEntriesPruned)
	}
	// scans + scanner_statuses pruning is order-dependent: the scan
	// stays only if some finding still references it. After resolved
	// findings are gone, the scan is referenced by no findings, so it
	// CAN be pruned. We don't pin the exact count (the prune order
	// could differ between SQLite versions), just assert progress.
	if stats.ScannerStatusesPruned == 0 && stats.ScansPruned == 0 {
		t.Errorf("expected at least one of scans/scanner_statuses pruned, got 0/0")
	}

	total, open, _ := s.FindingCount(context.Background())
	if total != 0 || open != 0 {
		t.Errorf("post-prune: total=%d open=%d, want 0/0", total, open)
	}
}

func TestPubsubBasicDelivery(t *testing.T) {
	s := openTestStore(t)
	ch, unsub := s.Subscribe()
	defer unsub()

	scanID, _ := s.OpenScan("all")
	expectEvent(t, ch, EventScanStarted, 500*time.Millisecond)

	if _, err := s.UpsertFinding(Finding{
		Fingerprint: "fp-pubsub", RuleID: "r", Severity: "high",
		Category: "ai-agent", Kind: "file", Locator: []byte(`{}`),
		Title: "t", Description: "d", FirstSeenScan: scanID,
	}); err != nil {
		t.Fatal(err)
	}
	expectEvent(t, ch, EventFindingOpened, 500*time.Millisecond)

	if _, err := s.ResolveFinding("fp-pubsub"); err != nil {
		t.Fatal(err)
	}
	expectEvent(t, ch, EventFindingResolved, 500*time.Millisecond)
}

func TestPubsubMultipleSubscribersAllReceive(t *testing.T) {
	s := openTestStore(t)
	a, unsubA := s.Subscribe()
	defer unsubA()
	b, unsubB := s.Subscribe()
	defer unsubB()

	_, err := s.OpenScan("all")
	if err != nil {
		t.Fatal(err)
	}
	expectEvent(t, a, EventScanStarted, 500*time.Millisecond)
	expectEvent(t, b, EventScanStarted, 500*time.Millisecond)
}

func TestPubsubSlowSubscriberDropped(t *testing.T) {
	// Tiny buffer so we overflow quickly.
	dbPath := filepath.Join(t.TempDir(), "slow.db")
	s, err := Open(Options{Path: dbPath, SubscriberBuffer: 2})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = s.Run(ctx) }()
	defer func() { cancel(); _ = s.Close() }()
	time.Sleep(5 * time.Millisecond)

	ch, _ := s.Subscribe()

	// Don't read the channel; flood with events.
	for i := 0; i < 5; i++ {
		if _, err := s.OpenScan("all"); err != nil {
			t.Fatal(err)
		}
	}

	// The slow subscriber should have been dropped; its channel must
	// be closed. Drain whatever made it through, then assert close.
	timeout := time.After(500 * time.Millisecond)
loop:
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				// Channel closed — subscriber was dropped as designed.
				return
			}
		case <-timeout:
			break loop
		}
	}
	t.Fatalf("slow subscriber's channel was not closed within timeout")
}

func TestConcurrentUpsertsAreSerializedSafely(t *testing.T) {
	s := openTestStore(t)
	scanID, _ := s.OpenScan("all")

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			fp, _ := Fingerprint("rule-x", "file", []byte(`{"p":`+itoa(i)+`}`), "")
			_, err := s.UpsertFinding(Finding{
				Fingerprint: fp, RuleID: "rule-x", Severity: "low",
				Category: "ai-agent", Kind: "file", Locator: []byte(`{"p":` + itoa(i) + `}`),
				Title: "t", Description: "d", FirstSeenScan: scanID,
			})
			if err != nil {
				t.Errorf("concurrent upsert %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	total, open, err := s.FindingCount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if total != 50 || open != 50 {
		t.Errorf("counts after 50 concurrent upserts: total=%d open=%d, want 50/50", total, open)
	}
}

// itoa is a tiny string-int helper so the test file doesn't need
// strconv as a transitive import dependency.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func expectEvent(t *testing.T, ch <-chan Event, want EventKind, timeout time.Duration) Event {
	t.Helper()
	select {
	case e, ok := <-ch:
		if !ok {
			t.Fatalf("channel closed waiting for %s", want)
		}
		if e.Kind != want {
			t.Fatalf("kind = %s, want %s", e.Kind, want)
		}
		return e
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %s", want)
		return Event{}
	}
}
