package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harshmaur/audr/internal/finding"
)

// fakeCache is an in-memory FileCache for unit testing. Tracks hit /
// miss counts so the test can assert "second scan saw zero parses."
type fakeCache struct {
	mu   sync.Mutex
	rows map[string]FileCacheEntry

	hits   atomic.Int64
	misses atomic.Int64
	puts   atomic.Int64
}

func newFakeCache() *fakeCache {
	return &fakeCache{rows: map[string]FileCacheEntry{}}
}

func (c *fakeCache) Get(_ context.Context, path string) (FileCacheEntry, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.rows[path]
	if ok {
		c.hits.Add(1)
	} else {
		c.misses.Add(1)
	}
	return e, ok, nil
}

func (c *fakeCache) Put(e FileCacheEntry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rows[e.Path] = e
	c.puts.Add(1)
	return nil
}

func TestScanCache_SecondRunReplaysFromCache(t *testing.T) {
	// Use AGENTS.md (FormatAgentDoc) — recognized by parse.DetectFormat
	// (so the walker enqueues it) but NOT in correlateRelevantFormats
	// (so the cache logic engages). Correlate-relevant files always
	// parse fresh regardless of cache state.
	root := t.TempDir()
	doc := filepath.Join(root, "AGENTS.md")
	if err := os.WriteFile(doc, []byte("# audr\n\nProject docs.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cache := newFakeCache()
	opts := Options{
		Roots:       []string{root},
		Workers:     1,
		Cache:       cache,
		AudrVersion: "test-1.0",
	}

	// First scan: every file is a cache miss. Cache should fill up
	// with rows for the non-correlate-relevant files.
	res1, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if res1.FilesParsed == 0 {
		t.Fatalf("first scan parsed 0 files; nothing to cache")
	}
	puts1 := cache.puts.Load()
	if puts1 == 0 {
		t.Fatalf("first scan put 0 cache rows despite parsing %d files", res1.FilesParsed)
	}

	// Second scan with no edits: every put-cached file should be a
	// cache hit. The cache layer's `parsed` accounting still
	// increments on hit (it's the post-cache equivalent of parse), so
	// FilesParsed matches the first run.
	cache.hits.Store(0)
	cache.puts.Store(0)
	res2, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if cache.hits.Load() == 0 {
		t.Fatalf("second scan had zero cache hits — cache logic isn't engaging")
	}
	if cache.puts.Load() != 0 {
		// Correlate-relevant files always parse fresh and DON'T
		// write cache rows; non-correlate files were cache hits and
		// shouldn't write either. Net: zero new puts on a second
		// identical scan.
		t.Fatalf("second scan wrote %d cache rows; expected 0 because nothing changed", cache.puts.Load())
	}
	_ = res2
}

func TestScanCache_VersionMismatchInvalidates(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "AGENTS.md")
	if err := os.WriteFile(path, []byte("# docs\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cache := newFakeCache()
	// Seed the cache with a row tagged with an OLD version. Same
	// (mtime, size) as the live file, but the version tag won't match
	// the running scan's AudrVersion — entry must be treated as stale.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	cache.rows[path] = FileCacheEntry{
		Path:        path,
		MTime:       info.ModTime().UnixNano(),
		Size:        info.Size(),
		Findings:    mustJSON(t, []finding.Finding{{RuleID: "stale-cached-finding"}}),
		AudrVersion: "old-version",
	}

	opts := Options{
		Roots:       []string{root},
		Workers:     1,
		Cache:       cache,
		AudrVersion: "new-version",
	}
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range res.Findings {
		if f.RuleID == "stale-cached-finding" {
			t.Fatalf("stale-version cache row was used despite version mismatch")
		}
	}
	// And the new version should have re-written the row.
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if got := cache.rows[path].AudrVersion; got != "new-version" {
		t.Fatalf("cache row not refreshed to new version: %q", got)
	}
}

func TestScanCache_MtimeChangeInvalidates(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "AGENTS.md")
	if err := os.WriteFile(path, []byte("# docs\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cache := newFakeCache()
	opts := Options{
		Roots:       []string{root},
		Workers:     1,
		Cache:       cache,
		AudrVersion: "v1",
	}
	if _, err := Run(context.Background(), opts); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	cache.hits.Store(0)
	cache.puts.Store(0)

	// Touch the file with new content so size and mtime both move.
	// Wait past 1s for second-granularity filesystems to advance.
	time.Sleep(1100 * time.Millisecond)
	if err := os.WriteFile(path, []byte("# docs\n\nmore content here\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Run(context.Background(), opts); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if cache.puts.Load() == 0 {
		t.Fatalf("after edit, scan should have re-cached the file with new mtime/size; got 0 puts")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}
