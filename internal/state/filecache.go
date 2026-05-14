package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// FileCacheEntry is the on-disk row for the file_cache table. The
// watch+poll engine (Phase 3) writes one row per scanned file with the
// mtime + size at scan time; the next poll cycle compares against this
// to find changed files cheaply without a full content read.
type FileCacheEntry struct {
	Path      string
	MTime     int64
	Size      int64
	ScannedAt int64
}

// GetFileCache returns the cached entry for path or (zero, false, nil)
// when not present. Reads are concurrent-safe under WAL.
func (s *Store) GetFileCache(ctx context.Context, path string) (FileCacheEntry, bool, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT path, mtime, size, scanned_at
		  FROM file_cache WHERE path = ?
	`, path)
	var e FileCacheEntry
	switch err := row.Scan(&e.Path, &e.MTime, &e.Size, &e.ScannedAt); {
	case errors.Is(err, sql.ErrNoRows):
		return FileCacheEntry{}, false, nil
	case err != nil:
		return FileCacheEntry{}, false, fmt.Errorf("file_cache scan: %w", err)
	default:
		return e, true, nil
	}
}

// PutFileCache upserts an entry. Called by the watch+poll engine after
// every successful per-file scan so the next cycle's mtime delta
// detects "no change."
func (s *Store) PutFileCache(entry FileCacheEntry) error {
	if entry.Path == "" {
		return errors.New("PutFileCache: empty path")
	}
	if entry.ScannedAt == 0 {
		entry.ScannedAt = NowUnix()
	}
	return s.submitWrite(func(tx *sql.Tx) error {
		_, err := tx.Exec(`
			INSERT INTO file_cache (path, mtime, size, scanned_at)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(path) DO UPDATE SET
				mtime = excluded.mtime,
				size = excluded.size,
				scanned_at = excluded.scanned_at
		`, entry.Path, entry.MTime, entry.Size, entry.ScannedAt)
		return err
	})
}

// PutFileCacheBatch upserts many entries in a single transaction.
// Significant speedup for first-run sweeps (10k+ files); not needed
// for incremental scans.
func (s *Store) PutFileCacheBatch(entries []FileCacheEntry) error {
	if len(entries) == 0 {
		return nil
	}
	now := NowUnix()
	return s.submitWrite(func(tx *sql.Tx) error {
		stmt, err := tx.Prepare(`
			INSERT INTO file_cache (path, mtime, size, scanned_at)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(path) DO UPDATE SET
				mtime = excluded.mtime,
				size = excluded.size,
				scanned_at = excluded.scanned_at
		`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, e := range entries {
			scanned := e.ScannedAt
			if scanned == 0 {
				scanned = now
			}
			if _, err := stmt.Exec(e.Path, e.MTime, e.Size, scanned); err != nil {
				return fmt.Errorf("file_cache batch insert %s: %w", e.Path, err)
			}
		}
		return nil
	})
}
