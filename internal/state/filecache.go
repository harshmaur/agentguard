package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// FileCacheEntry is the on-disk row for the file_cache table. The
// native scan walker writes one row per scanned file: (mtime, size)
// captures whether the file changed, findings caches the rules' verdict
// for unchanged files, and audr_version is the kill switch when rules
// or the engine itself change (binary upgrade invalidates every entry).
//
// Findings + AudrVersion are nullable on disk so older rows written by
// the watch+poll engine prior to v5 (which only persisted the stat
// tuple for change-detection) keep working — they just register as a
// cache miss until the next successful scan rewrites them.
type FileCacheEntry struct {
	Path        string
	MTime       int64
	Size        int64
	ScannedAt   int64
	Findings    []byte // JSON-encoded []finding.Finding; may be nil
	AudrVersion string // empty for pre-v5 rows
}

// GetFileCache returns the cached entry for path or (zero, false, nil)
// when not present. Reads are concurrent-safe under WAL.
func (s *Store) GetFileCache(ctx context.Context, path string) (FileCacheEntry, bool, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT path, mtime, size, scanned_at, findings, audr_version
		  FROM file_cache WHERE path = ?
	`, path)
	var e FileCacheEntry
	var findings sql.NullString
	var version sql.NullString
	switch err := row.Scan(&e.Path, &e.MTime, &e.Size, &e.ScannedAt, &findings, &version); {
	case errors.Is(err, sql.ErrNoRows):
		return FileCacheEntry{}, false, nil
	case err != nil:
		return FileCacheEntry{}, false, fmt.Errorf("file_cache scan: %w", err)
	default:
		if findings.Valid {
			e.Findings = []byte(findings.String)
		}
		if version.Valid {
			e.AudrVersion = version.String
		}
		return e, true, nil
	}
}

// PutFileCache upserts an entry. Called by the scan worker after every
// successful per-file scan so the next cycle's mtime delta detects "no
// change" AND the rules' verdict can be replayed without re-parsing.
func (s *Store) PutFileCache(entry FileCacheEntry) error {
	if entry.Path == "" {
		return errors.New("PutFileCache: empty path")
	}
	if entry.ScannedAt == 0 {
		entry.ScannedAt = NowUnix()
	}
	return s.submitWrite(func(tx *sql.Tx) error {
		_, err := tx.Exec(`
			INSERT INTO file_cache (path, mtime, size, scanned_at, findings, audr_version)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(path) DO UPDATE SET
				mtime        = excluded.mtime,
				size         = excluded.size,
				scanned_at   = excluded.scanned_at,
				findings     = excluded.findings,
				audr_version = excluded.audr_version
		`, entry.Path, entry.MTime, entry.Size, entry.ScannedAt, entry.Findings, entry.AudrVersion)
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
			INSERT INTO file_cache (path, mtime, size, scanned_at, findings, audr_version)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(path) DO UPDATE SET
				mtime        = excluded.mtime,
				size         = excluded.size,
				scanned_at   = excluded.scanned_at,
				findings     = excluded.findings,
				audr_version = excluded.audr_version
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
			if _, err := stmt.Exec(e.Path, e.MTime, e.Size, scanned, e.Findings, e.AudrVersion); err != nil {
				return fmt.Errorf("file_cache batch insert %s: %w", e.Path, err)
			}
		}
		return nil
	})
}
