package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ScanCacheEntry is one row of the scan_cache table. The orchestrator
// uses it to skip expensive sidecar invocations (osv-scanner,
// ospkg.EnumerateAndScan) when their inputs haven't changed since the
// last cycle.
//
// Scope is the cache key — producers namespace it (e.g. "deps:<root>",
// "ospkg:<manager>") so multiple subsystems can share the table.
// Fingerprint is opaque to the store: the producer mixes in whatever
// inputs invalidate the cached result (lockfile mtimes for deps,
// package-db mtime for ospkg). Payload is the producer's serialized
// output for those inputs — typically a JSON-encoded findings slice.
type ScanCacheEntry struct {
	Scope       string
	Fingerprint string
	Payload     []byte
	ScannedAt   int64
}

// GetScanCache returns the cached entry for scope, or (zero, false, nil)
// if not present.
func (s *Store) GetScanCache(ctx context.Context, scope string) (ScanCacheEntry, bool, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT scope, fingerprint, payload, scanned_at
		  FROM scan_cache WHERE scope = ?
	`, scope)
	var e ScanCacheEntry
	switch err := row.Scan(&e.Scope, &e.Fingerprint, &e.Payload, &e.ScannedAt); {
	case errors.Is(err, sql.ErrNoRows):
		return ScanCacheEntry{}, false, nil
	case err != nil:
		return ScanCacheEntry{}, false, fmt.Errorf("scan_cache scan: %w", err)
	default:
		return e, true, nil
	}
}

// PutScanCache upserts an entry. ScannedAt defaults to NowUnix() when zero.
func (s *Store) PutScanCache(entry ScanCacheEntry) error {
	if entry.Scope == "" {
		return errors.New("PutScanCache: empty scope")
	}
	if entry.Fingerprint == "" {
		return errors.New("PutScanCache: empty fingerprint")
	}
	if entry.ScannedAt == 0 {
		entry.ScannedAt = NowUnix()
	}
	return s.submitWrite(func(tx *sql.Tx) error {
		_, err := tx.Exec(`
			INSERT INTO scan_cache (scope, fingerprint, payload, scanned_at)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(scope) DO UPDATE SET
				fingerprint = excluded.fingerprint,
				payload     = excluded.payload,
				scanned_at  = excluded.scanned_at
		`, entry.Scope, entry.Fingerprint, entry.Payload, entry.ScannedAt)
		return err
	})
}

// DeleteScanCache removes entries whose scope has the given prefix.
// Used by callers that want to invalidate a producer's whole namespace
// (e.g. "deps:" sweeps every deps cache row). Returns the count deleted.
func (s *Store) DeleteScanCache(scopePrefix string) (int64, error) {
	if scopePrefix == "" {
		return 0, errors.New("DeleteScanCache: empty prefix")
	}
	var deleted int64
	err := s.submitWrite(func(tx *sql.Tx) error {
		res, err := tx.Exec(`DELETE FROM scan_cache WHERE scope LIKE ? || '%'`, scopePrefix)
		if err != nil {
			return err
		}
		deleted, _ = res.RowsAffected()
		return nil
	})
	return deleted, err
}
