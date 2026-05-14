package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// RetentionPolicy controls how aggressively the store prunes old rows.
// Defaults match the design doc's Lifecycle Concerns section.
type RetentionPolicy struct {
	// ScanRetention is how long completed/crashed scans stay around.
	// Default: 90 days.
	ScanRetentionSeconds int64

	// ResolvedFindingRetention is how long resolved findings stay
	// before they're GC'd. Default: 30 days post-resolution.
	ResolvedFindingRetentionSeconds int64

	// FileCacheStaleSeconds is how long a file_cache row may go
	// without a scan before it's pruned (the file likely got
	// deleted). Default: 30 days.
	FileCacheStaleSeconds int64
}

// DefaultRetention returns the production policy.
func DefaultRetention() RetentionPolicy {
	const day = int64(86400)
	return RetentionPolicy{
		ScanRetentionSeconds:            90 * day,
		ResolvedFindingRetentionSeconds: 30 * day,
		FileCacheStaleSeconds:           30 * day,
	}
}

// RetentionStats is what PruneRetention returns so callers can log
// "we pruned N rows" without re-querying.
type RetentionStats struct {
	ScansPruned             int
	ResolvedFindingsPruned  int
	ScannerStatusesPruned   int
	FileCacheEntriesPruned  int
}

// PruneRetention deletes rows older than the policy boundaries.
// Safe to call from a periodic ticker (the daemon's retention sweeper).
// Holds a single write transaction so the four delete passes are
// atomic — a reader never sees half a prune.
func (s *Store) PruneRetention(policy RetentionPolicy) (RetentionStats, error) {
	if policy.ScanRetentionSeconds <= 0 {
		policy = DefaultRetention()
	}
	now := NowUnix()
	var stats RetentionStats

	err := s.submitWrite(func(tx *sql.Tx) error {
		// 1. Prune resolved findings older than ResolvedFindingRetention.
		res, err := tx.Exec(`
			DELETE FROM findings
			 WHERE resolved_at IS NOT NULL
			   AND resolved_at < ?
		`, now-policy.ResolvedFindingRetentionSeconds)
		if err != nil {
			return fmt.Errorf("prune findings: %w", err)
		}
		if n, e := res.RowsAffected(); e == nil {
			stats.ResolvedFindingsPruned = int(n)
		}

		// 2. Prune scanner statuses whose scan is about to be pruned.
		// We do this before scans because scanner_statuses has an FK
		// referencing scans(id); foreign_keys=ON would block scans
		// pruning if statuses still pointed at them.
		res, err = tx.Exec(`
			DELETE FROM scanner_statuses
			 WHERE scan_id IN (
				SELECT id FROM scans
				 WHERE status IN ('completed','crashed')
				   AND COALESCE(completed_at, started_at) < ?
			 )
		`, now-policy.ScanRetentionSeconds)
		if err != nil {
			return fmt.Errorf("prune scanner_statuses: %w", err)
		}
		if n, e := res.RowsAffected(); e == nil {
			stats.ScannerStatusesPruned = int(n)
		}

		// 3. Prune scans themselves. We can't drop a scan that any
		// current finding's first_seen_scan/last_seen_scan still
		// references — that would orphan the FK. So we limit pruning
		// to scans NOT referenced by any open finding. (Findings'
		// resolved+retention pass above will eventually let stale
		// scans become unreferenced.)
		res, err = tx.Exec(`
			DELETE FROM scans
			 WHERE id NOT IN (SELECT first_seen_scan FROM findings)
			   AND id NOT IN (SELECT last_seen_scan FROM findings)
			   AND status IN ('completed','crashed')
			   AND COALESCE(completed_at, started_at) < ?
		`, now-policy.ScanRetentionSeconds)
		if err != nil {
			return fmt.Errorf("prune scans: %w", err)
		}
		if n, e := res.RowsAffected(); e == nil {
			stats.ScansPruned = int(n)
		}

		// 4. Prune file_cache rows we haven't re-scanned in a long time.
		res, err = tx.Exec(`
			DELETE FROM file_cache WHERE scanned_at < ?
		`, now-policy.FileCacheStaleSeconds)
		if err != nil {
			return fmt.Errorf("prune file_cache: %w", err)
		}
		if n, e := res.RowsAffected(); e == nil {
			stats.FileCacheEntriesPruned = int(n)
		}
		return nil
	})
	return stats, err
}

// FindingCount is exposed for tests; returns the total + open counts.
// Reads concurrent-safe under WAL.
func (s *Store) FindingCount(ctx context.Context) (total, open int, err error) {
	row := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE resolved_at IS NULL) FROM findings`)
	if err := row.Scan(&total, &open); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	return total, open, nil
}
