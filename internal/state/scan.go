package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// OpenScan records the start of a scan cycle and returns its ID. The
// daemon's scan orchestrator calls this before kicking off scanner
// backends; the resulting scan_id is recorded on every finding written
// during this cycle (first_seen_scan / last_seen_scan).
//
// Category accepts "all" (full-tree daemon cycle) or any of the four
// scan-category names. Caller is responsible for ensuring exactly one
// scan with status='in_progress' exists per category at a time —
// concurrent in-progress scans of the same category are a workflow
// bug, but the schema doesn't enforce uniqueness (an in-progress scan
// can be recorded BEFORE crashed scans get reconciled).
func (s *Store) OpenScan(category string) (int64, error) {
	if category == "" {
		return 0, errors.New("OpenScan: empty category")
	}
	now := NowUnix()
	var id int64

	err := s.submitWrite(func(tx *sql.Tx) error {
		res, err := tx.Exec(`
			INSERT INTO scans (category, started_at, status)
			VALUES (?, ?, 'in_progress')
		`, category, now)
		if err != nil {
			return fmt.Errorf("OpenScan insert: %w", err)
		}
		got, err := res.LastInsertId()
		if err != nil {
			return err
		}
		id = got
		return nil
	})
	if err != nil {
		return 0, err
	}

	// Publish event AFTER the row is committed. Subscribers see the
	// scan only when it's durable.
	s.publish(Event{Kind: EventScanStarted, Payload: Scan{
		ID:        id,
		Category:  category,
		StartedAt: now,
		Status:    "in_progress",
	}})
	return id, nil
}

// CompleteScan marks a scan finished. Idempotent: completing an
// already-completed scan is a no-op. Returns ErrNotFound if the scan
// row doesn't exist.
func (s *Store) CompleteScan(scanID int64) error {
	if scanID == 0 {
		return errors.New("CompleteScan: scanID is zero")
	}
	now := NowUnix()
	var (
		category string
		startedAt int64
	)
	err := s.submitWrite(func(tx *sql.Tx) error {
		row := tx.QueryRow(`SELECT category, started_at, status FROM scans WHERE id = ?`, scanID)
		var status string
		if err := row.Scan(&category, &startedAt, &status); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errScanNotFound
			}
			return err
		}
		if status == "completed" {
			return nil // idempotent
		}
		_, err := tx.Exec(`
			UPDATE scans SET status='completed', completed_at=?
			WHERE id = ? AND status='in_progress'
		`, now, scanID)
		return err
	})
	if err != nil {
		if errors.Is(err, errScanNotFound) {
			return ErrNotFound
		}
		return err
	}
	s.publish(Event{Kind: EventScanCompleted, Payload: Scan{
		ID:          scanID,
		Category:    category,
		StartedAt:   startedAt,
		CompletedAt: &now,
		Status:      "completed",
	}})
	return nil
}

// SnapshotScans returns the most recent N scans (excluding crashed
// ones older than the retention window). Currently unused by the
// server; exposed for diagnostic CLI commands like `audr daemon status`.
func (s *Store) SnapshotScans(ctx context.Context, limit int) ([]Scan, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, category, started_at, completed_at, status
		  FROM scans
		 ORDER BY started_at DESC
		 LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Scan
	for rows.Next() {
		var sc Scan
		var completedAt sql.NullInt64
		if err := rows.Scan(&sc.ID, &sc.Category, &sc.StartedAt, &completedAt, &sc.Status); err != nil {
			return nil, err
		}
		if completedAt.Valid {
			v := completedAt.Int64
			sc.CompletedAt = &v
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// RecordScannerStatus writes the per-(scan, category) outcome of a
// scanner backend. This is what the dashboard's per-category banners
// read to distinguish "ok with 0 findings" (clean) from "scanner
// errored" (unknown — must not show as clean).
func (s *Store) RecordScannerStatus(ss ScannerStatus) error {
	if ss.ScanID == 0 || ss.Category == "" || ss.Status == "" {
		return errors.New("RecordScannerStatus: missing required field")
	}
	if ss.ScannedAt == 0 {
		ss.ScannedAt = NowUnix()
	}
	err := s.submitWrite(func(tx *sql.Tx) error {
		_, err := tx.Exec(`
			INSERT INTO scanner_statuses (scan_id, category, status, error_text, scanned_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(scan_id, category) DO UPDATE SET
				status = excluded.status,
				error_text = excluded.error_text,
				scanned_at = excluded.scanned_at
		`, ss.ScanID, ss.Category, ss.Status, nullableString(ss.ErrorText), ss.ScannedAt)
		return err
	})
	if err != nil {
		return err
	}
	s.publish(Event{Kind: EventScannerStatus, Payload: ss})
	return nil
}

// SnapshotScannerStatuses returns the most recent scanner status per
// category. Used by the server to populate the dashboard's per-
// category indicators in the initial /api/findings snapshot.
//
// Implementation note: the previous version used WHERE scan_id IN
// (SELECT MAX(scan_id) ... GROUP BY category) which produced
// duplicate rows when categories appeared in different scans (the
// outer query couldn't tie a scan_id back to the specific category
// it was the max FOR — it just had a set of max-scan-ids and let
// every category's row through if its scan_id was in the set). The
// JOIN form below correctly returns exactly one row per category.
func (s *Store) SnapshotScannerStatuses(ctx context.Context) ([]ScannerStatus, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.scan_id, s.category, s.status, COALESCE(s.error_text,''), s.scanned_at
		  FROM scanner_statuses s
		  INNER JOIN (
			SELECT category, MAX(scan_id) AS max_id
			  FROM scanner_statuses
			 GROUP BY category
		  ) latest ON s.category = latest.category AND s.scan_id = latest.max_id
		 ORDER BY s.category
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScannerStatus
	for rows.Next() {
		var ss ScannerStatus
		if err := rows.Scan(&ss.ScanID, &ss.Category, &ss.Status, &ss.ErrorText, &ss.ScannedAt); err != nil {
			return nil, err
		}
		out = append(out, ss)
	}
	return out, rows.Err()
}

// errScanNotFound is the internal sentinel for CompleteScan's tx
// closure when the scanID isn't in the table.
var errScanNotFound = errors.New("state: scan not found")
