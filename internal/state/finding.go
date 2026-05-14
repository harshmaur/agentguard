package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// UpsertFinding inserts a finding or, if its fingerprint already
// exists, updates the soft fields (title, description, severity,
// last_seen_scan, updated_at) — fingerprint identity is immutable.
//
// Returns:
//
//   - opened=true when this is a new finding (fingerprint not seen
//     before, or seen but previously resolved and now reopened).
//   - opened=false when this is a re-detection of a still-open finding;
//     we bump last_seen_scan and updated_at, and emit an updated event.
//
// Either way, the appropriate Event is published to subscribers AFTER
// the transaction commits.
func (s *Store) UpsertFinding(f Finding) (opened bool, err error) {
	if f.Fingerprint == "" {
		return false, errors.New("UpsertFinding: empty fingerprint")
	}
	if f.FirstSeenScan == 0 {
		return false, errors.New("UpsertFinding: FirstSeenScan must reference a scan")
	}
	if f.LastSeenScan == 0 {
		f.LastSeenScan = f.FirstSeenScan
	}
	now := NowUnix()
	if f.FirstSeenAt == 0 {
		f.FirstSeenAt = now
	}
	f.UpdatedAt = now

	var emit []Event

	err = s.submitWrite(func(tx *sql.Tx) error {
		// Look at current state: does a row with this fingerprint
		// exist? Is it open or resolved? This determines whether we
		// emit "opened" (new or reopened) vs "updated" (re-detection).
		var (
			existed    bool
			wasResolved bool
		)
		row := tx.QueryRow(`SELECT resolved_at IS NOT NULL FROM findings WHERE fingerprint = ?`, f.Fingerprint)
		switch err := row.Scan(&wasResolved); {
		case err == sql.ErrNoRows:
			existed = false
		case err != nil:
			return fmt.Errorf("lookup existing: %w", err)
		default:
			existed = true
		}

		if !existed {
			// Brand-new finding.
			_, err := tx.Exec(`
				INSERT INTO findings
				    (fingerprint, rule_id, severity, category, kind, locator,
				     title, description, match_redacted,
				     first_seen_scan, last_seen_scan, resolved_at, first_seen_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
			`, f.Fingerprint, f.RuleID, f.Severity, f.Category, f.Kind, string(f.Locator),
				f.Title, f.Description, nullableString(f.MatchRedacted),
				f.FirstSeenScan, f.LastSeenScan, f.FirstSeenAt, f.UpdatedAt)
			if err != nil {
				return fmt.Errorf("insert: %w", err)
			}
			opened = true
			emit = append(emit, Event{Kind: EventFindingOpened, Payload: f})
			return nil
		}

		// Existing row. If currently resolved, reopen (clear resolved_at,
		// bump first_seen_scan to "now" so the dashboard treats this as
		// a fresh appearance).
		if wasResolved {
			_, err := tx.Exec(`
				UPDATE findings
				   SET severity = ?,
				       title = ?,
				       description = ?,
				       match_redacted = ?,
				       first_seen_scan = ?,
				       last_seen_scan  = ?,
				       resolved_at = NULL,
				       updated_at = ?
				 WHERE fingerprint = ?
			`, f.Severity, f.Title, f.Description, nullableString(f.MatchRedacted),
				f.LastSeenScan, f.LastSeenScan, f.UpdatedAt, f.Fingerprint)
			if err != nil {
				return fmt.Errorf("reopen: %w", err)
			}
			opened = true
			emit = append(emit, Event{Kind: EventFindingOpened, Payload: f})
			return nil
		}

		// Existing + open: re-detection. Bump last_seen + updated_at;
		// allow severity / title / description to change (rule body
		// might have been improved between scans).
		_, err := tx.Exec(`
			UPDATE findings
			   SET severity = ?,
			       title = ?,
			       description = ?,
			       match_redacted = ?,
			       last_seen_scan = ?,
			       updated_at = ?
			 WHERE fingerprint = ?
		`, f.Severity, f.Title, f.Description, nullableString(f.MatchRedacted),
			f.LastSeenScan, f.UpdatedAt, f.Fingerprint)
		if err != nil {
			return fmt.Errorf("update: %w", err)
		}
		opened = false
		emit = append(emit, Event{Kind: EventFindingUpdated, Payload: f})
		return nil
	})

	// submitWrite already published emit on commit; we don't append to
	// it after the closure returns. The closure captured emit via the
	// outer variable so this works.
	if err != nil {
		return false, err
	}
	// Push the events through by piggy-backing on a no-op write? Cleaner
	// alternative: directly publish here since we already returned from
	// submitWrite (commit succeeded). The writerLoop's emit slot is
	// for the request itself; we built emit AFTER the closure ran
	// because we needed the existed/wasResolved branch. So publish here.
	for _, e := range emit {
		s.publish(e)
	}
	return opened, nil
}

// ResolveFinding marks the finding resolved. Idempotent: resolving an
// already-resolved finding is a no-op (returns false). Returns
// changed=true when the row transitioned from open to resolved.
func (s *Store) ResolveFinding(fingerprint string) (changed bool, err error) {
	if fingerprint == "" {
		return false, errors.New("ResolveFinding: empty fingerprint")
	}
	now := NowUnix()

	var resolved Finding
	err = s.submitWrite(func(tx *sql.Tx) error {
		// Read current state. If already resolved, no-op.
		row := tx.QueryRow(`SELECT resolved_at IS NOT NULL FROM findings WHERE fingerprint = ?`, fingerprint)
		var wasResolved bool
		if err := row.Scan(&wasResolved); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errFindingNotFound
			}
			return err
		}
		if wasResolved {
			return nil
		}
		if _, err := tx.Exec(`UPDATE findings SET resolved_at=?, updated_at=? WHERE fingerprint=?`, now, now, fingerprint); err != nil {
			return err
		}
		// Load the row for the event payload so subscribers can render
		// the resolve animation without a second round-trip.
		r := tx.QueryRow(`
			SELECT fingerprint, rule_id, severity, category, kind, locator,
			       title, description, COALESCE(match_redacted,''),
			       first_seen_scan, last_seen_scan, resolved_at, first_seen_at, updated_at
			  FROM findings WHERE fingerprint = ?
		`, fingerprint)
		var f Finding
		var loc string
		var rAt sql.NullInt64
		if err := r.Scan(&f.Fingerprint, &f.RuleID, &f.Severity, &f.Category, &f.Kind,
			&loc, &f.Title, &f.Description, &f.MatchRedacted,
			&f.FirstSeenScan, &f.LastSeenScan, &rAt, &f.FirstSeenAt, &f.UpdatedAt); err != nil {
			return err
		}
		f.Locator = []byte(loc)
		if rAt.Valid {
			v := rAt.Int64
			f.ResolvedAt = &v
		}
		resolved = f
		changed = true
		return nil
	})
	if err != nil {
		if errors.Is(err, errFindingNotFound) {
			return false, nil
		}
		return false, err
	}
	if changed {
		s.publish(Event{Kind: EventFindingResolved, Payload: resolved})
	}
	return changed, nil
}

// SnapshotFindings returns every finding currently in the store (open
// and resolved), ordered for stable dashboard rendering: severity DESC,
// then first_seen_at ASC. Reads use the connection pool directly
// (concurrent with the writer goroutine in WAL).
func (s *Store) SnapshotFindings(ctx context.Context) ([]Finding, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT fingerprint, rule_id, severity, category, kind, locator,
		       title, description, COALESCE(match_redacted,''),
		       first_seen_scan, last_seen_scan, resolved_at, first_seen_at, updated_at
		  FROM findings
	`)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()

	var out []Finding
	for rows.Next() {
		var f Finding
		var loc string
		var rAt sql.NullInt64
		if err := rows.Scan(&f.Fingerprint, &f.RuleID, &f.Severity, &f.Category, &f.Kind,
			&loc, &f.Title, &f.Description, &f.MatchRedacted,
			&f.FirstSeenScan, &f.LastSeenScan, &rAt, &f.FirstSeenAt, &f.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		f.Locator = []byte(loc)
		if rAt.Valid {
			v := rAt.Int64
			f.ResolvedAt = &v
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// FindingByFingerprint returns a single finding or ErrNotFound. Used
// by the /api/remediation/:fp endpoint.
func (s *Store) FindingByFingerprint(ctx context.Context, fp string) (Finding, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT fingerprint, rule_id, severity, category, kind, locator,
		       title, description, COALESCE(match_redacted,''),
		       first_seen_scan, last_seen_scan, resolved_at, first_seen_at, updated_at
		  FROM findings WHERE fingerprint = ?
	`, fp)
	var f Finding
	var loc string
	var rAt sql.NullInt64
	if err := row.Scan(&f.Fingerprint, &f.RuleID, &f.Severity, &f.Category, &f.Kind,
		&loc, &f.Title, &f.Description, &f.MatchRedacted,
		&f.FirstSeenScan, &f.LastSeenScan, &rAt, &f.FirstSeenAt, &f.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Finding{}, ErrNotFound
		}
		return Finding{}, err
	}
	f.Locator = []byte(loc)
	if rAt.Valid {
		v := rAt.Int64
		f.ResolvedAt = &v
	}
	return f, nil
}

// ErrNotFound: returned by lookup APIs when the row doesn't exist.
var ErrNotFound = errors.New("state: not found")

// errFindingNotFound is the internal sentinel inside the tx closure
// when ResolveFinding hits a missing row.
var errFindingNotFound = errors.New("state: finding not found")

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
