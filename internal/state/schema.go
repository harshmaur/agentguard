package state

import (
	"context"
	"database/sql"
	"fmt"
)

// migrations are applied in order at Open time. New migrations append
// to the slice; existing entries MUST NOT be renumbered or edited
// (existing DBs would refuse to migrate or apply different SQL).
//
// Each migration is a single self-contained set of statements wrapped
// in a single SQL transaction by runMigrations(). Keep them
// idempotent where possible (use IF NOT EXISTS) so re-runs after a
// crash mid-migration recover cleanly.
var migrations = []string{
	// v1: initial schema. Findings use the kind+locator shape from
	// eng-review D17 instead of overfit (path, line).
	`
	CREATE TABLE IF NOT EXISTS scans (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		category     TEXT    NOT NULL,
		started_at   INTEGER NOT NULL,
		completed_at INTEGER,
		status       TEXT    NOT NULL CHECK(status IN ('in_progress','completed','crashed'))
	);
	CREATE INDEX IF NOT EXISTS scans_status ON scans(status);

	CREATE TABLE IF NOT EXISTS findings (
		fingerprint     TEXT    PRIMARY KEY,
		rule_id         TEXT    NOT NULL,
		severity        TEXT    NOT NULL CHECK(severity IN ('critical','high','medium','low')),
		category        TEXT    NOT NULL CHECK(category IN ('ai-agent','deps','secrets','os-pkg')),
		kind            TEXT    NOT NULL CHECK(kind IN ('file','os-package','dep-package')),
		locator         TEXT    NOT NULL,
		title           TEXT    NOT NULL,
		description     TEXT    NOT NULL,
		match_redacted  TEXT,
		first_seen_scan INTEGER NOT NULL REFERENCES scans(id),
		last_seen_scan  INTEGER NOT NULL REFERENCES scans(id),
		resolved_at     INTEGER,
		first_seen_at   INTEGER NOT NULL,
		updated_at      INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS findings_open     ON findings(resolved_at) WHERE resolved_at IS NULL;
	CREATE INDEX IF NOT EXISTS findings_category ON findings(category);
	CREATE INDEX IF NOT EXISTS findings_severity ON findings(severity);
	CREATE INDEX IF NOT EXISTS findings_resolved ON findings(resolved_at) WHERE resolved_at IS NOT NULL;

	CREATE TABLE IF NOT EXISTS scanner_statuses (
		scan_id    INTEGER NOT NULL REFERENCES scans(id),
		category   TEXT    NOT NULL,
		status     TEXT    NOT NULL CHECK(status IN ('ok','error','unavailable','outdated')),
		error_text TEXT,
		scanned_at INTEGER NOT NULL,
		PRIMARY KEY (scan_id, category)
	);

	CREATE TABLE IF NOT EXISTS file_cache (
		path       TEXT    PRIMARY KEY,
		mtime      INTEGER NOT NULL,
		size       INTEGER NOT NULL,
		scanned_at INTEGER NOT NULL
	);
	`,

	// v2 (2026-05-14): widen scanner_statuses.status to include
	// 'running' (the orchestrator marks a category as RUNNING at
	// the start of each backend) and 'disabled' (user-controllable
	// kill switch via `audr daemon scanners --off`).
	//
	// The v1 CHECK silently rejected both values for several
	// releases — orchestrator writes errored, the SSE/dashboard
	// never saw the running/disabled state. SQLite doesn't support
	// dropping a single CHECK; the standard idiom is rename →
	// recreate → copy → drop the old table. Pragma toggles ensure
	// FKs don't trip during the rebuild.
	`
	PRAGMA foreign_keys = OFF;

	CREATE TABLE scanner_statuses_v2 (
		scan_id    INTEGER NOT NULL REFERENCES scans(id),
		category   TEXT    NOT NULL,
		status     TEXT    NOT NULL CHECK(status IN ('ok','error','unavailable','outdated','running','disabled')),
		error_text TEXT,
		scanned_at INTEGER NOT NULL,
		PRIMARY KEY (scan_id, category)
	);

	INSERT INTO scanner_statuses_v2 (scan_id, category, status, error_text, scanned_at)
	SELECT scan_id, category, status, error_text, scanned_at FROM scanner_statuses;

	DROP TABLE scanner_statuses;
	ALTER TABLE scanner_statuses_v2 RENAME TO scanner_statuses;

	PRAGMA foreign_keys = ON;
	`,

	// v3 (2026-05-15): v1.3 "loveable daily driver" dedup engine.
	//
	// Adds three columns to findings — dedup_group_key (groups rows
	// that represent the same vulnerability across paths),
	// fix_authority (who can actually act: "you" | "maintainer" |
	// "upstream"), secondary_notify (maintainer hint when applicable).
	//
	// The migration WIPES all existing finding rows on purpose:
	// pre-v3 rows have no triage metadata, the dedup engine cannot
	// retroactively classify them without re-deriving from rule
	// output, and the daemon's next scan repopulates everything
	// within ~1 cycle (typically 60s). Trading first_seen_at
	// continuity for the simplest correct migration path. See
	// design doc fork 3 + the v3 baseline-reset notice cmd/audr
	// prints on the first post-v3 scan.
	//
	// Two new indexes cover the rolled-up dashboard query
	// (GROUP BY dedup_group_key, fix_authority).
	`
	DELETE FROM findings;

	ALTER TABLE findings ADD COLUMN dedup_group_key TEXT;
	ALTER TABLE findings ADD COLUMN fix_authority TEXT;
	ALTER TABLE findings ADD COLUMN secondary_notify TEXT;

	CREATE INDEX IF NOT EXISTS findings_dedup_group   ON findings(dedup_group_key);
	CREATE INDEX IF NOT EXISTS findings_fix_authority ON findings(fix_authority);
	`,

	// v4 (2026-05-16): scan_cache enables incremental scanning. The
	// orchestrator wraps expensive sidecar invocations (osv-scanner over
	// lockfiles, ospkg enumerator over the package DB) in a fingerprint
	// check — when nothing relevant has changed since the last scan, the
	// prior payload is reused and the sidecar is skipped entirely.
	//
	// scope is the cache key (e.g. "deps:/home/u/projects/foo",
	// "ospkg:dpkg"). fingerprint is opaque to the schema — the producer
	// chooses what inputs to mix in (lockfile mtimes for deps, package-db
	// mtime for ospkg). payload holds the JSON-encoded findings slice the
	// sidecar produced for those inputs.
	`
	CREATE TABLE IF NOT EXISTS scan_cache (
		scope        TEXT    PRIMARY KEY,
		fingerprint  TEXT    NOT NULL,
		payload      BLOB    NOT NULL,
		scanned_at   INTEGER NOT NULL
	);
	`,
}

// runMigrations applies any migrations newer than the current schema
// version. Idempotent: re-running after a clean run is a no-op.
// On a fresh DB the schema_version table itself is created first.
//
// Returns the slice of migration versions that were APPLIED THIS RUN
// (empty when nothing changed). Callers use this to surface one-shot
// post-migration notices — e.g. v3 baseline-reset for the v1.3 dedup
// engine.
func runMigrations(ctx context.Context, db *sql.DB) (appliedThisRun []int, err error) {
	// schema_version is a one-row table — always (version=N).
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return nil, fmt.Errorf("create schema_version: %w", err)
	}

	var current int
	row := db.QueryRowContext(ctx, `SELECT version FROM schema_version LIMIT 1`)
	if err := row.Scan(&current); err != nil {
		// No row yet. Insert version=0 to seed.
		if _, err := db.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (0)`); err != nil {
			return nil, fmt.Errorf("seed schema_version: %w", err)
		}
		current = 0
	}

	for i, sqlText := range migrations {
		v := i + 1
		if v <= current {
			continue
		}
		if err := applyOneMigration(ctx, db, v, sqlText); err != nil {
			return appliedThisRun, fmt.Errorf("apply migration v%d: %w", v, err)
		}
		appliedThisRun = append(appliedThisRun, v)
		current = v
	}
	return appliedThisRun, nil
}

func applyOneMigration(ctx context.Context, db *sql.DB, version int, body string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, body); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE schema_version SET version=?`, version); err != nil {
		return err
	}
	return tx.Commit()
}
