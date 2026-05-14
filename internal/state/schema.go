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
}

// runMigrations applies any migrations newer than the current schema
// version. Idempotent: re-running after a clean run is a no-op.
// On a fresh DB the schema_version table itself is created first.
func runMigrations(ctx context.Context, db *sql.DB) error {
	// schema_version is a one-row table — always (version=N).
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("create schema_version: %w", err)
	}

	var current int
	row := db.QueryRowContext(ctx, `SELECT version FROM schema_version LIMIT 1`)
	if err := row.Scan(&current); err != nil {
		// No row yet. Insert version=0 to seed.
		if _, err := db.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (0)`); err != nil {
			return fmt.Errorf("seed schema_version: %w", err)
		}
		current = 0
	}

	for i, sqlText := range migrations {
		v := i + 1
		if v <= current {
			continue
		}
		if err := applyOneMigration(ctx, db, v, sqlText); err != nil {
			return fmt.Errorf("apply migration v%d: %w", v, err)
		}
		current = v
	}
	return nil
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
