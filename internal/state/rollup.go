package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
)

// ListRolledUp aggregates open findings into vulnerability-level rows
// (one per DedupGroupKey) with fix-authority sub-buckets. This is the
// v1.3 dashboard's primary query — what the user sees by default when
// they open `/`.
//
// Only OPEN findings (resolved_at IS NULL) are returned. Resolved rows
// are not part of the daily-driver picture; /audit retains the flat
// resolved+open view for forensic mode.
//
// PathsPerGroupCap caps the number of paths surfaced per fix-authority
// bucket in the response. Groups with more affected paths still report
// their full PathCount; the dashboard renders the cap with a "show all"
// affordance and the server can re-query with a larger cap by passing 0
// (no cap).
//
// Rows are sorted by:
//
//  1. Severity, worst first (critical → low)
//  2. PathCount desc within the same severity (more-affected first)
//  3. DedupGroupKey ascending for stable output
//
// Two-query strategy: one SELECT pulls every open finding (already
// scoped by the migrating wipe, so post-v3 every row has triage fields
// populated), then we aggregate in Go. SQLite GROUP_CONCAT with the
// path/fingerprint pairs would require a second query anyway to map
// fingerprints back, and the in-Go aggregation reads cleanly and is
// trivially testable. Hot-path traffic is small (audr typically has
// hundreds-to-low-thousands of open findings, not millions).
func (s *Store) ListRolledUp(ctx context.Context, pathsPerGroupCap int) ([]RolledUpRow, error) {
	if pathsPerGroupCap < 0 {
		pathsPerGroupCap = 0
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT fingerprint, rule_id, severity, category, kind, locator,
		       title, description,
		       COALESCE(dedup_group_key, ''),
		       COALESCE(fix_authority, ''),
		       COALESCE(secondary_notify, ''),
		       first_seen_at
		  FROM findings
		 WHERE resolved_at IS NULL
	`)
	if err != nil {
		return nil, fmt.Errorf("query rolled-up findings: %w", err)
	}
	defer rows.Close()

	type member struct {
		fingerprint     string
		path            string
		authority       string
		secondaryNotify string
		severity        string
		firstSeenAt     int64
		ruleID          string
		title           string
		description     string
		category        string
	}
	groups := make(map[string][]member)
	for rows.Next() {
		var (
			fp, ruleID, severity, category, kind        string
			loc, title, description                     string
			dedupKey, fixAuthority, secondaryNotify     string
			firstSeenAt                                 int64
		)
		if err := rows.Scan(&fp, &ruleID, &severity, &category, &kind,
			&loc, &title, &description,
			&dedupKey, &fixAuthority, &secondaryNotify, &firstSeenAt); err != nil {
			return nil, fmt.Errorf("scan rolled-up row: %w", err)
		}
		key := dedupKey
		if key == "" {
			// Defensive: post-v3 every open row has a dedup_group_key.
			// If somehow not, fall back to fingerprint so the row still
			// appears (as its own singleton group) rather than silently
			// disappearing.
			key = "raw:" + fp
		}
		groups[key] = append(groups[key], member{
			fingerprint:     fp,
			path:            extractPathFromLocator([]byte(loc)),
			authority:       fixAuthority,
			secondaryNotify: secondaryNotify,
			severity:        severity,
			firstSeenAt:     firstSeenAt,
			ruleID:          ruleID,
			title:           title,
			description:     description,
			category:        category,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]RolledUpRow, 0, len(groups))
	for key, members := range groups {
		row := RolledUpRow{
			DedupGroupKey:  key,
			RuleID:         members[0].ruleID,
			Title:          members[0].title,
			Description:    members[0].description,
			Category:       members[0].category,
			PathCount:      len(members),
			WorstSeverity:  members[0].severity,
			WorstFirstSeen: members[0].firstSeenAt,
		}
		// Compute worst severity + earliest first-seen across the group.
		for _, m := range members {
			if severityRank(m.severity) < severityRank(row.WorstSeverity) {
				row.WorstSeverity = m.severity
			}
			if m.firstSeenAt < row.WorstFirstSeen {
				row.WorstFirstSeen = m.firstSeenAt
			}
		}
		// Partition by fix authority.
		bucket := map[string][]member{}
		for _, m := range members {
			a := m.authority
			if a == "" {
				a = "you" // safest default — never silently demote
			}
			bucket[a] = append(bucket[a], m)
		}
		// Recompute row.PathCount using UNIQUE paths across all
		// buckets — a package with 4 CVEs at 1 path has 4 findings
		// but should display as "1 path." Per-bucket counts follow
		// the same rule below.
		uniqRowPaths := map[string]struct{}{}
		for _, m := range members {
			uniqRowPaths[m.path] = struct{}{}
		}
		row.PathCount = len(uniqRowPaths)

		for _, authority := range orderedAuthorities() {
			ms, ok := bucket[authority]
			if !ok {
				continue
			}
			// Dedup paths inside this bucket — same package with
			// multiple CVEs at one path yields multiple findings
			// (different fingerprints, same path). The user sees
			// ONE row for the path; keep the first fingerprint so
			// per-path actions (snippet, file-issue) have an
			// addressable target.
			seen := map[string]struct{}{}
			unique := make([]member, 0, len(ms))
			for _, m := range ms {
				if _, dup := seen[m.path]; dup {
					continue
				}
				seen[m.path] = struct{}{}
				unique = append(unique, m)
			}
			grp := RolledUpGroup{
				FixAuthority: authority,
				PathCount:    len(unique),
			}
			// First non-empty secondary-notify wins.
			for _, m := range unique {
				if m.secondaryNotify != "" {
					grp.SecondaryNotify = m.secondaryNotify
					break
				}
			}
			// Stable path order: by path string ascending.
			sort.SliceStable(unique, func(i, j int) bool { return unique[i].path < unique[j].path })
			limit := len(unique)
			if pathsPerGroupCap > 0 && limit > pathsPerGroupCap {
				limit = pathsPerGroupCap
			}
			grp.Paths = make([]RolledUpPath, 0, limit)
			for i := 0; i < limit; i++ {
				grp.Paths = append(grp.Paths, RolledUpPath{
					Fingerprint: unique[i].fingerprint,
					Path:        unique[i].path,
				})
			}
			row.Groups = append(row.Groups, grp)
		}
		out = append(out, row)
	}

	// Order: worst severity first; then most-affected first; then
	// dedup-key alphabetic for determinism.
	sort.SliceStable(out, func(i, j int) bool {
		si := severityRank(out[i].WorstSeverity)
		sj := severityRank(out[j].WorstSeverity)
		if si != sj {
			return si < sj
		}
		if out[i].PathCount != out[j].PathCount {
			return out[i].PathCount > out[j].PathCount
		}
		return out[i].DedupGroupKey < out[j].DedupGroupKey
	})
	return out, nil
}

// orderedAuthorities returns the canonical sort order for sub-groups
// within a RolledUpRow: YOU first (the user's actionable bucket), then
// MAINTAINER (file an issue), then UPSTREAM (track only). Anything
// outside the enum falls to the end.
func orderedAuthorities() []string {
	return []string{"you", "maintainer", "upstream"}
}

// severityRank maps the string severity to a rank where lower = worse.
// Mirrors finding.Severity's iota ordering so SQL string comparisons
// don't have to know about ranks.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 99 // unknown sorts last
}

// extractPathFromLocator pulls a displayable filesystem path out of a
// locator JSON blob (canonicalised at insert time). The locator schema
// varies by kind:
//
//   - file kind:        {"path": "/foo/bar", "line": 5}
//   - dep-package:      {"ecosystem":"npm","name":"...","version":"...","manifest_path":"/path/to/lockfile"}
//   - os-package:       {"manager":"apt","name":"openssl","version":"..."}  (no path field)
//
// Tries "path" first, then "manifest_path" (used by dep findings).
// Returns "" for os-package findings — the dashboard renders the
// system-package locator from the wire-level FindingView fields, not
// from this string. Robust to malformed JSON.
func extractPathFromLocator(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	for _, key := range []string{"path", "manifest_path"} {
		if v, ok := m[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// ensure the standard sql package import isn't pruned in builds that
// don't yet use it directly (Go's compiler complains about unused
// imports — keep this in case future refactors trim the body).
var _ = sql.ErrNoRows
