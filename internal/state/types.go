package state

// Finding is the persistence-layer row shape. It mirrors the columns
// on the findings table 1:1. Server.FindingView is a separate wire-
// shape that this maps into; the two intentionally don't share a
// struct because the wire is more constrained (no NULL columns) and
// the storage form keeps room for fields we never expose.
type Finding struct {
	Fingerprint   string
	RuleID        string
	Severity      string // "critical" | "high" | "medium" | "low"
	Category      string // "ai-agent" | "deps" | "secrets" | "os-pkg"
	Kind          string // "file" | "os-package" | "dep-package"
	Locator       []byte // canonicalized JSON
	Title         string
	Description   string
	MatchRedacted string

	// v1.3 triage fields. Populated by internal/triage at scan time —
	// rules MAY emit them directly; the triage pass fills blanks.
	// All three are TEXT NULL in the schema; the Go zero value ("")
	// represents an unset column from a pre-v3 row (those rows are
	// wiped during the v3 migration, so in practice these are always
	// populated post-v3).
	DedupGroupKey   string // groups findings that represent the same vulnerability across paths
	FixAuthority    string // "you" | "maintainer" | "upstream"
	SecondaryNotify string // maintainer hint (e.g. "vercel") when applicable

	FirstSeenScan int64
	LastSeenScan  int64
	ResolvedAt    *int64 // nil = open; non-nil = unix seconds at resolution
	FirstSeenAt   int64
	UpdatedAt     int64
}

// Open reports whether the finding is currently open (unresolved).
func (f Finding) Open() bool { return f.ResolvedAt == nil }

// RolledUpRow is the v1.3 aggregate shape produced by ListRolledUp.
// Each row represents ONE unique vulnerability (one DedupGroupKey)
// partitioned by who can act on it (FixAuthority). The dashboard
// renders one Vuln per CVE/match, with three sub-groups (YOU /
// MAINTAINER / UPSTREAM) inside the expandable row.
//
// Severity is the worst severity across all member findings — a row
// with mixed severities sorts by its worst.
type RolledUpRow struct {
	DedupGroupKey  string
	WorstSeverity  string // "critical" | "high" | "medium" | "low"
	Category       string // copied from any member; same across the group
	RuleID         string // same for every member, by dedup-key construction
	Title          string // taken from the first member (rules emit consistent titles)
	Description    string
	PathCount      int             // total affected paths in the group
	Groups         []RolledUpGroup // one entry per FixAuthority bucket that has ≥1 member
	WorstFirstSeen int64           // first_seen_at across the group, used for "newest first" sort
}

// RolledUpGroup is one fix-authority bucket within a RolledUpRow.
// PathCount is the count of findings in this specific bucket;
// Fingerprints carries the per-finding identifiers so the dashboard
// can drill back to the underlying state.Finding for "View details"
// or per-path snooze.
type RolledUpGroup struct {
	FixAuthority    string
	SecondaryNotify string // populated when ≥1 member carries a maintainer hint; first wins
	PathCount       int
	// Paths is the affected-paths list, truncated server-side at 50
	// for response-size sanity. When PathCount > 50, the dashboard
	// shows "show all" affordance and re-queries with offset.
	Paths []RolledUpPath
}

// RolledUpPath is one row underneath a fix-authority group. Carries
// the minimal data the dashboard needs to render the row + drill back
// to the underlying finding via Fingerprint.
type RolledUpPath struct {
	Fingerprint string
	Path        string
}

// Scan is a single scan-cycle row. Scans aggregate the per-category
// scanner_statuses and bookend a stretch of finding writes.
type Scan struct {
	ID          int64
	Category    string // "all" for full-tree daemon scans; per-category for granular cycles
	StartedAt   int64
	CompletedAt *int64 // nil = in_progress | crashed
	Status      string // "in_progress" | "completed" | "crashed"
}

// ScannerStatus captures the outcome of one scanner backend running
// during one scan cycle. The dashboard renders these per-category.
type ScannerStatus struct {
	ScanID    int64
	Category  string
	Status    string // "ok" | "error" | "unavailable" | "outdated"
	ErrorText string
	ScannedAt int64
}

// EventKind enumerates the events the store publishes on its event
// bus. The HTTP server's /api/events SSE handler subscribes and
// forwards these to browser clients.
type EventKind string

const (
	EventScanStarted     EventKind = "scan-started"
	EventScanCompleted   EventKind = "scan-completed"
	EventFindingOpened   EventKind = "finding-opened"
	EventFindingUpdated  EventKind = "finding-updated" // seen again, last_seen_scan bumped
	EventFindingResolved EventKind = "finding-resolved"
	EventScannerStatus   EventKind = "scanner-status"
	EventPolicyChanged   EventKind = "policy-changed" // fsnotify saw ~/.audr/policy.yaml change on disk
)

// Event is the pub-sub payload Subscribe() returns on. Payload
// concrete type depends on Kind:
//
//   - EventScanStarted, EventScanCompleted: Scan
//   - EventFindingOpened, EventFindingUpdated, EventFindingResolved: Finding
//   - EventScannerStatus: ScannerStatus
//   - EventPolicyChanged: nil (the event itself is the signal — the
//     dashboard re-fetches /api/policy to read the new state)
type Event struct {
	Kind    EventKind
	Payload any
}
