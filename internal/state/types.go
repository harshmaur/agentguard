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

	FirstSeenScan int64
	LastSeenScan  int64
	ResolvedAt    *int64 // nil = open; non-nil = unix seconds at resolution
	FirstSeenAt   int64
	UpdatedAt     int64
}

// Open reports whether the finding is currently open (unresolved).
func (f Finding) Open() bool { return f.ResolvedAt == nil }

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
