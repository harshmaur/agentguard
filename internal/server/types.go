package server

// FindingView is the dashboard's API shape for a single finding. It is
// intentionally separate from internal/finding.Finding — the wire
// contract evolves on its own cadence (we add kind + locator per the
// eng review D17, which the internal Finding doesn't have yet), and
// the dashboard JS depends on the stability of this shape, not the
// internal model.
//
// Fingerprint is the stable identity. The dashboard JS keys all DOM
// elements on it (so SSE updates can re-find the same row), passes it
// back on /api/remediation/:fp lookups, and uses it for the
// "resolved" animation.
type FindingView struct {
	Fingerprint   string         `json:"fingerprint"`
	RuleID        string         `json:"rule_id"`
	Severity      string         `json:"severity"` // "critical" | "high" | "medium" | "low"
	Category      string         `json:"category"` // "ai-agent" | "deps" | "secrets" | "os-pkg"
	Kind          string         `json:"kind"`     // "file" | "os-package" | "dep-package"
	Locator       map[string]any `json:"locator"`
	Title         string         `json:"title"`
	Description   string         `json:"description"`
	MatchRedacted string         `json:"match_redacted,omitempty"`
	FirstSeen     string         `json:"first_seen"` // RFC3339
}

// SnapshotResponse is the body of GET /api/findings: the dashboard's
// initial state.
type SnapshotResponse struct {
	Findings []FindingView   `json:"findings"`
	Metrics  SnapshotMetrics `json:"metrics"`
	Daemon   DaemonInfo      `json:"daemon"`
	Scanners []ScannerInfo   `json:"scanners"`
}

// SnapshotMetrics is the metric strip data: totals shown across the top
// of the dashboard.
type SnapshotMetrics struct {
	OpenTotal       int `json:"open_total"`
	OpenCritical    int `json:"open_critical"`
	OpenHigh        int `json:"open_high"`
	OpenMedium      int `json:"open_medium"`
	OpenLow         int `json:"open_low"`
	ResolvedToday   int `json:"resolved_today"`
}

// DaemonInfo describes the daemon's runtime state. Phase 2 visual slice
// returns a fixed value; the adaptive backoff state machine in Phase 3
// will start emitting transitions.
type DaemonInfo struct {
	State           string           `json:"state"`        // "RUN" | "SLOW" | "PAUSE" | "OFFLINE"
	StateNote       string           `json:"state_note"`   // e.g., "battery", "load 5.2", or ""
	ScanTarget      string           `json:"scan_target"`  // current file being scanned, or ""
	ScanDone        int              `json:"scan_done"`    // files scanned in current cycle
	ScanTotal       int              `json:"scan_total"`   // approximate total this cycle
	Version         string           `json:"version"`
	UpdateAvailable *UpdateAvailable `json:"update_available,omitempty"`

	// ScanInProgress is true when the snapshot is being served while
	// a scan cycle is mid-flight. Lets the dashboard set scanActive
	// on initial load so it doesn't misleadingly show "INITIALIZING"
	// for the full duration of an already-running scan it didn't
	// catch the scan-started SSE event for.
	ScanInProgress bool `json:"scan_in_progress,omitempty"`

	// LastScanCompleted is the unix seconds of the most recent
	// completed scan, or 0 when no scan has ever completed. Lets
	// the dashboard's WATCHING state display a "last scan X min ago"
	// relative-time clause on initial load instead of waiting for
	// the next scan-completed SSE event.
	LastScanCompleted int64 `json:"last_scan_completed,omitempty"`

	// PendingNotifications counts the entries in
	// ${state_dir}/pending-notify.json — toasts that were dropped by
	// the OS (permission denied / missing notify-send / Focus mode).
	// Non-zero triggers a dashboard banner pointing the user at
	// `audr daemon notify --status` and macOS notification settings.
	PendingNotifications int `json:"pending_notifications,omitempty"`

	// ScannerEnabled mirrors the on-disk scanner.config.json so the
	// dashboard knows which categories are user-disabled vs
	// unavailable. Keys are the canonical category identifiers
	// (ai-agent, deps, secrets, os-pkg) and values are the enabled
	// flag.
	ScannerEnabled map[string]bool `json:"scanner_enabled,omitempty"`

	// InotifyLow signals that the watcher ran into the kernel's
	// fs.inotify.max_user_watches budget and demoted some scope to
	// poll-only. Linux-only; always false elsewhere. Dashboard
	// renders a banner with the sysctl fix command when true.
	InotifyLow bool `json:"inotify_low,omitempty"`

	// RemoteFsSkipped counts scope roots that resolved to a remote
	// filesystem (NFS / SMB / 9P / FUSE / WSL host mount) and were
	// excluded from tight-watch. Dashboard renders an info banner
	// when > 0 acknowledging the intentional skip.
	RemoteFsSkipped int `json:"remote_fs_skipped,omitempty"`
}

// UpdateAvailable is surfaced by the dashboard banner stack when the
// background updater finds a newer release. Always nil when the
// daemon is running the latest version (or the check hasn't run
// yet). Mirrors updater.Available — separate type to keep the wire
// contract independent of the internal package layout.
type UpdateAvailable struct {
	Version     string `json:"version"`      // e.g., "v0.3.0"
	URL         string `json:"url"`          // GitHub release page
	PublishedAt string `json:"published_at"` // RFC3339
}

// ScannerInfo mirrors daemon.SidecarStatus on the wire. The dashboard
// renders an amber dot in the metric strip + a footnote per scanner
// when state != "ok".
type ScannerInfo struct {
	Name         string `json:"name"`
	State        string `json:"state"`         // "ok" | "outdated" | "missing" | "error"
	FoundVersion string `json:"found_version,omitempty"`
	MinVersion   string `json:"min_version,omitempty"`
	ErrorText    string `json:"error_text,omitempty"`
}

// RemediationResponse is the body of GET /api/remediation/:fingerprint.
// Two fixes per the design-review D17: the manual steps a human walks
// through, and the paste-ready AI prompt the user drops into Claude
// Code / Codex.
type RemediationResponse struct {
	Fingerprint string `json:"fingerprint"`
	HumanSteps  string `json:"human_steps"`
	AIPrompt    string `json:"ai_prompt"`
}
