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
	State      string `json:"state"`        // "RUN" | "SLOW" | "PAUSE" | "OFFLINE"
	StateNote  string `json:"state_note"`   // e.g., "battery", "load 5.2", or ""
	ScanTarget string `json:"scan_target"`  // current file being scanned, or ""
	ScanDone   int    `json:"scan_done"`    // files scanned in current cycle
	ScanTotal  int    `json:"scan_total"`   // approximate total this cycle
	Version    string `json:"version"`
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
