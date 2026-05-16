package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/harshmaur/audr/internal/remediate"
	"github.com/harshmaur/audr/internal/state"
)

// rolledUpPathsCapDefault bounds the response size per fix-authority
// bucket. Picked to keep the largest realistic vulnerability row under
// ~10KB of JSON (50 paths * ~200 bytes path + fingerprint). When a
// bucket has more, the dashboard renders the cap + a "show all"
// affordance and re-queries with cap=0.
const rolledUpPathsCapDefault = 50

// overrideDisclaimer is the F3-mitigation prose the dashboard MUST
// render adjacent to every snippet body. Pinning a transitive dep can
// break the build; saying so out loud is the difference between a tool
// that helps and one that gets blamed.
const overrideDisclaimer = "⚠️ This override pins the transitive dep. Verify your build + tests pass before committing — semver compatibility isn't guaranteed when bypassing a maintainer's resolution."

// handleFindingsRollup serves the v1.3 default dashboard view: one row
// per unique vulnerability with three fix-authority sub-buckets each.
// Wire shape is RolledUpResponse — mirrors handleFindings (the flat
// /audit view) for daemon info + metrics + version so the dashboard
// can render the strip identically across both routes.
func (s *Server) handleFindingsRollup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cap := rolledUpPathsCapDefault
	if v := r.URL.Query().Get("cap"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cap = n
		}
	}

	rolled, err := s.opts.Store.ListRolledUp(ctx, cap)
	if err != nil {
		http.Error(w, "rolled-up findings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Reuse the flat findings query for metrics — the metric strip
	// counts ARE per-path (1 finding = 1 thing the user could resolve),
	// not per-vulnerability. The dashboard surfaces both: the
	// rolled-up row count, plus the underlying open count.
	rows, err := s.opts.Store.SnapshotFindings(ctx)
	if err != nil {
		http.Error(w, "snapshot findings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	views := make([]RolledUpView, 0, len(rolled))
	for _, row := range rolled {
		v := RolledUpView{
			DedupGroupKey: row.DedupGroupKey,
			WorstSeverity: row.WorstSeverity,
			Category:      row.Category,
			RuleID:        row.RuleID,
			Title:         row.Title,
			Description:   row.Description,
			PathCount:     row.PathCount,
			FirstSeen:     time.Unix(row.WorstFirstSeen, 0).UTC().Format(time.RFC3339),
		}
		for _, g := range row.Groups {
			groupView := RolledUpGroupVw{
				FixAuthority:    g.FixAuthority,
				SecondaryNotify: g.SecondaryNotify,
				PathCount:       g.PathCount,
			}
			for _, p := range g.Paths {
				groupView.Paths = append(groupView.Paths, RolledUpPathVw{
					Fingerprint: p.Fingerprint,
					Path:        p.Path,
				})
			}
			v.Groups = append(v.Groups, groupView)
		}
		views = append(views, v)
	}

	resp := RolledUpResponse{
		Rows:    views,
		Metrics: computeMetrics(rows),
		Daemon:  DaemonInfo{State: "RUN", Version: s.opts.Version},
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleRemediateSnippet renders an override-snippet for a single
// dep-package finding. Reads the finding's DedupGroupKey to extract
// the OSV (ecosystem, package, fixed-version, advisory) tuple, looks
// at the path-shaped Locator to detect the lockfile format, and
// emits the format-appropriate snippet plus the F3 disclaimer.
//
// Returns 404 when the fingerprint is unknown. Returns an empty
// snippet (200 with `snippet: ""`) when no upstream fix is available
// or the lockfile format isn't recognised — the dashboard renders
// "Track upstream" in that case.
func (s *Server) handleRemediateSnippet(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fp")
	if fp == "" {
		http.Error(w, "missing fingerprint", http.StatusBadRequest)
		return
	}
	f, err := s.opts.Store.FindingByFingerprint(r.Context(), fp)
	if err != nil {
		if errors.Is(err, state.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no finding for fingerprint " + fp})
			return
		}
		http.Error(w, "lookup finding: "+err.Error(), http.StatusInternalServerError)
		return
	}

	lockfilePath := extractLockfilePathFromLocator(f.Locator)
	snippet := remediate.SnippetForOSVFinding(f.DedupGroupKey, lockfilePath)

	resp := RemediateSnippetResponse{
		Fingerprint:  fp,
		Snippet:      snippet,
		LockfilePath: lockfilePath,
		LockfileFmt:  string(remediate.DetectFormat(lockfilePath)),
	}
	if snippet != "" {
		resp.Disclaimer = overrideDisclaimer
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleRemediateMaintainer renders the maintainer-notify view for a
// finding whose authority is MAINTAINER or whose path lives in a
// vendor dir. The dashboard's "File issue" button calls this, opens
// IssueURL in a new tab when present, and falls back to clipboard-
// copying BodyMarkdown when not.
func (s *Server) handleRemediateMaintainer(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fp")
	if fp == "" {
		http.Error(w, "missing fingerprint", http.StatusBadRequest)
		return
	}
	f, err := s.opts.Store.FindingByFingerprint(r.Context(), fp)
	if err != nil {
		if errors.Is(err, state.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no finding for fingerprint " + fp})
			return
		}
		http.Error(w, "lookup finding: "+err.Error(), http.StatusInternalServerError)
		return
	}

	details := remediate.IssueDetails{
		Maintainer:    f.SecondaryNotify,
		RuleID:        f.RuleID,
		AffectedPaths: []string{extractLockfilePathFromLocator(f.Locator)},
		Severity:      f.Severity,
		Title:         f.Title,
	}
	if key, ok := remediate.ParseOSVDedupKey(f.DedupGroupKey); ok {
		details.AdvisoryID = key.AdvisoryID
		details.Package = key.Package
		details.FixedVersion = key.FixedVersion
	}
	link := remediate.MaintainerLinkFor(details)

	writeJSON(w, http.StatusOK, RemediateMaintainerResponse{
		Fingerprint:  fp,
		IssueURL:     link.IssueURL,
		BodyMarkdown: link.BodyMarkdown,
		LabelHint:    link.LabelHint,
	})
}

// extractLockfilePathFromLocator pulls the manifest_path / path field
// out of a locator JSON blob. The two converter shapes use different
// field names — dep-package locator uses "manifest_path", file locator
// uses "path". Try both.
func extractLockfilePathFromLocator(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	for _, key := range []string{"manifest_path", "path"} {
		if v, ok := m[key]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	return ""
}
