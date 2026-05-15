package server

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/policy"
	"github.com/harshmaur/audr/internal/rules"
)

// handlePolicyPage serves the policy editor HTML (policy.html).
// Static asset — the JS inside does the API calls. The token query
// param survives the navigation just like / does.
func (s *Server) handlePolicyPage(w http.ResponseWriter, r *http.Request) {
	s.serveEmbedded(w, r, "policy.html", "text/html; charset=utf-8")
}

// policyAPIResponse is the JSON the editor renders from. Includes:
//
//   - The current policy file (so the editor can pre-populate).
//   - The complete rule catalog (rule-id, title, default severity,
//     formats) so the form view can show every rule, not just the
//     ones already overridden.
//   - The policy file path (so the editor can surface it next to
//     the page header).
//   - The canonical YAML representation (for the YAML tab).
type policyAPIResponse struct {
	Path     string                  `json:"path"`
	Policy   policy.Policy           `json:"policy"`
	YAML     string                  `json:"yaml"`
	Rules    []policyAPIRuleCatalog  `json:"rules"`
	Warnings []string                `json:"warnings,omitempty"`
}

// policyAPIRuleCatalog is one rule's catalog entry as the dashboard
// sees it. Built from the rules registry + the current Policy so
// the editor can render every known rule with its effective state.
type policyAPIRuleCatalog struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"default_severity"`
	Category string `json:"category"`
}

// handleGetPolicy returns the current policy + the rule catalog as
// JSON. GET /api/policy.
func (s *Server) handleGetPolicy(w http.ResponseWriter, _ *http.Request) {
	path, err := policy.Path()
	if err != nil {
		http.Error(w, "policy path: "+err.Error(), http.StatusInternalServerError)
		return
	}
	p, loadErr := policy.Load(path)
	var warnings []string
	if loadErr != nil {
		// Don't return an error — the editor renders even when the
		// on-disk file is corrupt so the user can fix it.
		warnings = append(warnings, "policy file failed to load: "+loadErr.Error())
		p = policy.DefaultPolicy()
	}
	yamlBytes, _ := policy.MarshalCanonical(p)

	resp := policyAPIResponse{
		Path:     path,
		Policy:   p,
		YAML:     string(yamlBytes),
		Rules:    catalogRules(),
		Warnings: warnings,
	}
	writeJSON(w, http.StatusOK, resp)
}

// handlePutPolicy validates and writes a new policy. POST /api/policy.
// Body is JSON matching policyAPIResponse.Policy. Returns the
// canonical YAML the server actually persisted so the editor stays
// in sync with the canonical view.
func (s *Server) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB cap
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	var p policy.Policy
	if err := json.Unmarshal(body, &p); err != nil {
		http.Error(w, "parse JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if p.Version == 0 {
		p.Version = policy.PolicyVersion
	}
	if err := p.Validate(); err != nil {
		http.Error(w, "policy validation failed: "+err.Error(),
			http.StatusUnprocessableEntity)
		return
	}
	path, err := policy.Path()
	if err != nil {
		http.Error(w, "policy path: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := policy.Save(path, p); err != nil {
		http.Error(w, "save: "+err.Error(), http.StatusInternalServerError)
		return
	}
	yamlBytes, _ := policy.MarshalCanonical(p)
	writeJSON(w, http.StatusOK, policyAPIResponse{
		Path:   path,
		Policy: p,
		YAML:   string(yamlBytes),
		Rules:  catalogRules(),
	})
}

// handleValidatePolicy validates a policy WITHOUT writing it.
// POST /api/policy/validate. Useful for the dashboard's
// debounced-as-you-type lint loop.
func (s *Server) handleValidatePolicy(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	var p policy.Policy
	if err := json.Unmarshal(body, &p); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":  false,
			"errors": []string{"parse JSON: " + err.Error()},
		})
		return
	}
	if p.Version == 0 {
		p.Version = policy.PolicyVersion
	}
	if err := p.Validate(); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":  false,
			"errors": []string{err.Error()},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true})
}

// handleRulesList returns the rule catalog as JSON. GET /api/rules.
// Exposed separately so the dashboard can refresh just the rule
// list (e.g., after upgrading audr) without re-fetching the policy
// blob.
func (s *Server) handleRulesList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"rules": catalogRules()})
}

// catalogRules builds the rule catalog from the global registry.
// Sorted by rule-id for stable rendering. Category is derived from
// the first format the rule targets — a coarse grouping the
// dashboard uses to navigate (AI-AGENT / MCP / SHELL / etc.).
func catalogRules() []policyAPIRuleCatalog {
	all := rules.All()
	out := make([]policyAPIRuleCatalog, 0, len(all))
	for _, r := range all {
		out = append(out, policyAPIRuleCatalog{
			ID:       r.ID(),
			Title:    r.Title(),
			Severity: r.Severity().String(),
			Category: categoryForRule(r),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// categoryForRule groups rules into the dashboard's left-rail
// categories. Cheap heuristic: rule-id prefix wins, fallback to
// format-family. The categorization is informational — it does NOT
// affect rule behavior, just UI grouping.
func categoryForRule(r rules.Rule) string {
	id := r.ID()
	switch {
	case len(id) >= 4 && id[:4] == "mcp-":
		return "MCP"
	case len(id) >= 7 && id[:7] == "claude-":
		return "Claude"
	case len(id) >= 6 && id[:6] == "codex-":
		return "Codex"
	case len(id) >= 7 && id[:7] == "cursor-":
		return "Cursor"
	case len(id) >= 11 && id[:11] == "powershell-":
		return "PowerShell"
	case len(id) >= 8 && id[:8] == "shellrc-":
		return "Shell"
	case len(id) >= 4 && id[:4] == "gha-":
		return "GitHub Actions"
	case len(id) >= 6 && id[:6] == "skill-":
		return "Skill"
	case len(id) >= 9 && id[:9] == "openclaw-":
		return "OpenClaw"
	case len(id) >= 17 && id[:17] == "mini-shai-hulud-":
		return "Shai-Hulud"
	}
	return "Other"
}

// Compile-time check: finding.Severity must String()-ify the way
// catalogRules expects. Catches a future refactor that breaks the
// dashboard contract.
var _ = func() bool {
	if finding.SeverityCritical.String() != "critical" {
		panic("finding.SeverityCritical.String() drifted from 'critical'; policy.go catalog will be wrong")
	}
	return true
}()
