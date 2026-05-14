// Package templates produces remediation text for an audr finding:
// (human-readable steps, paste-ready AI-agent prompt). It replaces the
// Phase 2 demo lookup with a per-rule + per-ecosystem dispatch covering
// audr's full v0.2 ruleset plus the OSV language ecosystems and OS
// package managers.
//
// Dispatch order:
//
//   1. Exact rule_id match (covers the 20-ish built-in rules).
//   2. rule_id prefix match (covers `osv-<ecosystem>-package` for
//      depscan and `osv-<manager>-<name>` for ospkg).
//   3. Category fallback (returns a templated prompt parameterized
//      by category + locator so even an unknown rule produces a
//      useful prompt).
//
// Implements server.RemediationLookup. Constructed once at daemon
// startup and passed to server.Options.Remediation.
package templates

import (
	"encoding/json"
	"strings"

	"github.com/harshmaur/audr/internal/state"
)

// Registry implements RemediationLookup. Add new rule handlers by
// appending to the perRule map or the prefix handlers slice.
type Registry struct {
	perRule   map[string]Handler
	prefixHandlers []prefixHandler
	fallback  Handler
}

// Handler produces (human_steps, ai_prompt) for a finding. Returns
// ok=false to fall through to the next handler in dispatch.
type Handler func(f state.Finding, loc Locator) (human, ai string, ok bool)

type prefixHandler struct {
	prefix  string
	handler Handler
}

// Locator is the parsed shape of state.Finding.Locator with typed
// accessors. We unmarshal once at dispatch time so handlers don't
// have to repeat the JSON parse.
type Locator struct {
	raw map[string]any
}

// String returns the locator value at key as a string. Empty when
// missing or non-string.
func (l Locator) String(key string) string {
	if v, ok := l.raw[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// Int returns the locator value at key as an int (0 when missing).
// JSON unmarshal decodes numbers as float64, so we convert.
func (l Locator) Int(key string) int {
	if v, ok := l.raw[key]; ok {
		if f, ok := v.(float64); ok {
			return int(f)
		}
	}
	return 0
}

// New builds the production Registry. Order of registration matters
// for prefix handlers (first match wins); exact-match rules are in a
// map and unordered. OS-package prefixes (osv-dpkg-, osv-rpm-,
// osv-apk-) MUST be registered before the language-ecosystem
// catchall (osv-) or the catchall claims everything starting with
// osv- and the OS-pkg-specific recipes never run.
func New() *Registry {
	r := &Registry{
		perRule: map[string]Handler{},
	}
	registerNativeRules(r)
	registerOSPkgHandlers(r)     // specific os-pkg manager prefixes FIRST
	registerEcosystemHandlers(r) // language ecosystems + osv- catchall LAST
	registerSecretHandlers(r)
	r.fallback = fallbackHandler
	return r
}

// Lookup implements server.RemediationLookup. Returns (human_steps,
// ai_prompt, true) when any handler in the dispatch chain produces
// content; falls back to the generic handler which always returns
// ok=true. ok=false is reserved for caller-side use (e.g., the demo
// registry's selective coverage).
func (r *Registry) Lookup(f state.Finding) (human, ai string, ok bool) {
	loc := Locator{}
	if len(f.Locator) > 0 {
		_ = json.Unmarshal(f.Locator, &loc.raw)
	}

	if h, exists := r.perRule[f.RuleID]; exists {
		if human, ai, ok := h(f, loc); ok {
			return human, ai, true
		}
	}
	for _, ph := range r.prefixHandlers {
		if strings.HasPrefix(f.RuleID, ph.prefix) {
			if human, ai, ok := ph.handler(f, loc); ok {
				return human, ai, true
			}
		}
	}
	if r.fallback != nil {
		human, ai, _ := r.fallback(f, loc)
		return human, ai, true
	}
	return "", "", false
}

// register helpers — small wrappers so the per-category files in this
// package read cleanly.

func (r *Registry) registerRule(ruleID string, h Handler) {
	r.perRule[ruleID] = h
}

func (r *Registry) registerPrefix(prefix string, h Handler) {
	r.prefixHandlers = append(r.prefixHandlers, prefixHandler{prefix: prefix, handler: h})
}
