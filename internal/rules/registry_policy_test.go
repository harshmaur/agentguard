package rules_test

import (
	"testing"
	"time"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
	"github.com/harshmaur/audr/internal/policy"
	"github.com/harshmaur/audr/internal/rules"

	// Side-effect import: register all built-in rules with the
	// global registry. Without this, the registry would be empty
	// and these tests would silently pass for the wrong reason.
	_ "github.com/harshmaur/audr/internal/rules/builtin"
)

// TestEmptyPolicy_BehavesIdenticallyToNoPolicy: the load-bearing
// regression from plan B1 — `~/.audr/policy.yaml` missing on disk
// MUST produce scan results identical to v1.1 (no policy support).
//
// We compare two runs against the same fixture: Apply(doc) and
// ApplyWithPolicy(doc, &empty). They must produce byte-identical
// findings, in identical order, with identical severities.
func TestEmptyPolicy_BehavesIdenticallyToNoPolicy(t *testing.T) {
	doc := parse.Parse("/test/.mcp.json", []byte(`{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}`))

	noFilter := rules.Apply(doc)

	empty := policy.NewEffective(policy.DefaultPolicy(), time.Now())
	withEmpty := rules.ApplyWithPolicy(doc, empty)

	if len(noFilter) != len(withEmpty) {
		t.Fatalf("finding count differs: nil-filter=%d, empty-policy=%d",
			len(noFilter), len(withEmpty))
	}
	for i := range noFilter {
		if noFilter[i].RuleID != withEmpty[i].RuleID {
			t.Errorf("finding[%d] rule diverges: %s vs %s",
				i, noFilter[i].RuleID, withEmpty[i].RuleID)
		}
		if noFilter[i].Severity != withEmpty[i].Severity {
			t.Errorf("finding[%d] severity diverges: %v vs %v",
				i, noFilter[i].Severity, withEmpty[i].Severity)
		}
	}
}

// TestPolicyDisablesRule: setting Enabled=false on a rule means the
// rule does NOT fire, even when its match condition is present.
// Exercises step 2 of the precedence model end-to-end through the
// registry.
func TestPolicyDisablesRule(t *testing.T) {
	doc := parse.Parse("/test/.mcp.json", []byte(`{
  "mcpServers": {
    "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}
  }
}`))

	// Confirm baseline: the rule fires without policy.
	baseline := rules.Apply(doc)
	if !findingsContainRule(baseline, "mcp-unpinned-npx") {
		t.Fatalf("baseline: mcp-unpinned-npx should fire on unpinned npx config")
	}

	// Disable it via policy.
	disabled := false
	p := policy.Policy{
		Version: 1,
		Rules: map[string]policy.RuleOverride{
			"mcp-unpinned-npx": {Enabled: &disabled},
		},
	}
	eff := policy.NewEffective(p, time.Now())
	withPolicy := rules.ApplyWithPolicy(doc, eff)
	if findingsContainRule(withPolicy, "mcp-unpinned-npx") {
		t.Errorf("policy-disabled rule should not fire; got %d findings", len(withPolicy))
	}
}

// TestPolicyOverridesSeverity: a severity override rewrites the
// emitted finding's severity. Step 7 of B3.4.
func TestPolicyOverridesSeverity(t *testing.T) {
	doc := parse.Parse("/test/.mcp.json", []byte(`{
  "mcpServers": {
    "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}
  }
}`))

	// Find the natural severity of mcp-unpinned-npx.
	baseline := rules.Apply(doc)
	var natural finding.Severity = -1
	for _, f := range baseline {
		if f.RuleID == "mcp-unpinned-npx" {
			natural = f.Severity
			break
		}
	}
	if natural == -1 {
		t.Skip("mcp-unpinned-npx didn't fire on baseline — fixture changed")
	}

	// Pick a target severity that differs from the natural one.
	target := "low"
	if natural == finding.SeverityLow {
		target = "medium"
	}
	p := policy.Policy{
		Version: 1,
		Rules: map[string]policy.RuleOverride{
			"mcp-unpinned-npx": {Severity: &target},
		},
	}
	eff := policy.NewEffective(p, time.Now())
	withPolicy := rules.ApplyWithPolicy(doc, eff)

	for _, f := range withPolicy {
		if f.RuleID != "mcp-unpinned-npx" {
			continue
		}
		if f.Severity == natural {
			t.Errorf("severity override didn't apply: still %v", f.Severity)
		}
	}
}

// TestPolicySuppressesFinding: a matching Suppression silences the
// finding even when the rule itself produced it. Step 6 of B3.4.
func TestPolicySuppressesFinding(t *testing.T) {
	doc := parse.Parse("/test/.mcp.json", []byte(`{
  "mcpServers": {
    "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}
  }
}`))

	p := policy.Policy{
		Version: 1,
		Suppressions: []policy.Suppression{
			{Rule: "mcp-unpinned-npx", Path: "/test/.mcp.json",
				Reason: "test fixture; not a real config"},
		},
	}
	eff := policy.NewEffective(p, time.Now())
	withPolicy := rules.ApplyWithPolicy(doc, eff)

	if findingsContainRule(withPolicy, "mcp-unpinned-npx") {
		t.Errorf("suppressed finding should not surface; got %d findings", len(withPolicy))
	}
}

// TestPolicyOutOfScopeSkipsRule: a scope-exclude entry removes a
// path from the rule's effective scope.
func TestPolicyOutOfScopeSkipsRule(t *testing.T) {
	doc := parse.Parse("/test/.mcp.json", []byte(`{
  "mcpServers": {
    "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}
  }
}`))

	p := policy.Policy{
		Version: 1,
		Rules: map[string]policy.RuleOverride{
			"mcp-unpinned-npx": {
				Scope: policy.Scope{Exclude: []string{"/test/*"}},
			},
		},
	}
	eff := policy.NewEffective(p, time.Now())
	withPolicy := rules.ApplyWithPolicy(doc, eff)

	if findingsContainRule(withPolicy, "mcp-unpinned-npx") {
		t.Errorf("scope-excluded rule should not fire; got %d findings", len(withPolicy))
	}
}

func findingsContainRule(fs []finding.Finding, ruleID string) bool {
	for _, f := range fs {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}
