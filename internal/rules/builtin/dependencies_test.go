package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/rules"
)

func TestAgentPackageKnownVulnerable_IsNotRegistered(t *testing.T) {
	for _, rule := range rules.All() {
		if rule.ID() == "agent-package-known-vulnerable" {
			t.Fatalf("agent-package-known-vulnerable should not be registered; external OSV/Trivy scanners own dependency CVE coverage")
		}
	}
}
