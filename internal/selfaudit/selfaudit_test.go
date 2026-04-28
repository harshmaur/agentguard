package selfaudit

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/harshmaur/agentguard/internal/correlate"
	"github.com/harshmaur/agentguard/internal/rules"
	_ "github.com/harshmaur/agentguard/internal/rules/builtin"
)

// TestBuild_BinaryFieldsPopulated asserts the per-binary fields look right.
// Hashing the running test binary produces a specific shape; we verify the
// shape, not the value (the value changes per build).
func TestBuild_BinaryFieldsPopulated(t *testing.T) {
	r, err := Build("vTEST")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if r.Binary.Path == "" {
		t.Errorf("Binary.Path empty")
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(r.Binary.Sha256) {
		t.Errorf("Binary.Sha256 = %q, want 64 lowercase hex chars", r.Binary.Sha256)
	}
	if r.Binary.Size <= 0 {
		t.Errorf("Binary.Size = %d, want > 0", r.Binary.Size)
	}
	if r.Binary.Version != "vTEST" {
		t.Errorf("Binary.Version = %q, want %q", r.Binary.Version, "vTEST")
	}
	if r.Binary.OS == "" || r.Binary.Arch == "" || r.Binary.GoVer == "" {
		t.Errorf("Binary.OS/Arch/GoVer must all be non-empty: %+v", r.Binary)
	}
	if r.GeneratedAt.IsZero() {
		t.Errorf("GeneratedAt is zero")
	}
}

// TestBuild_RuleCountMatchesRegistry catches a refactor that would silently
// drop rules from the manifest. The counts must agree exactly.
func TestBuild_RuleCountMatchesRegistry(t *testing.T) {
	r, err := Build("vTEST")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got, want := len(r.Rules), len(rules.All()); got != want {
		t.Fatalf("Rules count = %d, registry has %d", got, want)
	}
	// Spot-check that fields are populated for at least the first rule.
	first := r.Rules[0]
	if first.ID == "" || first.Title == "" || first.Severity == "" || first.Taxonomy == "" {
		t.Errorf("first rule has empty fields: %+v", first)
	}
}

// TestBuild_ChainCountMatchesManifest pairs with correlate's
// TestManifest_MatchesScenarios — together they prevent self-audit from
// silently underreporting chains when a new scenario is added.
func TestBuild_ChainCountMatchesManifest(t *testing.T) {
	r, err := Build("vTEST")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got, want := len(r.Chains), len(correlate.Manifest()); got != want {
		t.Fatalf("Chains count = %d, manifest has %d", got, want)
	}
}

// TestBuild_StableJSONShape pins the top-level JSON keys so CMDB ingestors
// don't break across versions. Adding a key is fine; renaming or removing
// one is a deliberate breaking change and should fail this test loudly.
func TestBuild_StableJSONShape(t *testing.T) {
	r, err := Build("vTEST")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	bs, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(bs, &top); err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{"generated_at", "binary", "rules", "attack_chains"}
	for _, k := range wantKeys {
		if _, ok := top[k]; !ok {
			t.Errorf("missing top-level key %q in JSON output (have keys: %v)", k, sortedKeys(top))
		}
	}

	// Binary section must include path, sha256, version, os, arch.
	var bin map[string]json.RawMessage
	if err := json.Unmarshal(top["binary"], &bin); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"path", "sha256", "size_bytes", "version", "go_version", "os", "arch"} {
		if _, ok := bin[k]; !ok {
			t.Errorf("missing binary key %q (have: %v)", k, sortedKeys(bin))
		}
	}
}

func sortedKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
