package output

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestSchema_EmbedIsWellFormed asserts the embedded schema document
// parses as JSON. Without this, a typo in report.v1.json would only
// surface at the moment a downstream consumer tries to validate
// against it — too late.
func TestSchema_EmbedIsWellFormed(t *testing.T) {
	bytes := Schema()
	if len(bytes) == 0 {
		t.Fatalf("embedded schema is empty (go:embed did not include report.v1.json?)")
	}
	var doc map[string]any
	if err := json.Unmarshal(bytes, &doc); err != nil {
		t.Fatalf("embedded schema is malformed JSON: %v", err)
	}
}

// TestSchema_IDMatchesAdvertisedURL asserts the $id in the embedded
// schema matches the SchemaURL constant the binary stamps onto every
// Report. If they ever drift, agents fetching the advertised URL would
// not get the schema audr meant.
func TestSchema_IDMatchesAdvertisedURL(t *testing.T) {
	var doc struct {
		ID string `json:"$id"`
	}
	if err := json.Unmarshal(Schema(), &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if doc.ID != SchemaURL {
		t.Fatalf("schema $id %q != SchemaURL %q — drift bug, fix one of them",
			doc.ID, SchemaURL)
	}
}

// TestSchema_RequiredTopLevelFields locks in the v1 contract: agents
// know they can count on schema, version, generated_at, stats, findings
// being present. Optional fields (baseline_diff, applied_filters, etc.)
// must NOT be in the required list — they're optional by design.
func TestSchema_RequiredTopLevelFields(t *testing.T) {
	var doc struct {
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(Schema(), &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	wantRequired := map[string]bool{
		"schema": true, "version": true, "generated_at": true,
		"stats": true, "findings": true,
	}
	mustNotBeRequired := map[string]bool{
		"baseline_diff": true, "applied_filters": true,
		"attack_chains": true, "warnings": true, "roots": true,
		"environment": true, "scan_mounts": true, "self_audit": true,
	}
	got := map[string]bool{}
	for _, r := range doc.Required {
		got[r] = true
	}
	for k := range wantRequired {
		if !got[k] {
			t.Errorf("schema is missing required top-level field %q", k)
		}
	}
	for k := range mustNotBeRequired {
		if got[k] {
			t.Errorf("schema marks %q as required, but it must stay optional for v1 additivity", k)
		}
	}
}

// TestSchema_DescribesBaselineDiff asserts the v1.1 additions
// (baseline_diff + applied_filters) appear in the schema's $defs. If
// you add a new top-level optional field, add a corresponding $defs
// entry AND a property reference so consumers can validate it.
func TestSchema_DescribesBaselineDiff(t *testing.T) {
	var doc struct {
		Defs       map[string]any `json:"$defs"`
		Properties map[string]any `json:"properties"`
	}
	if err := json.Unmarshal(Schema(), &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, name := range []string{"BaselineDiff", "AppliedFilters", "Finding", "Stats", "FixAuthority"} {
		if _, ok := doc.Defs[name]; !ok {
			t.Errorf("schema $defs missing %q", name)
		}
	}
	for _, name := range []string{"baseline_diff", "applied_filters", "findings", "stats"} {
		if _, ok := doc.Properties[name]; !ok {
			t.Errorf("schema properties missing %q", name)
		}
	}
}

// TestSchema_FixAuthorityEnumComplete asserts the enum values in the
// schema match the constants in finding/finding.go. New FixAuthority
// values added without updating the schema would mean the schema lies
// about what audr actually emits.
func TestSchema_FixAuthorityEnumComplete(t *testing.T) {
	var doc struct {
		Defs struct {
			FixAuthority struct {
				Enum []string `json:"enum"`
			} `json:"FixAuthority"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(Schema(), &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := map[string]bool{"you": true, "maintainer": true, "upstream": true}
	got := map[string]bool{}
	for _, v := range doc.Defs.FixAuthority.Enum {
		got[v] = true
	}
	for k := range want {
		if !got[k] {
			t.Errorf("FixAuthority enum missing %q", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("FixAuthority enum has unexpected value %q — update both sides if intentional", k)
		}
	}
}

// TestSchema_ReferencedFromJSONOutput documents the load-bearing tie:
// the SchemaURL constant must match the schema bytes we embed. Both
// the binary's JSON output and an external validator must agree.
func TestSchema_ReferencedFromJSONOutput(t *testing.T) {
	if !strings.Contains(string(Schema()), `"$id"`) {
		t.Fatalf("embedded schema is missing $id — required for content-addressing")
	}
}
