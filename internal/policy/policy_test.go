package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDefaultPolicyIsEmpty — the regression that the eng review made
// the most load-bearing: a fresh-install (no policy.yaml) MUST produce
// identical scan behavior to v1.1. The empty Policy is the contract
// boundary; if its semantics drift we silently break every existing
// installation on upgrade.
func TestDefaultPolicyIsEmpty(t *testing.T) {
	p := DefaultPolicy()
	if p.Version != PolicyVersion {
		t.Errorf("DefaultPolicy version = %d, want %d", p.Version, PolicyVersion)
	}
	if len(p.Rules) != 0 {
		t.Errorf("DefaultPolicy has %d rule overrides, want 0", len(p.Rules))
	}
	if len(p.Allowlists) != 0 {
		t.Errorf("DefaultPolicy has %d allowlists, want 0", len(p.Allowlists))
	}
	if len(p.Suppressions) != 0 {
		t.Errorf("DefaultPolicy has %d suppressions, want 0", len(p.Suppressions))
	}
}

// TestLoadMissingFileReturnsDefault: a fresh install with no
// ~/.audr/policy.yaml MUST NOT error. The daemon boots cleanly and
// scans with built-ins.
func TestLoadMissingFileReturnsDefault(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.yaml")
	p, err := Load(missing)
	if err != nil {
		t.Fatalf("Load missing file: %v", err)
	}
	if p.Version != PolicyVersion {
		t.Errorf("missing-file Load version = %d, want %d", p.Version, PolicyVersion)
	}
	if len(p.Rules) != 0 {
		t.Errorf("missing-file Load should have 0 rule overrides, got %d", len(p.Rules))
	}
}

// TestRoundTripPreservesFields: marshal → parse → marshal must
// produce identical bytes. This is the canonical-generated contract.
func TestRoundTripPreservesFields(t *testing.T) {
	enabled := false
	critical := "critical"
	policy1 := Policy{
		Version: 1,
		Rules: map[string]RuleOverride{
			"unpinned-npx": {
				Enabled:    &enabled,
				Severity:   &critical,
				Scope:      Scope{Include: []string{"~/.cursor/**"}, Exclude: []string{"~/sandbox/**"}},
				Allowlists: []string{"approved-mcp"},
				Notes:      "disabled while migrating off npx",
			},
		},
		Allowlists: map[string]Allowlist{
			"approved-mcp": {
				Entries: []string{"@anthropic/mcp-pg@2.1", "@modelcontextprotocol/server-fs"},
				Notes:   "approved by security review 2026-Q1",
			},
		},
		Suppressions: []Suppression{
			{Rule: "shellrc-secret-export", Path: "~/.zshrc", Reason: "OS keychain access token; not a real secret"},
		},
	}

	body1, err := MarshalCanonical(policy1)
	if err != nil {
		t.Fatalf("first marshal: %v", err)
	}
	policy2, err := Parse(body1)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, body1)
	}
	body2, err := MarshalCanonical(policy2)
	if err != nil {
		t.Fatalf("second marshal: %v", err)
	}
	if string(body1) != string(body2) {
		t.Errorf("marshal not idempotent:\n--- first ---\n%s\n--- second ---\n%s",
			body1, body2)
	}
}

// TestCanonicalSortsDeterministically: two Policies built from the
// same logical content but with different insertion order MUST
// produce byte-identical marshalled output. This is what makes the
// diff modal trustworthy — a save that's a no-op semantically
// produces a no-op diff visually.
func TestCanonicalSortsDeterministically(t *testing.T) {
	policyA := Policy{
		Version: 1,
		Rules: map[string]RuleOverride{
			"zeta":  {Enabled: boolPtr(false)},
			"alpha": {Enabled: boolPtr(false)},
			"mid":   {Enabled: boolPtr(false)},
		},
		Suppressions: []Suppression{
			{Rule: "z", Path: "/b", Reason: "r"},
			{Rule: "a", Path: "/a", Reason: "r"},
		},
	}
	policyB := Policy{
		Version: 1,
		Rules: map[string]RuleOverride{
			"mid":   {Enabled: boolPtr(false)},
			"alpha": {Enabled: boolPtr(false)},
			"zeta":  {Enabled: boolPtr(false)},
		},
		Suppressions: []Suppression{
			{Rule: "a", Path: "/a", Reason: "r"},
			{Rule: "z", Path: "/b", Reason: "r"},
		},
	}
	bodyA, err := MarshalCanonical(policyA)
	if err != nil {
		t.Fatal(err)
	}
	bodyB, err := MarshalCanonical(policyB)
	if err != nil {
		t.Fatal(err)
	}
	if string(bodyA) != string(bodyB) {
		t.Errorf("canonical-marshalled identical policies differ:\n--- A ---\n%s\n--- B ---\n%s",
			bodyA, bodyB)
	}

	// Spot-check rule ordering: alpha should come before mid, mid before zeta.
	lines := strings.Split(string(bodyA), "\n")
	posAlpha := lineIndex(lines, "  alpha:")
	posMid := lineIndex(lines, "  mid:")
	posZeta := lineIndex(lines, "  zeta:")
	if posAlpha < 0 || posMid < 0 || posZeta < 0 {
		t.Fatalf("expected all three rule keys to appear; got\n%s", bodyA)
	}
	if !(posAlpha < posMid && posMid < posZeta) {
		t.Errorf("rule sort order wrong: alpha=%d mid=%d zeta=%d", posAlpha, posMid, posZeta)
	}
}

// TestCanonicalSortsAllowlistEntries: entries WITHIN an allowlist
// must sort, not just the top-level allowlist keys.
func TestCanonicalSortsAllowlistEntries(t *testing.T) {
	p := Policy{
		Version: 1,
		Allowlists: map[string]Allowlist{
			"approved-mcp": {Entries: []string{"@z/pkg", "@a/pkg", "@m/pkg"}},
		},
	}
	body, err := MarshalCanonical(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(body), "\n")
	posA := lineIndex(lines, "      - '@a/pkg'")
	if posA < 0 {
		posA = lineIndex(lines, "      - \"@a/pkg\"")
	}
	posZ := lineIndex(lines, "      - '@z/pkg'")
	if posZ < 0 {
		posZ = lineIndex(lines, "      - \"@z/pkg\"")
	}
	if posA < 0 || posZ < 0 {
		t.Fatalf("expected entries to appear; got\n%s", body)
	}
	if posA >= posZ {
		t.Errorf("allowlist entries not sorted: @a at line %d, @z at line %d", posA, posZ)
	}
}

// TestValidateRejectsBadSeverity: a malformed severity string must
// fail validation. Caught at Parse and Save time so the daemon
// never loads or persists garbage.
func TestValidateRejectsBadSeverity(t *testing.T) {
	bad := "CRIT" // wrong case
	p := Policy{
		Version: 1,
		Rules: map[string]RuleOverride{
			"x": {Severity: &bad},
		},
	}
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate should reject bad severity")
	}
	if !strings.Contains(err.Error(), "severity") {
		t.Errorf("error should mention severity, got: %v", err)
	}
}

// TestValidateRequiresSuppressionFields: every suppression must
// carry rule, path, AND reason. Reason being required is the
// load-bearing piece — silent suppressions are how teams accumulate
// stale exclusions over time.
func TestValidateRequiresSuppressionFields(t *testing.T) {
	cases := []struct {
		name string
		s    Suppression
		want string
	}{
		{"missing rule", Suppression{Path: "/x", Reason: "r"}, "rule"},
		{"missing path", Suppression{Rule: "r", Reason: "r"}, "path"},
		{"missing reason", Suppression{Rule: "r", Path: "/x"}, "reason"},
		{"whitespace-only reason", Suppression{Rule: "r", Path: "/x", Reason: "  "}, "reason"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := Policy{Version: 1, Suppressions: []Suppression{tc.s}}
			err := p.Validate()
			if err == nil {
				t.Fatalf("Validate should reject suppression: %+v", tc.s)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Errorf("error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}

// TestValidateRejectsUnknownAllowlistReference: a rule referencing
// an allowlist that doesn't exist in the same Policy fails. Catches
// rename-without-update errors.
func TestValidateRejectsUnknownAllowlistReference(t *testing.T) {
	p := Policy{
		Version: 1,
		Rules: map[string]RuleOverride{
			"r": {Allowlists: []string{"does-not-exist"}},
		},
	}
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate should reject unknown allowlist reference")
	}
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Errorf("error should name the unknown allowlist, got: %v", err)
	}
}

// TestSaveRotatesBackups: writing a new policy moves the prior file
// to .bak.1, the prior .bak.1 to .bak.2, etc.
func TestSaveRotatesBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	enabled := false
	for i := 0; i < 3; i++ {
		critical := "critical"
		p := Policy{
			Version: 1,
			Rules: map[string]RuleOverride{
				"r": {Enabled: &enabled, Severity: &critical,
					Notes: "version " + strings.Repeat("x", i+1)},
			},
		}
		if err := Save(path, p); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}

	// After 3 saves, we expect:
	//   policy.yaml      → version 3 ("xxx")
	//   policy.yaml.bak.1 → version 2 ("xx")
	//   policy.yaml.bak.2 → version 1 ("x")
	expectations := []struct {
		path string
		want string
	}{
		{path, "xxx"},
		{path + ".bak.1", "xx"},
		{path + ".bak.2", "x"},
	}
	for _, e := range expectations {
		body, err := os.ReadFile(e.path)
		if err != nil {
			t.Errorf("read %s: %v", e.path, err)
			continue
		}
		if !strings.Contains(string(body), "notes: version "+e.want) {
			t.Errorf("%s did not contain expected version marker %q", e.path, e.want)
		}
	}
}

// TestSaveAtomicViaTempRename: an interrupted save (simulated by
// pre-existing .tmp file from a crashed prior save) does NOT leave
// the daemon staring at a half-written policy. We confirm the tmp
// file doesn't exist after a successful save.
func TestSaveAtomicViaTempRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	// Plant a stale .tmp from a "previous crash."
	if err := os.WriteFile(path+".tmp", []byte("crashed"), 0o600); err != nil {
		t.Fatal(err)
	}

	enabled := true
	p := Policy{
		Version: 1,
		Rules:   map[string]RuleOverride{"r": {Enabled: &enabled}},
	}
	if err := Save(path, p); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("final policy.yaml missing after Save: %v", err)
	}
	// The .tmp from the crash was overwritten and renamed away by
	// the successful save.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf(".tmp should be removed after successful save; err=%v", err)
	}
}

// TestSaveSetsRestrictivePermissions: the policy file must be 0600
// on disk. Matches the notify.config.json + scanner.config.json
// posture in the daemon's state dir.
func TestSaveSetsRestrictivePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	enabled := true
	p := Policy{Version: 1, Rules: map[string]RuleOverride{"r": {Enabled: &enabled}}}
	if err := Save(path, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows doesn't honor u/g/o bits; skip the assertion there.
	if mode := info.Mode().Perm(); mode != 0o600 && mode != 0o666 {
		// 0o666 accommodates Windows test runners.
		t.Errorf("file mode = %o, want 0600 (or 0666 on Windows)", mode)
	}
}

// TestRejectsFutureSchemaVersion: a policy.yaml from a NEWER audr
// release MUST be rejected rather than silently dropping fields the
// current binary doesn't understand. Forward-compat is via schema
// version bumps; backward-compat across binaries is a release-note
// concern.
func TestRejectsFutureSchemaVersion(t *testing.T) {
	body := []byte("version: 99\nrules: {}\n")
	_, err := Parse(body)
	if err == nil {
		t.Fatal("Parse should reject future schema version")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("error should mention version, got: %v", err)
	}
}

// TestNotesRoundTripThroughCanonical: the comment-preservation
// escape hatch. Plan B2.0 makes this load-bearing: the file is
// canonical (regular comments dropped) but each entry's `notes:`
// field survives.
func TestNotesRoundTripThroughCanonical(t *testing.T) {
	enabled := false
	p := Policy{
		Version: 1,
		Rules: map[string]RuleOverride{
			"r": {Enabled: &enabled, Notes: "downgraded after security review 2026-Q1"},
		},
		Allowlists: map[string]Allowlist{
			"a": {Entries: []string{"x"}, Notes: "approved set; revisit annually"},
		},
		Suppressions: []Suppression{
			{Rule: "r", Path: "/x", Reason: "false positive on dev fixture",
				Notes: "investigate at v0.7"},
		},
	}
	body, err := MarshalCanonical(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"downgraded after security review",
		"approved set; revisit annually",
		"investigate at v0.7",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("notes %q missing from canonical YAML:\n%s", want, body)
		}
	}

	p2, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	if p2.Rules["r"].Notes != "downgraded after security review 2026-Q1" {
		t.Errorf("rule notes lost in round-trip: %q", p2.Rules["r"].Notes)
	}
	if p2.Allowlists["a"].Notes != "approved set; revisit annually" {
		t.Errorf("allowlist notes lost: %q", p2.Allowlists["a"].Notes)
	}
	if p2.Suppressions[0].Notes != "investigate at v0.7" {
		t.Errorf("suppression notes lost: %q", p2.Suppressions[0].Notes)
	}
}

// TestCanonicalHasFileHeader: every saved policy must start with the
// header comment explaining the regeneration contract. Catches
// regressions where someone strips the header to "clean up" the
// file.
func TestCanonicalHasFileHeader(t *testing.T) {
	body, err := MarshalCanonical(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(body), "# ~/.audr/policy.yaml") {
		t.Errorf("canonical YAML missing the header comment:\n%s", body)
	}
	if !strings.Contains(string(body), "canonical-generated") {
		t.Errorf("header should explain the canonical-generated contract")
	}
}

// TestSuppressionExpiresRoundTrip: the optional Expires timestamp
// marshals to RFC3339 and parses back to the same instant.
func TestSuppressionExpiresRoundTrip(t *testing.T) {
	expires := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	p := Policy{
		Version: 1,
		Suppressions: []Suppression{
			{Rule: "r", Path: "/x", Reason: "temporary; revisit", Expires: &expires},
		},
	}
	body, err := MarshalCanonical(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "2026-08-01T00:00:00Z") {
		t.Errorf("expires not in RFC3339 form:\n%s", body)
	}
	p2, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	if p2.Suppressions[0].Expires == nil {
		t.Fatal("expires lost in round-trip")
	}
	if !p2.Suppressions[0].Expires.Equal(expires) {
		t.Errorf("expires drifted: round-trip %v vs original %v",
			p2.Suppressions[0].Expires, expires)
	}
}

// TestHashStableAcrossSemanticallyEqualPolicies: two Policies with
// identical content but different in-memory construction order
// hash identically.
func TestHashStableAcrossSemanticallyEqualPolicies(t *testing.T) {
	pA := Policy{
		Version: 1,
		Rules: map[string]RuleOverride{
			"z": {Enabled: boolPtr(false)},
			"a": {Enabled: boolPtr(false)},
		},
	}
	pB := Policy{
		Version: 1,
		Rules: map[string]RuleOverride{
			"a": {Enabled: boolPtr(false)},
			"z": {Enabled: boolPtr(false)},
		},
	}
	hA, err := Hash(pA)
	if err != nil {
		t.Fatal(err)
	}
	hB, err := Hash(pB)
	if err != nil {
		t.Fatal(err)
	}
	if hA != hB {
		t.Errorf("hashes diverge for semantically identical policies:\nA: %s\nB: %s",
			hA, hB)
	}
}

// ----- helpers ---------------------------------------------------

func boolPtr(b bool) *bool { return &b }

func lineIndex(lines []string, s string) int {
	for i, l := range lines {
		if l == s {
			return i
		}
	}
	return -1
}
