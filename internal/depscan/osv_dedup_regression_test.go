package depscan

import (
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/remediate"
)

// R3 (CRITICAL): v1.3 changed the OSV dedup key from per-(pkg,CVE) to
// per-package, with the `fixed` segment carrying max(fixed_version)
// across CVEs. The risk was that the simpler key would COLLAPSE
// detection — different CVEs falling into one row could obscure that
// we detected them. This regression locks the contract:
//
//   - Every advisory in the OSV report STILL produces its own
//     finding.Finding (one per CVE per path).
//   - The per-package max(fixed_version) ends up in the dedup key.
//   - Per-finding advisory IDs survive in Description / Context so
//     the dashboard's expanded view + the maintainer-link body can
//     still reference them.
//
// Concretely: the same package with N distinct CVEs across M paths
// emits N×M findings, all sharing one dedup_group_key. Dedup happens
// at render time, not at detection time.
func TestOSVDedupPerPackagePreservesAdvisoryCount(t *testing.T) {
	// Synthetic report: one package (protobufjs) with 3 CVEs at 2
	// distinct lockfile paths. Pre-v1.3 emitted 6 findings with 6
	// distinct dedup keys. Post-v1.3 still emits 6 findings (every
	// advisory detected) but all share a single per-package dedup key.
	raw := []byte(`{
		"results": [
			{
				"source": { "path": "/a/package-lock.json" },
				"packages": [
					{
						"package": { "name": "protobufjs", "ecosystem": "npm", "version": "7.0.0" },
						"vulnerabilities": [
							{
								"id": "GHSA-aaaa", "aliases": ["CVE-2025-1001"],
								"summary": "first vuln",
								"database_specific": { "severity": "HIGH" },
								"affected": [{ "ranges": [{ "events": [{ "fixed": "7.5.6" }] }] }]
							},
							{
								"id": "GHSA-bbbb", "aliases": ["CVE-2025-1002"],
								"summary": "second vuln",
								"database_specific": { "severity": "HIGH" },
								"affected": [{ "ranges": [{ "events": [{ "fixed": "8.0.1" }] }] }]
							},
							{
								"id": "GHSA-cccc", "aliases": ["CVE-2025-1003"],
								"summary": "third vuln",
								"database_specific": { "severity": "MEDIUM" },
								"affected": [{ "ranges": [{ "events": [{ "fixed": "7.2.0" }] }] }]
							}
						]
					}
				]
			},
			{
				"source": { "path": "/b/package-lock.json" },
				"packages": [
					{
						"package": { "name": "protobufjs", "ecosystem": "npm", "version": "7.0.0" },
						"vulnerabilities": [
							{
								"id": "GHSA-aaaa", "aliases": ["CVE-2025-1001"],
								"summary": "first vuln",
								"database_specific": { "severity": "HIGH" },
								"affected": [{ "ranges": [{ "events": [{ "fixed": "7.5.6" }] }] }]
							},
							{
								"id": "GHSA-bbbb", "aliases": ["CVE-2025-1002"],
								"summary": "second vuln",
								"database_specific": { "severity": "HIGH" },
								"affected": [{ "ranges": [{ "events": [{ "fixed": "8.0.1" }] }] }]
							},
							{
								"id": "GHSA-cccc", "aliases": ["CVE-2025-1003"],
								"summary": "third vuln",
								"database_specific": { "severity": "MEDIUM" },
								"affected": [{ "ranges": [{ "events": [{ "fixed": "7.2.0" }] }] }]
							}
						]
					}
				]
			}
		]
	}`)

	findings, err := ParseOSVScannerJSON(raw)
	if err != nil {
		t.Fatalf("ParseOSVScannerJSON: %v", err)
	}

	// 1) Detection: every CVE × path must be emitted. 3 CVEs × 2 paths = 6.
	if got := len(findings); got != 6 {
		t.Errorf("expected 6 findings (3 CVEs × 2 paths), got %d", got)
	}

	// 2) Per-finding advisory IDs survive in Description.
	wantAdvisories := map[string]int{"CVE-2025-1001": 0, "CVE-2025-1002": 0, "CVE-2025-1003": 0}
	for _, f := range findings {
		for adv := range wantAdvisories {
			if strings.Contains(f.Description, adv) {
				wantAdvisories[adv]++
			}
		}
	}
	for adv, count := range wantAdvisories {
		// Each advisory appears in 2 findings (one per path).
		if count != 2 {
			t.Errorf("advisory %s appears in %d findings, want 2 (one per path)", adv, count)
		}
	}

	// 3) Dedup key: every finding shares ONE per-package key with
	// max(fixed_version) = "8.0.1" (the highest across CVE-1001/1002/1003).
	keySeen := map[string]int{}
	for _, f := range findings {
		keySeen[f.DedupGroupKey]++
	}
	if len(keySeen) != 1 {
		t.Errorf("expected 1 dedup key shared across all 6 findings, got %d distinct keys: %v",
			len(keySeen), keys(keySeen))
	}

	var theKey string
	for k := range keySeen {
		theKey = k
	}
	parsed, ok := remediate.ParseOSVDedupKey(theKey)
	if !ok {
		t.Fatalf("dedup key %q failed to parse via remediate.ParseOSVDedupKey", theKey)
	}
	if parsed.Ecosystem != "npm" {
		t.Errorf("ecosystem = %q, want npm", parsed.Ecosystem)
	}
	if parsed.Package != "protobufjs" {
		t.Errorf("package = %q, want protobufjs", parsed.Package)
	}
	if parsed.FixedVersion != "8.0.1" {
		t.Errorf("fixed version = %q, want 8.0.1 (max across CVEs)", parsed.FixedVersion)
	}
	if parsed.AdvisoryID != "" {
		t.Errorf("advisory ID in key = %q, want empty (per-package key, CVE in finding body)", parsed.AdvisoryID)
	}
}

// TestOSVDedupDistinctPackagesStaySeparate locks the other half of
// the contract: two DIFFERENT packages with overlapping CVE shapes
// MUST emit distinct dedup keys. The renaming-bug failure mode here
// would be a substring-match somewhere collapsing protobufjs and
// @protobufjs/utf8 into the same row.
func TestOSVDedupDistinctPackagesStaySeparate(t *testing.T) {
	raw := []byte(`{
		"results": [{
			"source": { "path": "/a/package-lock.json" },
			"packages": [
				{
					"package": { "name": "protobufjs", "ecosystem": "npm", "version": "7.0.0" },
					"vulnerabilities": [{
						"id": "GHSA-aaaa", "aliases": ["CVE-2025-1001"],
						"summary": "x", "database_specific": { "severity": "HIGH" },
						"affected": [{ "ranges": [{ "events": [{ "fixed": "8.0.1" }] }] }]
					}]
				},
				{
					"package": { "name": "@protobufjs/utf8", "ecosystem": "npm", "version": "1.0.0" },
					"vulnerabilities": [{
						"id": "GHSA-aaaa", "aliases": ["CVE-2025-1001"],
						"summary": "x", "database_specific": { "severity": "HIGH" },
						"affected": [{ "ranges": [{ "events": [{ "fixed": "1.1.0" }] }] }]
					}]
				}
			]
		}]
	}`)
	findings, err := ParseOSVScannerJSON(raw)
	if err != nil {
		t.Fatalf("ParseOSVScannerJSON: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings (1 per package), got %d", len(findings))
	}
	if findings[0].DedupGroupKey == findings[1].DedupGroupKey {
		t.Errorf("distinct packages collapsed into same dedup key: %q", findings[0].DedupGroupKey)
	}
}

// TestOSVDedupPicksMaxFixedVersion locks the semver-aware compare
// inside the emitter's first pass. CVEs land in non-deterministic
// order from the JSON; the chosen fixed version MUST be the max.
func TestOSVDedupPicksMaxFixedVersion(t *testing.T) {
	cases := []struct {
		name      string
		fixed     []string
		wantMax   string
	}{
		{"simple", []string{"1.0.0", "2.5.0", "1.9.0"}, "2.5.0"},
		{"v-prefix mixed", []string{"v1.0.0", "1.2.3", "v0.9.0"}, "1.2.3"},
		{"three-segment win over two", []string{"5.0", "5.0.1"}, "5.0.1"},
		{"prerelease handling falls back to lexicographic", []string{"1.0.0", "1.0.0-rc1"}, "1.0.0-rc1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vulns := make([]string, 0, len(tc.fixed))
			for i, f := range tc.fixed {
				vulns = append(vulns, `{
					"id": "GHSA-`+string(rune('a'+i))+`",
					"aliases": ["CVE-2025-`+itoa(i)+`"],
					"summary": "",
					"database_specific": { "severity": "HIGH" },
					"affected": [{ "ranges": [{ "events": [{ "fixed": "`+f+`" }] }] }]
				}`)
			}
			raw := []byte(`{
				"results": [{
					"source": { "path": "/a/lock.json" },
					"packages": [{
						"package": { "name": "p", "ecosystem": "npm", "version": "0.0.0" },
						"vulnerabilities": [` + strings.Join(vulns, ",") + `]
					}]
				}]
			}`)
			findings, err := ParseOSVScannerJSON(raw)
			if err != nil {
				t.Fatalf("ParseOSVScannerJSON: %v", err)
			}
			if len(findings) == 0 {
				t.Fatal("expected findings, got 0")
			}
			parsed, ok := remediate.ParseOSVDedupKey(findings[0].DedupGroupKey)
			if !ok {
				t.Fatalf("failed to parse dedup key %q", findings[0].DedupGroupKey)
			}
			if parsed.FixedVersion != tc.wantMax {
				t.Errorf("max fixed = %q, want %q", parsed.FixedVersion, tc.wantMax)
			}
		})
	}
}

func keys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	out := []byte{}
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		out = append([]byte{byte('0' + n%10)}, out...)
		n /= 10
	}
	if neg {
		out = append([]byte{'-'}, out...)
	}
	return string(out)
}
