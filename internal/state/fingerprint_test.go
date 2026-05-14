package state

import (
	"strings"
	"testing"
)

func TestFingerprintIsStableAcrossEquivalentLocators(t *testing.T) {
	// Two locator JSON blobs differ only in key order + whitespace,
	// they MUST produce the same fingerprint.
	a, err := Fingerprint("rule-x", "file", []byte(`{"path":"/x","line":12}`), "match")
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := Fingerprint("rule-x", "file", []byte(`{ "line": 12, "path": "/x" }`), "match")
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a != b {
		t.Errorf("equivalent locators produced different fingerprints:\n  a=%s\n  b=%s", a, b)
	}
}

func TestFingerprintDistinguishesDifferentInputs(t *testing.T) {
	base, _ := Fingerprint("rule-x", "file", []byte(`{"path":"/x","line":12}`), "match")
	cases := []struct {
		name      string
		ruleID    string
		kind      string
		locator   string
		match     string
	}{
		{"different rule", "rule-y", "file", `{"path":"/x","line":12}`, "match"},
		{"different kind", "rule-x", "os-package", `{"path":"/x","line":12}`, "match"},
		{"different locator path", "rule-x", "file", `{"path":"/y","line":12}`, "match"},
		{"different locator line", "rule-x", "file", `{"path":"/x","line":13}`, "match"},
		{"different match", "rule-x", "file", `{"path":"/x","line":12}`, "different"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Fingerprint(tt.ruleID, tt.kind, []byte(tt.locator), tt.match)
			if err != nil {
				t.Fatal(err)
			}
			if got == base {
				t.Errorf("expected different fingerprint for %s, got same: %s", tt.name, got)
			}
		})
	}
}

func TestFingerprintHexLength(t *testing.T) {
	got, err := Fingerprint("rule", "file", []byte("{}"), "")
	if err != nil {
		t.Fatal(err)
	}
	// SHA-256 = 32 bytes = 64 hex chars.
	if len(got) != 64 {
		t.Errorf("fingerprint length = %d, want 64", len(got))
	}
	if strings.ContainsAny(got, "GHIJKLMNOPQRSTUVWXYZ-_") {
		t.Errorf("fingerprint contains non-hex: %s", got)
	}
}

func TestFingerprintAcceptsEmptyLocator(t *testing.T) {
	// Some findings (e.g., chain findings) have no specific locator.
	// Empty body should canonicalize to "null" and hash cleanly.
	got, err := Fingerprint("chain-1", "chain", nil, "x")
	if err != nil {
		t.Fatalf("empty locator: %v", err)
	}
	if got == "" {
		t.Fatal("empty fingerprint")
	}
}

func TestFingerprintRejectsMalformedLocator(t *testing.T) {
	if _, err := Fingerprint("rule", "file", []byte(`{bogus`), "match"); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestCanonicalEncodeSortsObjectKeys(t *testing.T) {
	got, err := canonicalizeJSON([]byte(`{"b":1,"a":2,"c":3}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":2,"b":1,"c":3}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestCanonicalEncodePreservesArrayOrder(t *testing.T) {
	got, err := canonicalizeJSON([]byte(`[3,1,2]`))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `[3,1,2]` {
		t.Errorf("got %s, want [3,1,2] — arrays must NOT be reordered", got)
	}
}

func TestCanonicalEncodeNestedObject(t *testing.T) {
	got, err := canonicalizeJSON([]byte(`{"outer":{"z":1,"a":2},"inner":[{"b":1,"a":2}]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"inner":[{"a":2,"b":1}],"outer":{"a":2,"z":1}}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
