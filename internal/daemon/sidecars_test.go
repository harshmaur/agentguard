package daemon

import (
	"testing"
)

func TestParseOSVScannerVersionAcceptsRealOutput(t *testing.T) {
	// Verbatim shape of `osv-scanner --version` from v1.8.x. Reproduced
	// from upstream release notes; do NOT trim the leading whitespace
	// (the parser must tolerate the indent).
	stdout := []byte("osv-scanner version: 1.8.2\ncommit: deadbeef\nbuilt at: 2024-04-12T00:00:00Z\n")
	got, ok := parseOSVScannerVersion(stdout, nil)
	if !ok {
		t.Fatalf("parseOSVScannerVersion returned ok=false on real input %q", stdout)
	}
	if got != "1.8.2" {
		t.Errorf("parsed version = %q, want 1.8.2", got)
	}
}

func TestParseTruffleHogVersionAcceptsRealOutput(t *testing.T) {
	tests := []struct {
		name   string
		stdout []byte
		want   string
	}{
		{
			name:   "plain trufflehog 3.63.0",
			stdout: []byte("trufflehog 3.63.0\n"),
			want:   "3.63.0",
		},
		{
			name:   "with build suffix",
			stdout: []byte("trufflehog 3.81.5-rc1\n"),
			want:   "3.81.5-rc1",
		},
		{
			name:   "stderr only (older Go-built trufflehog)",
			stdout: nil,
			want:   "3.63.0",
		},
	}
	// special-case: third case puts the version on stderr.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr []byte
			if tt.name == "stderr only (older Go-built trufflehog)" {
				stderr = []byte("trufflehog 3.63.0\n")
			}
			got, ok := parseTruffleHogVersion(tt.stdout, stderr)
			if !ok {
				t.Fatalf("parseTruffleHogVersion ok=false")
			}
			if got != tt.want {
				t.Errorf("parsed version = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseVersionRejectsBogus(t *testing.T) {
	cases := []string{"", "v1", "x.y.z", "1.2.3.4", "1", "abc1.2.3"}
	for _, c := range cases {
		if _, ok := parseVersion(c); ok {
			t.Errorf("parseVersion(%q) ok=true, want false", c)
		}
	}
}

func TestCompareSemverOrdering(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.8.0", "1.8.0", 0},
		{"1.8.0", "1.8.1", -1},
		{"1.8.1", "1.8.0", 1},
		{"1.7.99", "1.8.0", -1},
		{"2.0.0", "1.99.99", 1},
		{"3.63.0-rc1", "3.63.0", 0}, // pre-release stripped
		{"3.63.0+build5", "3.63.0", 0},
	}
	for _, tt := range tests {
		got, ok := compareSemver(tt.a, tt.b)
		if !ok {
			t.Errorf("compareSemver(%q, %q) ok=false", tt.a, tt.b)
			continue
		}
		if got != tt.want {
			t.Errorf("compareSemver(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCompareToMinClassifications(t *testing.T) {
	tests := []struct {
		found, min string
		want       SidecarState
	}{
		{"1.8.2", "1.8.0", SidecarOK},
		{"1.8.0", "1.8.0", SidecarOK},
		{"1.7.99", "1.8.0", SidecarOutdated},
		{"badver", "1.8.0", SidecarError},
		{"1.8.0", "notparseable", SidecarError},
	}
	for _, tt := range tests {
		if got := compareToMin(tt.found, tt.min); got != tt.want {
			t.Errorf("compareToMin(%q, %q) = %q, want %q", tt.found, tt.min, got, tt.want)
		}
	}
}

func TestDefaultSidecarConfigHasPositiveTimeout(t *testing.T) {
	c := DefaultSidecarConfig()
	if c.ProbeTimeout <= 0 {
		t.Errorf("default probe timeout = %v, want > 0", c.ProbeTimeout)
	}
	if c.OSVScannerMinVersion == "" || c.TruffleHogMinVersion == "" {
		t.Errorf("default min versions empty: %+v", c)
	}
}
