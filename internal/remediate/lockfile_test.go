package remediate

import (
	"strings"
	"testing"
)

func TestDetectFormat(t *testing.T) {
	cases := []struct {
		path string
		want LockfileFormat
	}{
		{"/home/alice/projects/audr/package-lock.json", FormatNPM},
		{"npm-shrinkwrap.json", FormatNPM},
		{"/x/yarn.lock", FormatYarn},
		{"pnpm-lock.yaml", FormatPNPM},
		{"bun.lock", FormatBun},
		{"bun.lockb", FormatBun},
		{"go.sum", FormatGo},
		{"go.mod", FormatGo},
		{"Cargo.lock", FormatCargo},
		{"requirements.txt", FormatUnknown},
		{"Pipfile.lock", FormatUnknown},
		{"", FormatUnknown},
	}
	for _, tc := range cases {
		got := DetectFormat(tc.path)
		if got != tc.want {
			t.Errorf("DetectFormat(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestEcosystemMatches(t *testing.T) {
	cases := []struct {
		ecosystem string
		format    LockfileFormat
		want      bool
	}{
		// JS family all match "npm".
		{"npm", FormatNPM, true},
		{"npm", FormatYarn, true},
		{"npm", FormatPNPM, true},
		{"npm", FormatBun, true},
		{"NPM", FormatNPM, true}, // case-insensitive normalisation
		{"  npm  ", FormatNPM, true},

		// Go.
		{"Go", FormatGo, true},
		{"go", FormatGo, true},

		// Cargo accepts a few canonical spellings.
		{"crates.io", FormatCargo, true},
		{"cratesio", FormatCargo, true},
		{"cargo", FormatCargo, true},

		// Cross-ecosystem mismatches MUST return false — this is the F6
		// guard. Without it, audr could render a Go replace snippet
		// against a JS lockfile.
		{"npm", FormatGo, false},
		{"Go", FormatNPM, false},
		{"crates.io", FormatNPM, false},
		{"PyPI", FormatNPM, false},
		{"", FormatNPM, false},
		{"npm", FormatUnknown, false},
		{"", FormatUnknown, false},
	}
	for _, tc := range cases {
		got := EcosystemMatches(tc.ecosystem, tc.format)
		if got != tc.want {
			t.Errorf("EcosystemMatches(%q, %q) = %v, want %v",
				tc.ecosystem, tc.format, got, tc.want)
		}
	}
}

func TestSnippet_PerFormat(t *testing.T) {
	cases := []struct {
		name           string
		format         LockfileFormat
		pkg            string
		fixed          string
		wantContains   []string
		wantNotContain []string
	}{
		{
			name:         "npm overrides",
			format:       FormatNPM,
			pkg:          "undici",
			fixed:        "5.28.4",
			wantContains: []string{`"overrides"`, `"undici"`, `"^5.28.4"`},
		},
		{
			name:         "bun uses npm-shaped overrides",
			format:       FormatBun,
			pkg:          "picomatch",
			fixed:        "2.3.1",
			wantContains: []string{`"overrides"`, `"picomatch"`, `"^2.3.1"`},
		},
		{
			name:         "yarn resolutions",
			format:       FormatYarn,
			pkg:          "hono",
			fixed:        "4.10.0",
			wantContains: []string{`"resolutions"`, `"hono"`, `"^4.10.0"`},
		},
		{
			name:         "pnpm.overrides nested",
			format:       FormatPNPM,
			pkg:          "@hono/node-server",
			fixed:        "1.10.0",
			wantContains: []string{`"pnpm"`, `"overrides"`, `"@hono/node-server"`, `"^1.10.0"`},
		},
		{
			name:         "go replace directive",
			format:       FormatGo,
			pkg:          "github.com/some/dep",
			fixed:        "v1.2.3",
			wantContains: []string{`replace github.com/some/dep => github.com/some/dep v1.2.3`},
		},
		{
			name:         "go replace strips leading v",
			format:       FormatGo,
			pkg:          "github.com/some/dep",
			fixed:        "1.2.3", // already no leading v
			wantContains: []string{"v1.2.3"},
		},
		{
			name:         "cargo patch block",
			format:       FormatCargo,
			pkg:          "regex",
			fixed:        "1.10.0",
			wantContains: []string{`[patch.crates-io]`, `regex = "1.10.0"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Snippet(tc.format, tc.pkg, tc.fixed)
			for _, want := range tc.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("Snippet missing %q in output:\n%s", want, got)
				}
			}
			for _, ng := range tc.wantNotContain {
				if strings.Contains(got, ng) {
					t.Errorf("Snippet unexpectedly contained %q in output:\n%s", ng, got)
				}
			}
		})
	}
}

func TestSnippet_EmptyOnDegenerateInputs(t *testing.T) {
	cases := []struct {
		name   string
		format LockfileFormat
		pkg    string
		fixed  string
	}{
		{"unknown format", FormatUnknown, "x", "1.0.0"},
		{"empty fixed version", FormatNPM, "x", ""},
		{"whitespace-only fixed", FormatNPM, "x", "  "},
		{"empty pkg", FormatNPM, "", "1.0.0"},
		{"whitespace pkg", FormatNPM, " \t", "1.0.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Snippet(tc.format, tc.pkg, tc.fixed); got != "" {
				t.Errorf("expected empty snippet, got:\n%s", got)
			}
		})
	}
}
