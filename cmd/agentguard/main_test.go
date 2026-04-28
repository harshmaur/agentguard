package main

import (
	"strings"
	"testing"
)

func TestResolveOutput(t *testing.T) {
	tests := []struct {
		name           string
		flags          scanFlags
		// We cannot meaningfully assert browser-open or summary-dest from a
		// test environment without a TTY. Instead we assert on:
		// - format
		// - reportToStdout (the easy-to-verify slug of the routing decision)
		// - reportPath emptiness ("non-empty" when expecting a temp file)
		wantFormat         string
		wantReportToStdout bool
		wantReportPath     string // "" = don't care, "tmp" = expects /tmp/agentguard-...
		wantErr            bool
	}{
		{
			name:               "default html: temp file path",
			flags:              scanFlags{format: "html", openMode: "auto"},
			wantFormat:         "html",
			wantReportToStdout: false,
			wantReportPath:     "tmp",
		},
		{
			name:               "html with explicit -o path",
			flags:              scanFlags{format: "html", output: "/tmp/x.html", openMode: "auto"},
			wantFormat:         "html",
			wantReportToStdout: false,
			wantReportPath:     "/tmp/x.html",
		},
		{
			name:               "html with -o - forces stdout",
			flags:              scanFlags{format: "html", output: "-", openMode: "auto"},
			wantFormat:         "html",
			wantReportToStdout: true,
		},
		{
			name:               "sarif default goes to stdout",
			flags:              scanFlags{format: "sarif", openMode: "auto"},
			wantFormat:         "sarif",
			wantReportToStdout: true,
		},
		{
			name:               "sarif with -o file",
			flags:              scanFlags{format: "sarif", output: "/tmp/r.sarif", openMode: "auto"},
			wantFormat:         "sarif",
			wantReportToStdout: false,
			wantReportPath:     "/tmp/r.sarif",
		},
		{
			name:               "json default goes to stdout",
			flags:              scanFlags{format: "json", openMode: "auto"},
			wantFormat:         "json",
			wantReportToStdout: true,
		},
		{
			name:    "unknown format fails",
			flags:   scanFlags{format: "yaml", openMode: "auto"},
			wantErr: true,
		},
		{
			name:    "invalid open mode fails",
			flags:   scanFlags{format: "html", openMode: "maybe"},
			wantErr: true,
		},
		{
			name:               "uppercase format normalized",
			flags:              scanFlags{format: "HTML", openMode: "auto"},
			wantFormat:         "html",
			wantReportToStdout: false,
			wantReportPath:     "tmp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveOutput(tt.flags)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got plan=%+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.format != tt.wantFormat {
				t.Errorf("format = %q, want %q", got.format, tt.wantFormat)
			}
			if got.reportToStdout != tt.wantReportToStdout {
				t.Errorf("reportToStdout = %v, want %v", got.reportToStdout, tt.wantReportToStdout)
			}
			switch tt.wantReportPath {
			case "":
				// don't care
			case "tmp":
				if !strings.HasPrefix(got.reportPath, "/tmp/agentguard-") &&
					!strings.Contains(got.reportPath, "agentguard-") {
					t.Errorf("reportPath = %q, expected temp path containing 'agentguard-'", got.reportPath)
				}
			default:
				if got.reportPath != tt.wantReportPath {
					t.Errorf("reportPath = %q, want %q", got.reportPath, tt.wantReportPath)
				}
			}
		})
	}
}

func TestResolveOutput_NeverDisablesBrowser(t *testing.T) {
	// --open never must override even when stdout-TTY would otherwise open.
	plan, err := resolveOutput(scanFlags{format: "html", openMode: "never"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if plan.openBrowser {
		t.Errorf("--open never should disable openBrowser, got true")
	}
}
