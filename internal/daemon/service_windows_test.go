//go:build windows

package daemon

import (
	"encoding/xml"
	"os"
	"strings"
	"testing"
)

// TestComposeTaskXML_WellFormed: the composed XML must unmarshal
// back into the same struct, and the marshalled output must include
// the load-bearing element names schtasks looks for. A regression in
// the XML schema would only surface in a Windows CI runner without
// this test.
func TestComposeTaskXML_WellFormed(t *testing.T) {
	os.Setenv("USERNAME", "TestUser")
	os.Setenv("USERDOMAIN", "TESTDOMAIN")
	defer os.Unsetenv("USERNAME")
	defer os.Unsetenv("USERDOMAIN")

	b := &schtasksBackend{cfg: ServiceConfig{
		Name:        "audr-daemon",
		Description: "test desc",
		ExecPath:    `C:\Users\TestUser\AppData\Local\audr\audr.exe`,
		Args:        []string{"daemon", "run-internal"},
	}}
	out, err := b.composeTaskXML()
	if err != nil {
		t.Fatalf("composeTaskXML: %v", err)
	}

	// Re-parse to verify the XML is well-formed.
	var doc taskXML
	if err := xml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("re-parse XML: %v\n%s", err, out)
	}

	// Verify the load-bearing fields landed correctly.
	if doc.Principals.Principal.LogonType != "InteractiveToken" {
		t.Errorf("LogonType = %q, want InteractiveToken (S0 services lose desktop access)",
			doc.Principals.Principal.LogonType)
	}
	if doc.Principals.Principal.RunLevel != "LeastPrivilege" {
		t.Errorf("RunLevel = %q, want LeastPrivilege (elevation triggers UAC prompt)",
			doc.Principals.Principal.RunLevel)
	}
	if doc.Settings.DisallowStartIfOnBatteries {
		t.Errorf("DisallowStartIfOnBatteries = true; daemon must run on battery")
	}
	if doc.Settings.StopIfGoingOnBatteries {
		t.Errorf("StopIfGoingOnBatteries = true; daemon must keep running on battery")
	}
	if doc.Settings.MultipleInstancesPolicy != "IgnoreNew" {
		t.Errorf("MultipleInstancesPolicy = %q, want IgnoreNew (defense vs trigger races)",
			doc.Settings.MultipleInstancesPolicy)
	}
	if doc.Triggers.LogonTrigger.UserID != `TESTDOMAIN\TestUser` {
		t.Errorf("UserID = %q, want TESTDOMAIN\\TestUser", doc.Triggers.LogonTrigger.UserID)
	}
	if doc.Actions.Exec.Command != `C:\Users\TestUser\AppData\Local\audr\audr.exe` {
		t.Errorf("Command = %q, want full ExecPath", doc.Actions.Exec.Command)
	}
	if doc.Actions.Exec.Arguments != "daemon run-internal" {
		t.Errorf("Arguments = %q, want 'daemon run-internal'", doc.Actions.Exec.Arguments)
	}

	// XML must start with the declaration; no BOM. schtasks accepts
	// UTF-8 without BOM but a stray BOM has been the source of
	// real-world "schtasks /Create fails silently" reports.
	if !strings.HasPrefix(string(out), "<?xml") {
		t.Errorf("output must start with <?xml declaration, got: %q", string(out[:32]))
	}
	if out[0] == 0xEF && out[1] == 0xBB && out[2] == 0xBF {
		t.Errorf("output starts with UTF-8 BOM; schtasks parses BOM-less UTF-8 correctly, BOM has been a footgun")
	}
}

// TestComposeTaskXML_RejectsMissingUsername: USERNAME env var is the
// only way to get the current user without calling
// GetUserNameExW. If it's unset we refuse rather than silently
// install a task with an empty UserID that schtasks would later
// reject.
func TestComposeTaskXML_RejectsMissingUsername(t *testing.T) {
	prev := os.Getenv("USERNAME")
	os.Unsetenv("USERNAME")
	defer os.Setenv("USERNAME", prev)

	b := &schtasksBackend{cfg: ServiceConfig{
		Name:     "audr-daemon",
		ExecPath: `C:\audr.exe`,
	}}
	_, err := b.composeTaskXML()
	if err == nil {
		t.Fatal("composeTaskXML should refuse when USERNAME is unset")
	}
	if !strings.Contains(err.Error(), "USERNAME") {
		t.Errorf("err message should mention USERNAME, got %v", err)
	}
}

// TestComposeTaskXML_NoDomainStillWorks: USERDOMAIN is optional on
// machines not joined to a domain. Without it the UserID is just the
// bare username — Task Scheduler accepts that.
func TestComposeTaskXML_NoDomainStillWorks(t *testing.T) {
	os.Setenv("USERNAME", "AloneUser")
	os.Unsetenv("USERDOMAIN")
	defer os.Unsetenv("USERNAME")

	b := &schtasksBackend{cfg: ServiceConfig{
		Name:     "audr-daemon",
		ExecPath: `C:\audr.exe`,
		Args:     []string{"daemon", "run-internal"},
	}}
	out, err := b.composeTaskXML()
	if err != nil {
		t.Fatalf("composeTaskXML: %v", err)
	}
	var doc taskXML
	if err := xml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Triggers.LogonTrigger.UserID != "AloneUser" {
		t.Errorf("UserID = %q, want AloneUser (no domain prefix)",
			doc.Triggers.LogonTrigger.UserID)
	}
}

// TestParseSchtasksStatus covers the status normalization across the
// values schtasks /FO LIST emits. Each row maps to one of our
// canonical statuses.
func TestParseSchtasksStatus(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want string
	}{
		{
			name: "Running",
			out: `HostName:                              MACHINE
TaskName:                              \audr-daemon
Status:                                Running
Logon Mode:                            Interactive only
`,
			want: "running",
		},
		{
			name: "Ready",
			out:  "Status:                                Ready\n",
			want: "stopped",
		},
		{
			name: "Queued",
			out:  "Status:                                Queued\n",
			want: "stopped",
		},
		{
			name: "Disabled",
			out:  "Status:                                Disabled\n",
			want: "stopped",
		},
		{
			name: "Could Not Start",
			out:  "Status:                                Could Not Start\n",
			want: "unknown",
		},
		{
			name: "no Status line",
			out:  "HostName: x\nTaskName: y\n",
			want: "unknown",
		},
		{
			name: "Status with trailing CR (Windows line endings)",
			out:  "Status:                                Running\r\nFoo: bar\r\n",
			want: "running",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseSchtasksStatus(tc.out); got != tc.want {
				t.Errorf("parseSchtasksStatus(%q) = %q, want %q", tc.out, got, tc.want)
			}
		})
	}
}
