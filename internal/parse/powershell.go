package parse

import (
	"regexp"
	"strings"
)

// parsePowerShellProfile parses a PowerShell profile script and
// returns a flat picture of env-var assignments, dot-sourced files,
// module imports, aliases, and pipelines. This is NOT a full
// PowerShell language parser — it does not handle here-strings,
// function bodies, parameter blocks, splat expansion, or runtime
// command substitution. The goal is the same shape as parseShellRC:
// give rules enough structure to fire confidently on the common
// patterns while staying small enough to fuzz.
//
// Tolerated input shapes (each example is one line):
//
//	$env:PATH = "C:\Users\X\bin;$env:PATH"   → EnvVars["PATH"]
//	$env:API_KEY = 'sk-real'                 → EnvVars["API_KEY"]
//	$global:foo = "bar"                      → Vars["foo"] (scope prefix stripped)
//	$bar = 42                                → Vars["bar"]
//	. C:\Tools\my-profile.ps1                → Sources
//	Import-Module posh-git                   → Modules
//	Set-Alias ll Get-ChildItem               → Aliases["ll"] = "Get-ChildItem"
//	New-Alias -Name g -Value git             → Aliases["g"] = "git"
//	iwr https://x.test/setup.ps1 | iex       → Pipelines (stage 1, stage 2)
//
// Things we deliberately skip:
//   - `function Foo { ... }` bodies (no AST; rules use Raw)
//   - Here-strings `@'...'@`, `@"..."@` (require multi-line state)
//   - param() blocks (no signature analysis in v1.1)
//   - Backtick line continuations are joined naively before parsing
//
// Backtick continuation handling: a trailing `` ` `` (one backtick
// followed by EOL) merges the next physical line into the current
// logical line. Mirrors PowerShell's actual behavior closely enough
// for the simple cases real profiles use.
func parsePowerShellProfile(raw []byte) *PowerShellProfile {
	src := string(raw)
	rawLines := strings.Split(src, "\n")
	logicalLines, lineMap := joinBacktickContinuations(rawLines)

	p := &PowerShellProfile{
		EnvVars:     map[string]string{},
		EnvVarLines: map[string]int{},
		Vars:        map[string]string{},
		VarLines:    map[string]int{},
		Aliases:     map[string]string{},
		AliasLines:  map[string]int{},
		Lines:       rawLines,
	}

	for idx, line := range logicalLines {
		stripped := strings.TrimSpace(line)
		if stripped == "" {
			continue
		}
		// Strip a leading line comment. We do NOT attempt to
		// understand `<# block #>` here — block comments are
		// out-of-scope; rules that care can walk Raw.
		if strings.HasPrefix(stripped, "#") {
			continue
		}
		// Trim trailing `# comment` if it's clearly outside quoted
		// strings. We do a conservative split-on-` #` (space-hash)
		// and only trim when the `#` is not inside paired quotes.
		stripped = stripTrailingComment(stripped)
		if stripped == "" {
			continue
		}
		lineNo := lineMap[idx]

		switch {
		case strings.HasPrefix(stripped, ". "):
			// Dot-source: `. ./other.ps1` (Unix-style) or
			// `. C:\path\to\other.ps1` (Windows-style).
			fields := splitPSFields(stripped)
			if len(fields) >= 2 {
				p.Sources = append(p.Sources, unquote(fields[1]))
			}
		case psImportModuleRE.MatchString(stripped):
			// Import-Module foo / Import-Module -Name foo /
			// Add-PSSnapin foo / using module foo
			m := extractModuleTarget(stripped)
			if m != "" {
				p.Modules = append(p.Modules, m)
			}
		case psAliasRE.MatchString(stripped):
			// Set-Alias / New-Alias — both support either positional
			// `<name> <value>` or named `-Name <name> -Value <value>`.
			name, val := extractAliasNameValue(stripped)
			if name != "" {
				p.Aliases[name] = val
				p.AliasLines[name] = lineNo
			}
		case psEnvAssignRE.MatchString(stripped):
			// $env:KEY = "value"
			k, v := extractEnvAssign(stripped)
			if k != "" {
				p.EnvVars[k] = v
				p.EnvVarLines[k] = lineNo
			}
		case psVarAssignRE.MatchString(stripped):
			// $foo = "value" (or $global:foo, $script:foo etc — scope stripped)
			k, v := extractVarAssign(stripped)
			if k != "" {
				p.Vars[k] = v
				p.VarLines[k] = lineNo
			}
		}

		// Pipeline detection runs independently of the above; a
		// pipeline can sit inside an assignment RHS or be its own
		// statement. We split on `|` that aren't inside quotes.
		stages := splitPipelineStages(stripped)
		if len(stages) > 1 {
			p.Pipelines = append(p.Pipelines, PowerShellPipeline{
				Stages: stages,
				Line:   lineNo,
			})
		}
	}
	return p
}

// joinBacktickContinuations folds trailing-backtick line continuations
// into single logical lines. Returns the joined lines and a map from
// the new logical index back to the original 1-based line number
// where each statement starts (so finding emissions point at the
// right line for the user).
func joinBacktickContinuations(rawLines []string) ([]string, map[int]int) {
	var out []string
	lineMap := map[int]int{}
	i := 0
	for i < len(rawLines) {
		startLine := i + 1
		cur := rawLines[i]
		// A trailing backtick (with possible whitespace after) marks
		// continuation. Detection is conservative: we look for `` ` ``
		// as the last non-whitespace token. We don't try to detect
		// backticks inside strings, which would require quote-state
		// tracking — false positives here are limited to "joined two
		// lines that PowerShell wouldn't have joined", which still
		// parses fine: the second line was already on its own and
		// will look like an empty / mismatched statement, which we
		// already tolerate.
		for endsWithBacktick(cur) && i+1 < len(rawLines) {
			cur = strings.TrimRight(cur, " \t")
			cur = strings.TrimSuffix(cur, "`")
			cur += " " + strings.TrimSpace(rawLines[i+1])
			i++
		}
		lineMap[len(out)] = startLine
		out = append(out, cur)
		i++
	}
	return out, lineMap
}

func endsWithBacktick(s string) bool {
	s = strings.TrimRight(s, " \t")
	return strings.HasSuffix(s, "`")
}

// stripTrailingComment trims `# comment` from the tail of a line
// when the `#` is not inside paired quotes. Conservative — when in
// doubt, leaves the line intact so the assignment-extractors can
// still match.
func stripTrailingComment(s string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				// Require a preceding space or start-of-line so we
				// don't trim things like `#requires` directives or
				// hash-prefixed identifiers (rare but legal).
				if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' {
					return strings.TrimSpace(s[:i])
				}
			}
		}
	}
	return s
}

var (
	psEnvAssignRE     = regexp.MustCompile(`^\$env:[A-Za-z_][A-Za-z0-9_]*\s*=`)
	psVarAssignRE     = regexp.MustCompile(`^\$(?:[A-Za-z_]+:)?[A-Za-z_][A-Za-z0-9_]*\s*=`)
	psImportModuleRE  = regexp.MustCompile(`(?i)^(?:Import-Module|Add-PSSnapin|using\s+module)\b`)
	psAliasRE         = regexp.MustCompile(`(?i)^(?:Set-Alias|New-Alias)\b`)
	psScopePrefixRE   = regexp.MustCompile(`^(?:global|script|local|private|using):`)
)

// extractEnvAssign pulls KEY and VALUE from `$env:KEY = "value"`.
// Returns empty key when the line doesn't match the expected shape.
func extractEnvAssign(s string) (string, string) {
	// $env:KEY = ...
	rest := strings.TrimPrefix(s, "$env:")
	eq := strings.Index(rest, "=")
	if eq < 0 {
		return "", ""
	}
	key := strings.TrimSpace(rest[:eq])
	val := strings.TrimSpace(rest[eq+1:])
	return key, unquote(val)
}

// extractVarAssign pulls KEY and VALUE from `$var = ...` or
// `$<scope>:<var> = ...`. The scope prefix (global/script/local) is
// stripped — rules generally don't care about scope.
func extractVarAssign(s string) (string, string) {
	rest := strings.TrimPrefix(s, "$")
	rest = psScopePrefixRE.ReplaceAllString(rest, "")
	eq := strings.Index(rest, "=")
	if eq < 0 {
		return "", ""
	}
	key := strings.TrimSpace(rest[:eq])
	val := strings.TrimSpace(rest[eq+1:])
	return key, unquote(val)
}

// extractModuleTarget pulls the module name out of an Import-Module /
// Add-PSSnapin / using-module statement. Handles both positional
// `Import-Module Foo` and `Import-Module -Name Foo`. The `using
// module Foo` form has TWO leading tokens (`using` + `module`); we
// skip both before looking for the target.
func extractModuleTarget(s string) string {
	fields := splitPSFields(s)
	startIdx := 1
	// `using module ...` — skip the second token as well.
	if len(fields) >= 1 && strings.EqualFold(fields[0], "using") {
		startIdx = 2
	}
	// fields[startIdx-1] is the cmdlet; the module is the first
	// non-flag field after.
	for i := startIdx; i < len(fields); i++ {
		f := fields[i]
		if strings.HasPrefix(f, "-") {
			// Named flag — skip it, and skip its value (next field)
			// unless it's the flag-end indicator.
			if i+1 < len(fields) && !strings.HasPrefix(fields[i+1], "-") {
				if strings.EqualFold(f, "-Name") {
					return unquote(fields[i+1])
				}
				i++ // skip the flag's value
			}
			continue
		}
		return unquote(f)
	}
	return ""
}

// extractAliasNameValue pulls (name, value) from a Set-Alias /
// New-Alias statement. Both positional and named forms are
// supported.
func extractAliasNameValue(s string) (string, string) {
	fields := splitPSFields(s)
	var positional []string
	var named = map[string]string{}
	for i := 1; i < len(fields); i++ {
		f := fields[i]
		if strings.HasPrefix(f, "-") && i+1 < len(fields) && !strings.HasPrefix(fields[i+1], "-") {
			named[strings.ToLower(f)] = unquote(fields[i+1])
			i++
			continue
		}
		if !strings.HasPrefix(f, "-") {
			positional = append(positional, unquote(f))
		}
	}
	name := named["-name"]
	val := named["-value"]
	if name == "" && len(positional) >= 1 {
		name = positional[0]
	}
	if val == "" && len(positional) >= 2 {
		val = positional[1]
	}
	return name, val
}

// splitPSFields splits a PowerShell line into whitespace-separated
// fields, preserving quoted segments as single fields. Single and
// double quotes are honored; PowerShell-style escape via backtick is
// NOT honored (rare in profile scripts).
func splitPSFields(s string) []string {
	var out []string
	var cur strings.Builder
	inSingle, inDouble := false, false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			cur.WriteByte(c)
		case c == '"' && !inSingle:
			inDouble = !inDouble
			cur.WriteByte(c)
		case (c == ' ' || c == '\t') && !inSingle && !inDouble:
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// splitPipelineStages splits a line on `|` that aren't inside paired
// quotes. Returns the original stages, trimmed. A non-pipeline line
// returns a single-element slice (the whole stripped line).
func splitPipelineStages(s string) []string {
	var stages []string
	var cur strings.Builder
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			cur.WriteByte(c)
		case c == '"' && !inSingle:
			inDouble = !inDouble
			cur.WriteByte(c)
		case c == '|' && !inSingle && !inDouble:
			// `||` is PowerShell's logical-or (added in 7.0); we
			// don't try to split on that. Cheap check: is the next
			// byte also `|`?
			if i+1 < len(s) && s[i+1] == '|' {
				cur.WriteByte(c)
				cur.WriteByte(c)
				i++
				continue
			}
			stages = append(stages, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		stages = append(stages, strings.TrimSpace(cur.String()))
	}
	return stages
}

// unquote strips matching surrounding single or double quotes.
// Embedded escapes are left as-is — rule authors see the raw inner
// text, which is what they want for substring matching against
// secrets / URLs.
func unquote(s string) string {
	if len(s) < 2 {
		return s
	}
	first := s[0]
	last := s[len(s)-1]
	if (first == '\'' && last == '\'') || (first == '"' && last == '"') {
		return s[1 : len(s)-1]
	}
	return s
}
