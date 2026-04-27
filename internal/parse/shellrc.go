package parse

import (
	"regexp"
	"strings"
)

// parseShellRC walks a shell rc file looking for `export KEY=VALUE` or bare
// `KEY=VALUE` assignments, and `source ...` / `. ...` invocations. The parser
// tolerates malformed lines by skipping them.
//
// This is not a full shell parser. We handle the common cases that matter for
// rules: env-var assignments with literal values, and `source` of other files.
// Heredocs, command substitution, parameter expansion, and `function` blocks
// are out of scope — rules that need those should run on the raw text.
func parseShellRC(raw []byte) *ShellRC {
	rc := &ShellRC{
		EnvVars:     map[string]string{},
		EnvVarLines: map[string]int{},
	}
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		stripped := strings.TrimSpace(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		// `source FOO` or `. FOO`
		if strings.HasPrefix(stripped, "source ") || strings.HasPrefix(stripped, ". ") {
			fields := strings.Fields(stripped)
			if len(fields) >= 2 {
				rc.Sources = append(rc.Sources, fields[1])
			}
			continue
		}
		// `export KEY=VALUE` or `KEY=VALUE`
		assign := stripped
		if strings.HasPrefix(assign, "export ") {
			assign = strings.TrimPrefix(assign, "export ")
		}
		if !envAssignRE.MatchString(assign) {
			continue
		}
		idx := strings.Index(assign, "=")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(assign[:idx])
		val := strings.TrimSpace(assign[idx+1:])
		val = strings.Trim(val, `"'`)
		// Strip trailing comments.
		if hashIdx := strings.Index(val, " #"); hashIdx > 0 {
			val = strings.TrimSpace(val[:hashIdx])
		}
		rc.EnvVars[key] = val
		rc.EnvVarLines[key] = i + 1
	}
	return rc
}

var envAssignRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// parseEnvFile parses a .env-style file. Same dialect as docker/composer:
// KEY=value, optional quotes, comments start with #.
func parseEnvFile(raw []byte) *EnvFile {
	ef := &EnvFile{
		Vars:  map[string]string{},
		Lines: map[string]int{},
	}
	for i, line := range strings.Split(string(raw), "\n") {
		stripped := strings.TrimSpace(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		if !envAssignRE.MatchString(stripped) {
			continue
		}
		idx := strings.Index(stripped, "=")
		key := strings.TrimSpace(stripped[:idx])
		val := strings.TrimSpace(stripped[idx+1:])
		val = strings.Trim(val, `"'`)
		ef.Vars[key] = val
		ef.Lines[key] = i + 1
	}
	return ef
}
