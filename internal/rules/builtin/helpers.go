package builtin

import (
	"regexp"
	"strings"
)

// --- Credential matching --------------------------------------------------

// apiKeyValuePatterns recognize known credential VALUE shapes. Matched
// against env-var values, header values, and shell-rc export values.
//
// Order matters only for description accuracy (we use the first match's
// label); functionally any single match flips the credential bit.
var apiKeyValuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                             // AWS access key
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`),                   // GitHub token (classic, fine-grained, server-to-server)
	regexp.MustCompile(`(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}`),     // Stripe live/test, secret/restricted
	regexp.MustCompile(`sk-ant-[a-z][a-z0-9]{2,}-[A-Za-z0-9_\-]{32,}`), // Anthropic
	regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),                       // Google API
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),                 // Slack
	// v0.1.4: extended set after a real Mac scan caught only 1 of 3
	// production tokens in .zprofile.
	regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-\.]{20,}`),  // GitLab personal access token
	regexp.MustCompile(`\bglptt-[A-Za-z0-9_\-\.]{20,}`),  // GitLab project trigger token
	regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}`),          // Hugging Face
	regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36,}`),         // npm modern token
}

// credentialNameSuffix recognizes env var names that scream "I am a secret"
// even when the VALUE shape isn't a known credential prefix. The Mac scan
// surfaced FONTAWESOME_REGISTRY_AUTHTOKEN=<UUID> — the UUID alone is not a
// recognizable credential, but the env name's _AUTHTOKEN suffix makes the
// risk obvious. Trades up some false positives for catching the real prod
// secrets that don't fit a vendor prefix.
var credentialNameSuffix = regexp.MustCompile(
	`(?i)(?:^|_)(?:token|key|secret|password|passwd|auth|credential|credentials|pat|psk|apikey|authtoken)$`,
)

// valueLooksLikeSecret returns true for non-trivial values that could
// plausibly be a credential. Filters out things like "true", "info", short
// paths, etc. Requires length >= 16 AND at least 2 character classes
// (digits + letters, or mixed case). UUIDs satisfy this trivially.
func valueLooksLikeSecret(v string) bool {
	if len(v) < 16 {
		return false
	}
	hasDigit, hasLower, hasUpper := false, false, false
	for _, c := range v {
		switch {
		case '0' <= c && c <= '9':
			hasDigit = true
		case 'a' <= c && c <= 'z':
			hasLower = true
		case 'A' <= c && c <= 'Z':
			hasUpper = true
		}
	}
	classes := 0
	for _, b := range []bool{hasDigit, hasLower, hasUpper} {
		if b {
			classes++
		}
	}
	return classes >= 2
}

// matchesCredential checks both the value (against known credential prefix
// patterns) and the name (for credential-suggesting suffixes paired with a
// non-trivial value). Used by the MCP, Codex, Windsurf, and shellrc rules.
func matchesCredential(name, value string) bool {
	for _, pat := range apiKeyValuePatterns {
		if pat.MatchString(value) {
			return true
		}
	}
	if name != "" && credentialNameSuffix.MatchString(name) && valueLooksLikeSecret(value) {
		return true
	}
	return false
}

// --- Slice helpers --------------------------------------------------------

func containsAny(haystack []string, needles ...string) bool {
	for _, h := range haystack {
		for _, n := range needles {
			if h == n {
				return true
			}
		}
	}
	return false
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

// --- Source-line helpers --------------------------------------------------

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// findKeyLineRaw returns the 1-indexed line where `"key"` first appears in
// JSON source. Used to give findings a useful line number for ClaudeSettings
// and other JSON-shaped formats. Returns 0 if not found.
func findKeyLineRaw(raw []byte, key string) int {
	needle := `"` + key + `"`
	idx := strings.Index(string(raw), needle)
	if idx < 0 {
		return 0
	}
	return strings.Count(string(raw[:idx]), "\n") + 1
}

// findLineCodex returns the 1-indexed line where marker first appears in
// the TOML source. Used for Codex rules.
func findLineCodex(raw []byte, marker string) int {
	idx := strings.Index(string(raw), marker)
	if idx < 0 {
		return 0
	}
	return strings.Count(string(raw[:idx]), "\n") + 1
}

func prettyURL(u string) string {
	if u == "" {
		return "the upstream service"
	}
	return u
}

// --- Shared danger lists --------------------------------------------------

// dangerousBashVerbs are commands that should never be allowlisted with
// arbitrary args (`<verb>:*` in Claude or `<verb>` in Cursor). Each maps
// to a one-line reason for the finding's description. Consumed by both
// claude-bash-allowlist-too-broad and cursor-allowlist-too-broad — the
// risk shape is identical, the harnesses just spell allowlist entries
// differently.
var dangerousBashVerbs = map[string]string{
	"curl":    "network egress (any HTTP request to any host)",
	"wget":    "network egress (any HTTP request to any host)",
	"nc":      "network egress / shell tunneling",
	"ncat":    "network egress / shell tunneling",
	"scp":     "file exfil over SSH",
	"sftp":    "file exfil over SFTP",
	"rsync":   "bulk file copy (anywhere on disk)",
	"aws":     "AWS CLI (s3 cp, sts assume-role, ...)",
	"gh":      "GitHub CLI (gist create, repo create, ...)",
	"glab":    "GitLab CLI",
	"bash":    "arbitrary shell command",
	"sh":      "arbitrary shell command",
	"zsh":     "arbitrary shell command",
	"fish":    "arbitrary shell command",
	"eval":    "arbitrary shell evaluation",
	"exec":    "process replacement",
	"sudo":    "privilege escalation",
	"doas":    "privilege escalation",
	"su":      "user switching",
	"docker":  "container ops (docker run --privileged, mount /, ...)",
	"kubectl": "Kubernetes ops (apply, exec into any pod)",
}
