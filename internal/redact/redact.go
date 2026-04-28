// Package redact replaces credential-shaped strings with <redacted:type> markers.
//
// Redaction is applied at finding-construction time (see internal/finding) so
// raw secrets never travel through formatters, logs, panics, or pipe-to-head.
// Defense in depth: a missed pattern here is the worst-case launch story.
package redact

import (
	"regexp"
	"strings"
)

// pattern represents a single credential pattern we know how to recognize.
type pattern struct {
	name string
	re   *regexp.Regexp
}

// patterns is the ordered list of credential patterns.
// Order matters: more-specific patterns (provider-prefixed) come before
// generic high-entropy patterns so we report the strongest type label.
var patterns = []pattern{
	// AWS access key IDs.
	{"aws-access-key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	// AWS secret access keys (40 chars of base64-ish).
	{"aws-secret-key", regexp.MustCompile(`(?i)aws_secret[_a-z]*[\s:=]+["']?([A-Za-z0-9/+=]{40})["']?`)},
	// GitHub tokens (classic, fine-grained, server-to-server).
	{"github-token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`)},
	// Stripe keys (live/test, secret/restricted).
	{"stripe-key", regexp.MustCompile(`(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}`)},
	// Anthropic API keys (e.g. sk-ant-api03-...).
	{"anthropic-key", regexp.MustCompile(`sk-ant-[a-z][a-z0-9]{2,}-[A-Za-z0-9_\-]{32,}`)},
	// OpenAI keys (sk-proj-, sk-svcacct-, plain sk-).
	{"openai-key", regexp.MustCompile(`sk-(?:proj|svcacct|None|admin)?-?[A-Za-z0-9_\-]{20,}`)},
	// Slack tokens.
	{"slack-token", regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`)},
	// Google API keys.
	{"google-api-key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
	// GitLab personal access token (v0.1.4).
	{"gitlab-token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-\.]{20,}`)},
	// GitLab project trigger token (v0.1.4).
	{"gitlab-project-token", regexp.MustCompile(`\bglptt-[A-Za-z0-9_\-\.]{20,}`)},
	// Hugging Face API token (v0.1.4).
	{"huggingface-token", regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}`)},
	// npm modern auth token (v0.1.4).
	{"npm-token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36,}`)},
	// JSON Web Tokens (three base64 segments separated by dots).
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)},
	// PEM private keys (single-line marker; multi-line handled by line-aware redactor).
	{"private-key-pem", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`)},
	// URLs with inline basic-auth credentials. Captures user:pass section.
	{"url-credentials", regexp.MustCompile(`(?i)(https?|postgres(?:ql)?|mysql|mongodb|redis|amqp|ftp|ssh)://[^/\s:@]+:[^/\s@]+@`)},
	// env-var assignments where the key NAME suggests a secret (and the value is non-trivial).
	{"secret-env-var", regexp.MustCompile(`(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|bearer|password|passwd|api[_-]?secret|client[_-]?secret|priv[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9_\-+/=.]{12,})["']?`)},
}

// String returns s with credential-shaped substrings replaced by <redacted:type>.
//
// This is intentionally conservative: false positives (over-redacting) are
// acceptable. False negatives (leaking a real secret) are not.
func String(s string) string {
	if s == "" {
		return s
	}
	for _, p := range patterns {
		s = p.re.ReplaceAllStringFunc(s, func(_ string) string {
			return "<redacted:" + p.name + ">"
		})
	}
	// Catch-all for high-entropy hex blobs that look like raw secrets and
	// weren't matched by a provider-specific pattern. Only triggers on long
	// runs (32+ chars), all hex, that are word-boundary isolated.
	s = highEntropyHex.ReplaceAllString(s, "<redacted:high-entropy-hex>")
	return s
}

var highEntropyHex = regexp.MustCompile(`\b[A-Fa-f0-9]{32,}\b`)

// Lines redacts each line independently. Useful for redacting log/file
// contents while preserving line numbers in the redacted output.
func Lines(s string) string {
	if !strings.ContainsAny(s, "\n") {
		return String(s)
	}
	parts := strings.Split(s, "\n")
	for i, line := range parts {
		parts[i] = String(line)
	}
	return strings.Join(parts, "\n")
}

// Patterns returns the names of all configured credential patterns.
// Used by self-audit and tests to verify pattern coverage.
func Patterns() []string {
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, p.name)
	}
	return out
}
