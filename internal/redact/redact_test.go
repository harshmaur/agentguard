package redact

import (
	"strings"
	"testing"
)

func TestString_RedactsKnownSecrets(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		mustNot string // substring that must NOT appear in output
		mustHave string // marker that MUST appear in output
	}{
		{"aws-access-key", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE", "<redacted:aws-access-key>"},
		{"github-token-classic", "GH_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz", "ghp_1234567890abcdefghijklmnopqrstuvwxyz", "<redacted:github-token>"},
		{"github-token-fine-grained", "ghp_aBcD1234ZyXwVuTsRqPoNmLkJiHgFeDcBaZyXwV", "ghp_aBcD1234", "<redacted:github-token>"},
		{"stripe-live", "STRIPE=sk_live_abcdefghijklmnopqrstuvwx", "sk_live_abcdefghijklmnopqrstuvwx", "<redacted:stripe-key>"},
		{"anthropic-key", "ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890", "sk-ant-api03-abcd", "<redacted:anthropic-key>"},
		{"slack-bot", "SLACK_TOKEN=xoxb-1234567890-abcdefghijklm", "xoxb-1234567890", "<redacted:slack-token>"},
		{"google-api", "key=AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456", "AIzaSyABCDEFGHIJ", "<redacted:google-api-key>"},
		{"jwt", "JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummysig123456", "eyJhbGciOiJIUzI1NiI", "<redacted:jwt>"},
		{"pem-private-key-rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...", "-----BEGIN RSA PRIVATE KEY-----", "<redacted:private-key-pem>"},
		{"pem-private-key-ed", "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "<redacted:private-key-pem>"},
		{"db-url-with-creds", "postgres://admin:hunter2@db.example.com:5432/prod", "admin:hunter2@", "<redacted:url-credentials>"},
		{"https-url-creds", "https://user:secretpass@api.example.com/v1", "user:secretpass@", "<redacted:url-credentials>"},
		{"secret-env-var", `password = "supersecretvalue123"`, "supersecretvalue123", "<redacted:secret-env-var>"},
		{"api-key-yaml", `api_key: "abc123def456ghi789jkl"`, "abc123def456ghi789jkl", "<redacted:secret-env-var>"},
		{"high-entropy-hex", "deadbeef0123456789abcdef0123456789abcdef0123456789", "deadbeef0123456789abcdef", "<redacted:high-entropy-hex>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := String(tt.input)
			if strings.Contains(got, tt.mustNot) {
				t.Errorf("redact leaked %q in output: %q", tt.mustNot, got)
			}
			if !strings.Contains(got, tt.mustHave) {
				t.Errorf("redact missing marker %q in output: %q", tt.mustHave, got)
			}
		})
	}
}

func TestString_PreservesNonSecrets(t *testing.T) {
	cases := []string{
		"hello world",
		"this is a normal message",
		"GET /api/users HTTP/1.1",
		"package main",
		"agentguard scan --jobs 4",
		"version: 1.0.0",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if got := String(c); got != c {
				t.Errorf("String(%q) = %q, expected unchanged", c, got)
			}
		})
	}
}

func TestLines_PerLineRedaction(t *testing.T) {
	input := "line one is normal\nGH_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz\nline three normal"
	got := Lines(input)
	if strings.Contains(got, "ghp_1234567890") {
		t.Errorf("Lines leaked secret: %q", got)
	}
	if !strings.Contains(got, "<redacted:github-token>") {
		t.Errorf("Lines missing redaction marker: %q", got)
	}
	if !strings.Contains(got, "line one is normal") || !strings.Contains(got, "line three normal") {
		t.Errorf("Lines damaged non-secret lines: %q", got)
	}
}

// TestString_PropertyNoSecretLeaks is a property-style test that scans many
// generated fixtures containing planted secrets and asserts NONE appear in
// any redacted output. This is the critical regression test referenced in the
// design doc.
func TestString_PropertyNoSecretLeaks(t *testing.T) {
	// Each fixture: a planted secret embedded in surrounding text.
	plantedSecrets := []struct {
		secret string
		kind   string
	}{
		{"AKIAIOSFODNN7EXAMPLE", "aws-access-key"},
		{"AKIA0123456789ABCDEF", "aws-access-key"},
		{"ghp_1234567890abcdefghijklmnopqrstuvwxyz", "github-token"},
		{"ghs_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "github-token"},
		{"sk_live_abcdefghijklmnopqrstuvwxyz1234", "stripe-key"},
		{"sk_test_abcdefghijklmnopqrstuvwxyz1234", "stripe-key"},
		{"sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890", "anthropic-key"},
		{"sk-proj-abcdefghijklmnopqrstuvwxyz1234567890", "openai-key"},
		{"xoxb-1234567890123-abcdefghijklm", "slack-token"},
		{"xoxp-1234567890-abcdefghij", "slack-token"},
		{"AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456", "google-api-key"},
		{"deadbeefcafebabe1234567890abcdefdeadbeefcafe", "high-entropy-hex"},
	}

	contexts := []string{
		"%s",
		"export TOKEN=%s",
		"foo: \"%s\"",
		"foo='%s'",
		"# comment with %s in it",
		"  args:\n    - %s\n",
		"const Token = %q",
		"<token>%s</token>",
		"Authorization: Bearer %s",
		"PROD_KEY=%s extra",
		"# %s",
		"value = %s",
	}

	count := 0
	for _, ps := range plantedSecrets {
		for _, ctx := range contexts {
			input := strings.ReplaceAll(ctx, "%s", ps.secret)
			input = strings.ReplaceAll(input, "%q", `"`+ps.secret+`"`)
			out := String(input)
			if strings.Contains(out, ps.secret) {
				t.Errorf("LEAK: secret %q (kind=%s) appeared in redacted output: %q\n   input: %q",
					ps.secret, ps.kind, out, input)
			}
			count++
		}
	}
	t.Logf("verified %d planted-secret fixtures, no leaks", count)
}

func TestPatterns_NotEmpty(t *testing.T) {
	if len(Patterns()) == 0 {
		t.Fatal("Patterns() returned empty list")
	}
}
