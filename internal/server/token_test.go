package server

import (
	"encoding/base64"
	"testing"
)

func TestNewTokenReturnsURLSafeBase64(t *testing.T) {
	tok, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	// Base64 raw URL encoding: no padding, only A-Z a-z 0-9 - _ allowed.
	for _, r := range tok {
		ok := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_'
		if !ok {
			t.Fatalf("token contains non-URL-safe char %q: %q", r, tok)
		}
	}
	// 32 random bytes -> 43 chars in base64 (4 * ceil(32/3) - padding).
	if len(tok) != 43 {
		t.Errorf("token length = %d, want 43 (32 bytes b64-encoded)", len(tok))
	}
	// Decodes back to 32 bytes.
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("token does not decode cleanly: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("decoded length = %d, want 32", len(raw))
	}
}

func TestNewTokenReturnsDifferentValues(t *testing.T) {
	// Sanity check: not a constant. 100 calls; zero collisions expected
	// because the keyspace is 2^256.
	seen := map[string]struct{}{}
	for i := 0; i < 100; i++ {
		tok, err := NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("duplicate token within 100 calls: %q", tok)
		}
		seen[tok] = struct{}{}
	}
}
