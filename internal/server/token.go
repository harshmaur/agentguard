// Package server implements the audr daemon's localhost HTTP surface:
// the dashboard HTML/JS/CSS, the /api/findings + /api/events + /api/
// remediation endpoints, and the token + Host-header auth that protects
// them.
//
// Design notes from /plan-eng-review (revision 5):
//
//   - Plain HTTP on 127.0.0.1 — no TLS. The token is the auth, not TLS;
//     localhost loopback has no in-transit threat to encrypt against.
//   - 256-bit token in URL, regenerated each daemon start, constant-time
//     compared on every request.
//   - Strict Host-header validation rejects any request whose Host:
//     header isn't exactly "127.0.0.1:<port>" or "localhost:<port>".
//     Gold-standard DNS rebinding mitigation (D16).
//   - Listener binds 127.0.0.1 only. The daemon hard-fails at startup
//     if anything tries to bind 0.0.0.0.
package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// tokenBytes is the cryptographic strength of the per-daemon auth
// token: 256 bits. Anything less risks a 64-bit guess on a leaked
// daemon log; anything more is wasted.
const tokenBytes = 32

// NewToken returns a 256-bit cryptographically random token,
// base64url-encoded without padding. The result is URL-safe — no '+',
// '/', or '=' characters that would need escaping in a query string.
//
// The token is the daemon's only auth credential. Once generated,
// callers MUST keep it confidential (mode 0600 on the state file,
// constant-time comparison on every request, never log it).
func NewToken() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("token: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
