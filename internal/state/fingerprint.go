// Package state owns audr's persistent storage: a SQLite store with the
// kind+locator finding schema (eng-review D17), a single-writer goroutine
// + WAL (D12) for safe concurrent access, schema migrations, crash
// recovery (in-progress scans get marked crashed on next start),
// retention pruning, and a pub-sub event bus that the HTTP server's SSE
// stream subscribes to.
//
// Phase 2 ships the foundation: the schema, the writer, the read API,
// crash recovery, retention. Phase 3 (watch+poll) and Phase 4 (scanner
// orchestration) write into it; the server reads + subscribes.
package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// Fingerprint computes a finding's stable identity hash, the value
// stored as the PRIMARY KEY on findings(fingerprint). Inputs are the
// fields whose change SHOULD create a different finding row (not
// fields that change while the finding stays the same — e.g., not the
// path, because a rename keeps the finding identity intact).
//
// Hash formula:
//
//	sha256(rule_id || '|' || kind || '|' || canonicalize(locator) || '|' || normalized_match)
//
// Canonicalize means: object keys sorted, no insignificant whitespace,
// numbers in their shortest JSON form. This guarantees two equivalent
// locator JSON blobs produce the same fingerprint regardless of how
// the caller serialized them.
//
// Returns hex-encoded SHA-256 (64 chars). Errors on malformed locator
// JSON.
func Fingerprint(ruleID, kind string, locator []byte, normalizedMatch string) (string, error) {
	canon, err := canonicalizeJSON(locator)
	if err != nil {
		return "", fmt.Errorf("fingerprint: canonicalize locator: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(ruleID))
	h.Write([]byte("|"))
	h.Write([]byte(kind))
	h.Write([]byte("|"))
	h.Write(canon)
	h.Write([]byte("|"))
	h.Write([]byte(normalizedMatch))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// canonicalizeJSON re-encodes a JSON document with sorted object keys.
// Wire shape: scalar values are emitted unchanged; objects have their
// keys sorted lexicographically; arrays preserve order.
//
// We don't need a full RFC 8785 (JCS) implementation — the inputs we
// see are small (a few keys per finding locator), so round-tripping
// through encoding/json with manual key sort is correct + simple.
func canonicalizeJSON(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return []byte("null"), nil
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return canonicalEncode(v)
}

func canonicalEncode(v any) ([]byte, error) {
	switch t := v.(type) {
	case map[string]any:
		var buf bytes.Buffer
		buf.WriteByte('{')
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			child, err := canonicalEncode(t[k])
			if err != nil {
				return nil, err
			}
			buf.Write(child)
		}
		buf.WriteByte('}')
		return buf.Bytes(), nil
	case []any:
		var buf bytes.Buffer
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			child, err := canonicalEncode(e)
			if err != nil {
				return nil, err
			}
			buf.Write(child)
		}
		buf.WriteByte(']')
		return buf.Bytes(), nil
	default:
		// String, json.Number, bool, nil — encoding/json's defaults
		// are already canonical for our purposes (no extra whitespace).
		return json.Marshal(t)
	}
}

// ErrInvalidLocator wraps a json.Unmarshal-style error for callers
// that want to distinguish "this finding has bad metadata" from other
// failures.
var ErrInvalidLocator = errors.New("invalid locator JSON")
