package output

// schema.go embeds the canonical JSON Schema for the Report wire shape
// so the audr binary can print it offline (`audr scan --print-schema`)
// without needing network access to audr.dev/schema/report.v1.json. The
// embedded bytes are the source of truth for the hosted URL — the
// release pipeline copies the same file to the audr-web site's
// public/schema/ directory so the URL the binary advertises always
// resolves to the same document.
//
// The embedded schema is validated at startup via Schema() returning
// well-formed JSON; the json_baseline_test.go schema-additivity test
// also asserts that every required Report field referenced here exists
// on JSONReport so additions to the wire shape cannot silently leave
// the schema stale.

import _ "embed"

//go:embed schema/report.v1.json
var embeddedSchema []byte

// Schema returns the canonical JSON Schema bytes embedded in the binary.
// The returned slice is read-only; callers must not mutate it. The
// schema URL `https://audr.dev/schema/report.v1.json` serves the same
// document, so a network-enabled consumer can validate against either
// the local copy or the hosted one — they are byte-identical by CI gate.
func Schema() []byte {
	return embeddedSchema
}
