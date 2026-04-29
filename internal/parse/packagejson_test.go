package parse

import "testing"

func TestDetectFormatPackageJSON(t *testing.T) {
	if got := DetectFormat("/repo/package.json"); got != FormatPackageJSON {
		t.Fatalf("DetectFormat(package.json) = %q, want %q", got, FormatPackageJSON)
	}
}

func TestParsePackageJSON(t *testing.T) {
	doc := Parse("package.json", []byte(`{"name":"openclaw","version":"2026.3.21","dependencies":{"x":"1.0.0"},"devDependencies":{"openclaw":"2026.3.1"}}`))
	if doc.ParseError != nil {
		t.Fatalf("ParseError = %v", doc.ParseError)
	}
	if doc.PackageJSON == nil || doc.PackageJSON.Name != "openclaw" || doc.PackageJSON.DevDependencies["openclaw"] != "2026.3.1" {
		t.Fatalf("PackageJSON not parsed: %#v", doc.PackageJSON)
	}
}
