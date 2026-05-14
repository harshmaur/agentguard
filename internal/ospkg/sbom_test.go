package ospkg

import (
	"encoding/json"
	"testing"
)

func TestBuildSBOMShape(t *testing.T) {
	info := DistroInfo{ID: DistroDebian, Manager: ManagerDpkg}
	pkgs := []Package{
		{Manager: ManagerDpkg, Name: "openssl", Version: "3.0.7-1"},
		{Manager: ManagerDpkg, Name: "libc6", Version: "2.36-9+deb12u4"},
	}
	body, err := buildSBOM(info, pkgs)
	if err != nil {
		t.Fatal(err)
	}
	var doc sbomDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.BomFormat != "CycloneDX" || doc.SpecVersion != "1.5" {
		t.Errorf("header = %s/%s, want CycloneDX/1.5", doc.BomFormat, doc.SpecVersion)
	}
	if len(doc.Components) != 2 {
		t.Fatalf("components = %d, want 2", len(doc.Components))
	}
	if doc.Components[0].PURL != "pkg:deb/debian/openssl@3.0.7-1" {
		t.Errorf("openssl PURL = %q, want pkg:deb/debian/openssl@3.0.7-1", doc.Components[0].PURL)
	}
	// Hyphen / + / ~ chars in version are valid path-segment chars
	// per RFC 3986; url.PathEscape leaves them alone, and OSV-Scanner
	// accepts the literal form for deb versions (including epoch
	// and +deb suffixes).
	if doc.Components[1].PURL != "pkg:deb/debian/libc6@2.36-9+deb12u4" {
		t.Errorf("libc6 PURL = %q, want unencoded `+` in version", doc.Components[1].PURL)
	}
}

func TestBuildSBOMRpmAndApkPurls(t *testing.T) {
	pkgs := []Package{{Name: "openssl", Version: "3.0.7-22.el9"}}

	body, _ := buildSBOM(DistroInfo{ID: DistroRocky, Manager: ManagerRpm}, pkgs)
	var doc sbomDoc
	_ = json.Unmarshal(body, &doc)
	if doc.Components[0].PURL != "pkg:rpm/rocky/openssl@3.0.7-22.el9" {
		t.Errorf("rocky rpm PURL = %q", doc.Components[0].PURL)
	}

	pkgs = []Package{{Name: "openssl", Version: "3.1.4-r0"}}
	body, _ = buildSBOM(DistroInfo{ID: DistroAlpine, Manager: ManagerApk}, pkgs)
	_ = json.Unmarshal(body, &doc)
	if doc.Components[0].PURL != "pkg:apk/alpine/openssl@3.1.4-r0" {
		t.Errorf("alpine apk PURL = %q", doc.Components[0].PURL)
	}
}

func TestBuildSBOMRejectsEmptyPackages(t *testing.T) {
	if _, err := buildSBOM(DistroInfo{ID: DistroDebian, Manager: ManagerDpkg}, nil); err == nil {
		t.Error("expected error for empty packages")
	}
}

func TestParseOSVOutputExtractsVulnerabilities(t *testing.T) {
	// Realistic OSV-Scanner JSON shape (trimmed).
	body := []byte(`{
		"results": [{
			"source": {"path": "/tmp/sbom.json", "type": "sbom"},
			"packages": [{
				"package": {
					"name": "openssl",
					"version": "3.0.7-1",
					"ecosystem": "Debian",
					"purl": "pkg:deb/debian/openssl@3.0.7-1"
				},
				"vulnerabilities": [{
					"id": "DSA-5677-1",
					"aliases": ["CVE-2026-43581"],
					"summary": "TLS handshake memory disclosure",
					"database_specific": {"severity": "CRITICAL"},
					"affected": [{
						"ranges": [{
							"events": [
								{"introduced": "0"},
								{"fixed": "3.0.13-1"}
							]
						}]
					}]
				}]
			}]
		}]
	}`)
	got, err := parseOSVOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d vulns, want 1", len(got))
	}
	v := got[0]
	if v.Package.Name != "openssl" || v.Package.Manager != ManagerDpkg {
		t.Errorf("package = %+v, want openssl/dpkg", v.Package)
	}
	if v.AdvisoryID != "CVE-2026-43581" {
		t.Errorf("AdvisoryID = %q, want CVE prefix (chosen over DSA)", v.AdvisoryID)
	}
	if v.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", v.Severity)
	}
	if v.FixedIn != "3.0.13-1" {
		t.Errorf("FixedIn = %q, want 3.0.13-1", v.FixedIn)
	}
}

func TestParseOSVOutputEmptyInputReturnsNil(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte(""), []byte("   \n\t")} {
		got, err := parseOSVOutput(raw)
		if err != nil {
			t.Errorf("empty input err: %v", err)
		}
		if got != nil {
			t.Errorf("got %d vulns on empty input, want nil", len(got))
		}
	}
}

func TestParseOSVOutputSkipsUnknownEcosystems(t *testing.T) {
	// A package with ecosystem="Go" (a language ecosystem) shouldn't
	// produce an os-pkg vulnerability — that's handled by depscan,
	// not ospkg. This guards the orchestrator from misrouting findings.
	body := []byte(`{
		"results": [{
			"source": {"path": "/tmp/sbom.json", "type": "sbom"},
			"packages": [{
				"package": {"name": "foo", "version": "1.0", "ecosystem": "Go", "purl": "pkg:golang/foo@1.0"},
				"vulnerabilities": [{"id": "GHSA-x", "summary": "x"}]
			}]
		}]
	}`)
	got, _ := parseOSVOutput(body)
	if len(got) != 0 {
		t.Errorf("got %d vulns from a Go-ecosystem package; want 0 (ospkg only handles OS managers)", len(got))
	}
}

func TestNormalizeSeverityMapsAllCases(t *testing.T) {
	for in, want := range map[string]string{
		"CRITICAL": "critical",
		"HIGH":     "high",
		"MEDIUM":   "medium",
		"MODERATE": "medium",
		"LOW":      "low",
		"UNKNOWN":  "medium", // default for unknown
		"":         "medium",
	} {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestChooseAdvisoryIDPrefersCVE(t *testing.T) {
	got := chooseAdvisoryID("DSA-5677-1", []string{"CVE-2026-43581", "GHSA-xyz"})
	if got != "CVE-2026-43581" {
		t.Errorf("got %q, want the CVE alias", got)
	}
	got = chooseAdvisoryID("OSV-2024-9999", nil)
	if got != "OSV-2024-9999" {
		t.Errorf("got %q, want raw ID when no aliases", got)
	}
	got = chooseAdvisoryID("", []string{"GHSA-only"})
	if got != "GHSA-only" {
		t.Errorf("got %q, want first alias when ID empty", got)
	}
}
