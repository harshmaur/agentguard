package ospkg

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// sbomDoc is the minimal CycloneDX 1.5 SBOM shape OSV-Scanner ingests.
// We don't fill optional metadata (timestamp, tools, etc.) — OSV only
// inspects components[].purl for matching, and a leaner SBOM is
// cheaper to write to disk + parse for OSV-Scanner.
type sbomDoc struct {
	BomFormat   string          `json:"bomFormat"`
	SpecVersion string          `json:"specVersion"`
	Version     int             `json:"version"`
	Components  []sbomComponent `json:"components"`
}

type sbomComponent struct {
	Type    string `json:"type"`    // "library" is what OSV expects for OS packages
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

// buildSBOM turns the enumerated package list into a CycloneDX 1.5
// document. Each package gets a PURL identifier that maps to OSV's
// internal ecosystem (Debian, Ubuntu, RHEL, etc.) so OSV can find
// matching advisories.
//
// PURL spec: https://github.com/package-url/purl-spec
//
//   pkg:deb/<distro>/<name>@<version>?arch=<arch>
//   pkg:rpm/<distro>/<name>@<version>
//   pkg:apk/<distro>/<name>@<version>
//
// We omit the arch qualifier (audr doesn't enumerate it from
// dpkg/rpm/apk in this slice). OSV matches without arch for the
// distros it covers.
func buildSBOM(info DistroInfo, pkgs []Package) ([]byte, error) {
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("buildSBOM: no packages")
	}
	purlType := managerToPurlType(info.Manager)
	if purlType == "" {
		return nil, fmt.Errorf("buildSBOM: no PURL type for manager %q", info.Manager)
	}
	purlDistro := string(info.ID) // "debian" / "ubuntu" / "rhel" / etc.

	doc := sbomDoc{
		BomFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Components:  make([]sbomComponent, 0, len(pkgs)),
	}
	for _, p := range pkgs {
		purl := fmt.Sprintf("pkg:%s/%s/%s@%s",
			purlType,
			purlDistro,
			url.PathEscape(p.Name),
			url.PathEscape(p.Version),
		)
		doc.Components = append(doc.Components, sbomComponent{
			Type:    "library",
			Name:    p.Name,
			Version: p.Version,
			PURL:    purl,
		})
	}
	return json.Marshal(doc)
}

func managerToPurlType(m Manager) string {
	switch m {
	case ManagerDpkg:
		return "deb"
	case ManagerRpm:
		return "rpm"
	case ManagerApk:
		return "apk"
	default:
		return ""
	}
}
