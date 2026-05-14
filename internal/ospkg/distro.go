// Package ospkg enumerates installed OS packages and runs them
// through OSV-Scanner to find applicable CVEs. v1 ships Linux
// only — Debian/Ubuntu (dpkg), RHEL/Rocky/Alma (rpm), Alpine (apk) —
// because those are the distros OSV's database covers natively.
// macOS (brew) and Windows (winget) ship as fix-command rendering
// only in Phase 6 templates; this package returns Available=false
// on them.
//
// Pipeline:
//
//   1. Detect distro (parse /etc/os-release).
//   2. Enumerate installed packages via dpkg-query / rpm / apk.
//   3. Build a CycloneDX 1.5 SBOM whose components carry pkg-URL
//      identifiers (pkg:deb/<distro>/<name>@<version>, etc.).
//   4. Shell out: `osv-scanner scan source --sbom=<tmpfile> --format=json`.
//   5. Parse the JSON; emit one Vulnerability per (package, advisory) pair.
//
// Each scan touches the rpm/dpkg/apk database read-only. No package
// state is modified — the daemon never auto-applies upgrades.
package ospkg

import (
	"bufio"
	"errors"
	"os"
	"strings"
)

// DistroID is the lowercase ID field from /etc/os-release ("debian",
// "ubuntu", "rhel", "rocky", "almalinux", "alpine", "fedora", "arch",
// "opensuse-tumbleweed", ...). Empty when not Linux.
type DistroID string

// Known distro IDs we recognize for OS-package CVE detection.
const (
	DistroDebian   DistroID = "debian"
	DistroUbuntu   DistroID = "ubuntu"
	DistroRHEL     DistroID = "rhel"
	DistroRocky    DistroID = "rocky"
	DistroAlma     DistroID = "almalinux"
	DistroAlpine   DistroID = "alpine"
	DistroFedora   DistroID = "fedora"
	DistroCentOS   DistroID = "centos"
)

// Manager is the package manager native to a distro. Maps 1:1 to the
// PURL type used in the CycloneDX SBOM and to the `locator.manager`
// stored on state.Finding for OS-package kind rows.
type Manager string

const (
	ManagerDpkg Manager = "dpkg"
	ManagerRpm  Manager = "rpm"
	ManagerApk  Manager = "apk"
)

// DistroInfo captures everything we read out of /etc/os-release that
// matters downstream: the canonical ID, the version codename (used
// in some PURL qualifiers like `distro=bookworm`), and the package
// manager.
type DistroInfo struct {
	ID            DistroID
	VersionCodename string // "bookworm", "jammy", "9", etc. — may be empty
	Manager       Manager
}

// detectDistro reads /etc/os-release and maps its ID field to a
// DistroInfo. Returns an empty info + nil when the file doesn't
// exist (non-Linux or minimal container), and an error only on
// genuine parse failures.
//
// We deliberately only recognize a small allowlist of distros
// matching OSV-Scanner's coverage. Unknown IDs return (empty, nil)
// so the orchestrator can mark os-pkg category "unavailable" with a
// friendly "this distro isn't covered by OSV yet" message.
func detectDistro() (DistroInfo, error) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DistroInfo{}, nil
		}
		return DistroInfo{}, err
	}
	defer f.Close()

	values := map[string]string{}
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.IndexByte(line, '=')
		if i < 0 {
			continue
		}
		k := strings.TrimSpace(line[:i])
		v := strings.Trim(strings.TrimSpace(line[i+1:]), `"'`)
		values[k] = v
	}
	if err := scan.Err(); err != nil {
		return DistroInfo{}, err
	}

	rawID := strings.ToLower(strings.TrimSpace(values["ID"]))
	codename := values["VERSION_CODENAME"]
	if codename == "" {
		codename = values["VERSION_ID"]
	}

	mgr, distroID, ok := managerFor(rawID, values["ID_LIKE"])
	if !ok {
		return DistroInfo{}, nil
	}
	return DistroInfo{
		ID:              distroID,
		VersionCodename: codename,
		Manager:         mgr,
	}, nil
}

// managerFor resolves (rawID, idLike) → (Manager, DistroID, ok).
// ID_LIKE is the canonical "I'm derived from X" hint — distros like
// Linux Mint set ID=linuxmint, ID_LIKE="ubuntu debian" so we should
// still treat them as dpkg-family. Same for RHEL clones (Rocky,
// Alma) and Alpine-based images.
//
// We deliberately do not recognize Arch or openSUSE here: OSV-Scanner
// doesn't cover their ecosystems well, and feeding them in produces
// noisy/empty results. Phase 4's `unavailable` status with a v1.1
// message is the right user-facing answer.
func managerFor(id, idLike string) (Manager, DistroID, bool) {
	// Check direct ID first; fall back to ID_LIKE tokens.
	candidates := []string{id}
	for _, tok := range strings.Fields(strings.ToLower(idLike)) {
		candidates = append(candidates, strings.Trim(tok, `"`))
	}
	for _, c := range candidates {
		switch c {
		case "debian", "ubuntu":
			return ManagerDpkg, DistroID(c), true
		case "rhel", "centos", "fedora", "rocky", "almalinux":
			return ManagerRpm, DistroID(c), true
		case "alpine":
			return ManagerApk, DistroAlpine, true
		}
	}
	return "", "", false
}
