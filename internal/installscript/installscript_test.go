// Package installscript_test guards the install.sh script's cosign and
// repository identity strings. install.sh is bash, so it is not exercised by
// `go test ./...` directly. This test file pulls the script's most
// security-sensitive substrings into Go's test runner so a typo cannot ship
// undetected — a wrong --certificate-identity-regexp would let cosign
// silently verify a binary signed by the wrong identity.
package installscript_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func installScript(t *testing.T) string {
	t.Helper()
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(repoRoot, "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestInstallSh_CosignCertIdentityRegexp(t *testing.T) {
	// MUST match the GitHub repo URL exactly. A typo here makes cosign
	// verification silently pass against the wrong signing identity.
	const want = `--certificate-identity-regexp 'https://github.com/harshmaur/audr/.+'`

	script := installScript(t)
	if !strings.Contains(script, want) {
		t.Fatalf("install.sh missing exact cosign --certificate-identity-regexp\n  want substring: %s", want)
	}
}

func TestInstallSh_CosignOIDCIssuer(t *testing.T) {
	const want = `--certificate-oidc-issuer 'https://token.actions.githubusercontent.com'`

	script := installScript(t)
	if !strings.Contains(script, want) {
		t.Fatalf("install.sh missing exact cosign --certificate-oidc-issuer\n  want substring: %s", want)
	}
}

func TestInstallSh_RepoConstant(t *testing.T) {
	const want = `REPO="harshmaur/audr"`

	script := installScript(t)
	if !strings.Contains(script, want) {
		t.Fatalf("install.sh REPO constant must be %q (drives every download URL)", want)
	}
}

func TestInstallSh_BinaryPathExtractsFromArchiveDir(t *testing.T) {
	// The release tarball wraps the binary in a versioned directory:
	//   audr-vX.Y.Z-os-arch/audr
	// install.sh must point at the binary file INSIDE that directory.
	// Pointing at the directory itself causes `mv` to install a directory
	// at $INSTALL_DIR/audr instead of an executable file (regression
	// surfaced by the v0.3.0 smoke test).
	const want = `binary="${tmp}/audr-${VERSION}-${os}-${arch}/audr"`

	script := installScript(t)
	if !strings.Contains(script, want) {
		t.Fatalf("install.sh binary= must include /audr suffix to point at the file, not the dir\n  want: %s", want)
	}
}

func TestInstallSh_NoLegacyReferences(t *testing.T) {
	// Once renamed, no legacy product-name references should leak back into
	// install.sh — any commit that re-introduces the old name fails CI.
	legacyLower := "agent" + "guard"
	legacyTitle := "Agent" + "Guard"
	legacyUpper := "AGENT" + "GUARD"

	script := installScript(t)
	for _, banned := range []string{legacyLower, legacyTitle, legacyUpper} {
		if strings.Contains(script, banned) {
			t.Errorf("install.sh contains banned legacy substring %q", banned)
		}
	}
}
