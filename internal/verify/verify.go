// Package verify provides release-artifact verification for Audr
// tarballs published to GitHub Releases.
//
// Two layers, both optional but progressively stronger:
//
//  1. SHA-256 against a SHA256SUMS file. Always runs.
//  2. cosign verify-blob against the sigstore transparency log. Runs only if
//     a `cosign` binary is on PATH and the .sig/.crt files exist next to the
//     tarball. We shell out instead of linking sigstore — keeps the
//     audr binary small and avoids pulling 100+ MB of indirect deps
//     into a security tool.
//
// The intent: a fresh machine that does not yet have cosign can still get the
// SHA-256 check, which is the difference between "tarball matches the
// publisher's recorded hash" and "tarball is whatever a CDN handed me." That
// is most of the value for most installs.
package verify

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Result is a structured outcome from Verify. Callers render it; we don't
// print here so the cobra layer controls formatting.
type Result struct {
	Tarball string
	Sum     string // hex SHA-256 of Tarball
	Sums    string // path to SHA256SUMS used
	SumsOK  bool   // tarball hash matched a line in SHA256SUMS

	CosignAvailable bool
	CosignAttempted bool
	CosignOK        bool   // cosign verify-blob exit 0
	CosignDetail    string // human-readable summary or stderr excerpt
	SigPath         string
	CertPath        string

	// Identity used for cosign verification. The default is the keyless
	// GitHub Actions OIDC issuer matching the harshmaur/audr repo.
	CertIdentityRegexp string
	CertOIDCIssuer     string
}

// Defaults wired into the CLI. Overridable for tests / forks.
const (
	DefaultCertIdentityRegexp = `https://github.com/harshmaur/audr/.+`
	DefaultCertOIDCIssuer     = `https://token.actions.githubusercontent.com`
)

// Options tunes a Verify call. All fields are optional; an empty Options is
// the default install path (look for SHA256SUMS next to the tarball, expect
// the harshmaur/audr release identity).
type Options struct {
	// SumsPath is the SHA256SUMS file to check against. Empty = look next
	// to the tarball.
	SumsPath string
	// CertIdentityRegexp overrides the cosign --certificate-identity-regexp
	// flag. Empty = DefaultCertIdentityRegexp.
	CertIdentityRegexp string
	// CertOIDCIssuer overrides the cosign --certificate-oidc-issuer flag.
	// Empty = DefaultCertOIDCIssuer.
	CertOIDCIssuer string
}

// Verify computes the tarball's SHA-256, looks for that hash in a SHA256SUMS
// file, and optionally invokes cosign if the binary is on PATH and the
// detached .sig/.crt files are alongside the tarball.
func Verify(tarballPath string, opts Options) (Result, error) {
	certIdentity := opts.CertIdentityRegexp
	if certIdentity == "" {
		certIdentity = DefaultCertIdentityRegexp
	}
	oidcIssuer := opts.CertOIDCIssuer
	if oidcIssuer == "" {
		oidcIssuer = DefaultCertOIDCIssuer
	}

	r := Result{
		Tarball:            tarballPath,
		CertIdentityRegexp: certIdentity,
		CertOIDCIssuer:     oidcIssuer,
	}

	sum, err := sha256File(tarballPath)
	if err != nil {
		return r, fmt.Errorf("hash %s: %w", tarballPath, err)
	}
	r.Sum = sum

	sumsPath := opts.SumsPath
	if sumsPath == "" {
		sumsPath = filepath.Join(filepath.Dir(tarballPath), "SHA256SUMS")
	}
	r.Sums = sumsPath

	matched, err := matchInSumsFile(sumsPath, sum, filepath.Base(tarballPath))
	if err != nil {
		// Hard error reading sums — surface it. Caller decides exit code.
		return r, fmt.Errorf("read %s: %w", sumsPath, err)
	}
	r.SumsOK = matched

	cosignPath := lookupCosign()
	r.CosignAvailable = cosignPath != ""
	r.SigPath = tarballPath + ".sig"
	r.CertPath = tarballPath + ".crt"
	if r.CosignAvailable && fileExists(r.SigPath) && fileExists(r.CertPath) {
		r.CosignAttempted = true
		ok, detail := runCosign(cosignPath, tarballPath, r.SigPath, r.CertPath, certIdentity, oidcIssuer)
		r.CosignOK = ok
		r.CosignDetail = detail
	}

	return r, nil
}

// Pass is the operator-friendly summary: did every check we ran pass?
//
// We treat "cosign not attempted because the binary or the .sig/.crt are not
// present" as pass-by-omission. Without those files the SHA-256 check is the
// strongest signal we have, and forcing a cosign-or-fail gate would punish
// the install path that explicitly does not require cosign.
func (r Result) Pass() bool {
	if !r.SumsOK {
		return false
	}
	if r.CosignAttempted && !r.CosignOK {
		return false
	}
	return true
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// matchInSumsFile parses a SHA256SUMS-format file (one line per file:
// "<64-hex>  <filename>") and returns true if the given hash appears for the
// expected basename. We require both — a hash that matches a *different*
// filename is not a pass.
func matchInSumsFile(sumsPath, wantHash, wantBase string) (bool, error) {
	f, err := os.Open(sumsPath)
	if err != nil {
		return false, err
	}
	defer f.Close()
	wantHash = strings.ToLower(wantHash)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		gotHash := strings.ToLower(strings.TrimPrefix(fields[0], "*"))
		gotName := fields[len(fields)-1]
		gotName = strings.TrimPrefix(gotName, "*")
		if gotHash == wantHash && filepath.Base(gotName) == wantBase {
			return true, nil
		}
	}
	if err := sc.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func lookupCosign() string {
	p, err := exec.LookPath("cosign")
	if err != nil {
		return ""
	}
	return p
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !st.IsDir()
}

// runCosign shells out to cosign verify-blob. cosignPath is the absolute
// path resolved by exec.LookPath — using it directly avoids a second PATH
// resolution and makes the intent obvious. Returns (passed, detail) where
// detail is a short human-readable summary. We don't return raw stderr in
// the pass case — sigstore output is verbose and full of UUIDs that belong
// in --debug, not in a one-line summary.
func runCosign(cosignPath, tarball, sig, crt, certIdentityRegexp, oidcIssuer string) (bool, string) {
	cmd := exec.Command(cosignPath, "verify-blob",
		"--certificate", crt,
		"--signature", sig,
		"--certificate-identity-regexp", certIdentityRegexp,
		"--certificate-oidc-issuer", oidcIssuer,
		tarball,
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return true, "verified against sigstore transparency log"
	}
	excerpt := strings.TrimSpace(string(out))
	// Trim to the first non-empty line — sigstore can dump 20+ lines.
	if i := strings.Index(excerpt, "\n"); i > 0 {
		excerpt = excerpt[:i]
	}
	if errors.Is(err, exec.ErrNotFound) {
		return false, "cosign not on PATH"
	}
	if excerpt == "" {
		excerpt = err.Error()
	}
	return false, excerpt
}
