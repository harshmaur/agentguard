package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/harshmaur/audr/internal/verify"
	"github.com/spf13/cobra"
)

var errVerifyFailed = errors.New("verification failed")

func newVerifyCmd() *cobra.Command {
	var (
		flagSums         string
		flagCertIdentity string
		flagOIDCIssuer   string
	)
	cmd := &cobra.Command{
		Use:   "verify <tarball>",
		Short: "Verify a downloaded release tarball against SHA256SUMS (and cosign if installed)",
		Long: `Verify a downloaded release tarball.

audr verify hashes the tarball, compares it against a SHA256SUMS file
(by default, the SHA256SUMS file in the same directory), and if the
'cosign' binary is on PATH plus the .sig and .crt files are alongside the
tarball, runs 'cosign verify-blob' against the sigstore transparency log.

This is the no-cosign-required path documented in README.md. The SHA-256
check alone proves the tarball matches the publisher's recorded hash; the
cosign check (when present) additionally proves the hash was signed by the
GitHub Actions release workflow at github.com/harshmaur/audr.

Exit code is 0 if all attempted checks pass, 1 otherwise.`,
		Example: `  audr verify audr-v0.2.4-linux-arm64.tar.gz
  audr verify --sums ./SHA256SUMS ./audr-v0.2.4-linux-arm64.tar.gz`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tarball := args[0]
			if _, err := os.Stat(tarball); err != nil {
				return fmt.Errorf("tarball: %w", err)
			}
			r, err := verify.Verify(tarball, verify.Options{
				SumsPath:           flagSums,
				CertIdentityRegexp: flagCertIdentity,
				CertOIDCIssuer:     flagOIDCIssuer,
			})
			if err != nil {
				return err
			}
			printVerifyResult(cmd.OutOrStdout(), r)
			if !r.Pass() {
				return errVerifyFailed
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&flagSums, "sums", "", "path to SHA256SUMS (default: SHA256SUMS in tarball directory)")
	cmd.Flags().StringVar(&flagCertIdentity, "cert-identity-regexp", "", "override cosign certificate identity regexp")
	cmd.Flags().StringVar(&flagOIDCIssuer, "cert-oidc-issuer", "", "override cosign OIDC issuer")
	return cmd
}

func printVerifyResult(w io.Writer, r verify.Result) {
	mark := func(ok bool) string {
		if ok {
			return "OK  "
		}
		return "FAIL"
	}
	fmt.Fprintf(w, "tarball:      %s\n", r.Tarball)
	fmt.Fprintf(w, "sha256:       %s\n", r.Sum)
	fmt.Fprintf(w, "sums file:    %s\n", r.Sums)
	fmt.Fprintf(w, "[%s] sha256 matches SHA256SUMS\n", mark(r.SumsOK))

	switch {
	case r.CosignAttempted:
		fmt.Fprintf(w, "[%s] cosign verify-blob — %s\n", mark(r.CosignOK), r.CosignDetail)
		fmt.Fprintf(w, "  identity: %s\n", r.CertIdentityRegexp)
		fmt.Fprintf(w, "  issuer:   %s\n", r.CertOIDCIssuer)
	case r.CosignAvailable:
		fmt.Fprintln(w, "[skip] cosign present, but no .sig/.crt next to tarball — skipping signature check")
	default:
		fmt.Fprintln(w, "[skip] cosign not on PATH — install cosign to verify the sigstore transparency log signature")
	}

	if r.Pass() {
		fmt.Fprintln(w, "\nverify: PASS")
	} else {
		fmt.Fprintln(w, "\nverify: FAIL — do not install this artifact")
	}
}
