package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/harshmaur/agentguard/internal/selfaudit"
	"github.com/spf13/cobra"
)

func newSelfAuditCmd() *cobra.Command {
	var flagJSON bool
	cmd := &cobra.Command{
		Use:   "self-audit",
		Short: "Print the SHA-256 of the running binary plus its full rule + chain manifest",
		Long: `self-audit produces a structured trust report of the running agentguard
binary: SHA-256 of the executable, version, build VCS revision, every rule
the binary will fire on a scan, and every attack chain in the correlation
engine.

Use cases:
  - prove to a security reviewer what is compiled in
  - diff the manifest from two installs to confirm they are identical
  - feed --json into a CMDB / asset-inventory ingestor

self-audit does NOT verify the binary against a published SHA256SUMS file.
For that, use 'agentguard verify' on the downloaded tarball.`,
		Example: `  agentguard self-audit
  agentguard self-audit --json | jq .binary.sha256
  diff <(ssh dev1 agentguard self-audit --json) <(ssh dev2 agentguard self-audit --json)`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := selfaudit.Build(Version)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if flagJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			printSelfAuditText(out, report)
			return nil
		},
	}
	cmd.Flags().BoolVar(&flagJSON, "json", false, "emit the manifest as JSON instead of human-readable text")
	return cmd
}

func printSelfAuditText(w io.Writer, r selfaudit.Report) {
	fmt.Fprintln(w, "AgentGuard self-audit")
	fmt.Fprintln(w, strings.Repeat("=", 60))
	fmt.Fprintf(w, "binary:       %s\n", r.Binary.Path)
	fmt.Fprintf(w, "sha256:       %s\n", r.Binary.Sha256)
	fmt.Fprintf(w, "size:         %d bytes\n", r.Binary.Size)
	fmt.Fprintf(w, "version:      %s\n", r.Binary.Version)
	if r.Binary.BuildVCS != "" {
		fmt.Fprintf(w, "vcs.revision: %s\n", r.Binary.BuildVCS)
	}
	fmt.Fprintf(w, "go:           %s (%s/%s)\n", r.Binary.GoVer, r.Binary.OS, r.Binary.Arch)
	fmt.Fprintf(w, "generated:    %s\n", r.GeneratedAt.Format("2006-01-02T15:04:05Z"))
	fmt.Fprintln(w)

	fmt.Fprintf(w, "Rules (%d):\n", len(r.Rules))
	for _, rule := range r.Rules {
		fmt.Fprintf(w, "  [%-9s %-10s] %-40s %s\n",
			rule.Severity,
			rule.Taxonomy,
			rule.ID,
			rule.Title,
		)
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "Attack chains (%d):\n", len(r.Chains))
	for _, c := range r.Chains {
		fmt.Fprintf(w, "  [%-8s] %-36s %s\n", c.Severity, c.ID, c.Title)
	}
}
