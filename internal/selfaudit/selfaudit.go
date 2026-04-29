// Package selfaudit produces a structured report of what is compiled into
// the running audr binary: its SHA-256, version, and the full list of
// rules and attack chains that will fire on a scan.
//
// The use case is procurement-grade trust. A CISO asking "what does the
// binary on this developer's laptop actually do?" can run
// `audr self-audit --json`, diff it against the same command run on a
// known-good machine, and prove the two binaries are identical.
//
// Self-audit does not verify the binary against a published SHA256SUMS —
// that is what `audr verify` is for. The two commands are
// complementary: verify proves the tarball you downloaded matches what the
// publisher signed; self-audit proves the binary you have right now
// behaves the way its hash claims.
package selfaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"time"

	"github.com/harshmaur/audr/internal/correlate"
	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
	"github.com/harshmaur/audr/internal/rules"
)

// Report is the structured self-audit output. Stable JSON shape — downstream
// tools (CI, CMDB ingestion) can rely on it.
type Report struct {
	GeneratedAt time.Time   `json:"generated_at"`
	Binary      Binary      `json:"binary"`
	Rules       []RuleEntry `json:"rules"`
	Chains      []ChainEntry `json:"attack_chains"`
}

// Binary captures everything we know about the executable we are running
// inside. Path + SHA-256 together let an operator compare two installs.
type Binary struct {
	Path     string `json:"path"`
	Sha256   string `json:"sha256"`
	Size     int64  `json:"size_bytes"`
	Version  string `json:"version"`
	GoVer    string `json:"go_version"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	BuildVCS string `json:"build_vcs,omitempty"` // commit hash if -buildvcs left on
}

// RuleEntry is the public manifest entry for a registered rule.
type RuleEntry struct {
	ID       string         `json:"id"`
	Title    string         `json:"title"`
	Severity string         `json:"severity"`
	Taxonomy string         `json:"taxonomy"`
	Formats  []parse.Format `json:"formats"`
}

// ChainEntry mirrors correlate.ChainMeta for JSON output.
type ChainEntry struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
}

// Build assembles the full report. Pass the version string from the cobra
// layer (it lives in cmd/audr/main.go and we don't want to import
// main from a library).
func Build(version string) (Report, error) {
	binPath, err := os.Executable()
	if err != nil {
		return Report{}, fmt.Errorf("locate executable: %w", err)
	}

	sum, size, err := sha256AndSize(binPath)
	if err != nil {
		return Report{}, fmt.Errorf("hash executable: %w", err)
	}

	r := Report{
		GeneratedAt: time.Now().UTC(),
		Binary: Binary{
			Path:    binPath,
			Sha256:  sum,
			Size:    size,
			Version: version,
			GoVer:   runtime.Version(),
			OS:      runtime.GOOS,
			Arch:    runtime.GOARCH,
		},
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				r.Binary.BuildVCS = s.Value
				break
			}
		}
	}

	for _, rule := range rules.All() {
		r.Rules = append(r.Rules, RuleEntry{
			ID:       rule.ID(),
			Title:    rule.Title(),
			Severity: rule.Severity().String(),
			Taxonomy: string(rule.Taxonomy()),
			Formats:  rule.Formats(),
		})
	}
	sort.Slice(r.Rules, func(i, j int) bool { return r.Rules[i].ID < r.Rules[j].ID })

	for _, c := range correlate.Manifest() {
		r.Chains = append(r.Chains, ChainEntry{
			ID:       c.ID,
			Title:    c.Title,
			Severity: c.Severity.String(),
		})
	}
	sort.Slice(r.Chains, func(i, j int) bool {
		// Critical (0) before High (1) before Medium etc; within tier, alpha.
		if severityRank(r.Chains[i].Severity) != severityRank(r.Chains[j].Severity) {
			return severityRank(r.Chains[i].Severity) < severityRank(r.Chains[j].Severity)
		}
		return r.Chains[i].ID < r.Chains[j].ID
	})

	return r, nil
}

func severityRank(s string) int {
	switch s {
	case finding.SeverityCritical.String():
		return 0
	case finding.SeverityHigh.String():
		return 1
	case finding.SeverityMedium.String():
		return 2
	case finding.SeverityLow.String():
		return 3
	}
	return 99
}

func sha256AndSize(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
