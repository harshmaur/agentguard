package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/harshmaur/audr/internal/depscan"
	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/ospkg"
	"github.com/harshmaur/audr/internal/scan"
	"github.com/harshmaur/audr/internal/secretscan"
	"github.com/harshmaur/audr/internal/state"
)

// Orchestrator drives audr's scanning cadence: runs the existing
// scan/depscan/secretscan engines on a periodic interval, converts
// their findings to the kind+locator state schema (D17), persists
// them via the state.Store, detects resolutions (open findings not
// re-detected in the latest cycle), and records per-category
// scanner statuses (D4).
//
// Implements daemon.Subsystem: Run(ctx) blocks until ctx cancels.
// On startup it kicks an initial scan immediately so the dashboard
// has content within seconds of `audr daemon start`.
//
// Phase 4 wires native rules + TruffleHog (with AI chat transcript
// roots from secretscan.AIChatTranscriptRoots). OSV-Scanner deps and
// the OS-package enumerator land in v1.1; for now we record their
// scanner status as "unavailable" so the dashboard's per-category
// banner fires correctly (proving the D4 contract end-to-end).
type Orchestrator struct {
	opts Options
	log  *slog.Logger
}

// Options configures an Orchestrator. Most fields default sanely.
type Options struct {
	// Store is the destination for findings + scanner statuses. Required.
	Store *state.Store

	// Roots are the filesystem paths to scan. Empty defaults to $HOME.
	Roots []string

	// Interval between scan cycles. Defaults to 10 minutes. With
	// Phase 3's watcher wired via ExternalTriggers, the interval
	// becomes a safety-net fallback — most scans fire from filesystem
	// quiescence events.
	Interval time.Duration

	// ExternalTriggers, when non-nil, is an additional channel the
	// orchestrator selects on alongside its internal ticker. Each
	// receive runs one scan cycle (subject to the same runMu lock
	// the periodic ticker uses). Phase 3 wires the watcher's
	// Triggers() channel here.
	ExternalTriggers <-chan time.Time

	// ScanOpts is the scan.Options template applied per cycle. Roots,
	// Logger, and ScanTimeout are overridden by the orchestrator.
	ScanOpts scan.Options

	// RunSecrets enables TruffleHog secret scanning. Defaults to true
	// when trufflehog is on PATH; false otherwise. AI chat transcript
	// paths get added to the scan roots when this is enabled.
	RunSecrets *bool

	// RunOSPkg enables OS-package CVE detection (Linux only, via
	// ospkg.EnumerateAndScan). Defaults to ospkg.Available(); tests
	// pin to false so they don't shell out to real dpkg/rpm/osv-scanner.
	RunOSPkg *bool

	// RunDeps enables language-package CVE detection via osv-scanner
	// (npm / pip / cargo / maven / etc.). Defaults to true iff
	// osv-scanner is on PATH; tests pin to false.
	RunDeps *bool

	// HomeDir is used to discover AI chat transcript paths. Empty
	// defaults to os.UserHomeDir().
	HomeDir string

	// Logger receives orchestrator-level events. nil → discard.
	Logger *slog.Logger
}

// New constructs an Orchestrator with the provided options. Validates
// the required fields but does not start running yet — Run() does
// that.
func New(opts Options) (*Orchestrator, error) {
	if opts.Store == nil {
		return nil, errors.New("orchestrator: Store is required")
	}
	if opts.Interval <= 0 {
		opts.Interval = 10 * time.Minute
	}
	if opts.HomeDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("orchestrator: resolve home: %w", err)
		}
		opts.HomeDir = home
	}
	if len(opts.Roots) == 0 {
		opts.Roots = []string{opts.HomeDir}
	}
	if opts.RunSecrets == nil {
		// Default: true iff trufflehog is on PATH. Avoids surprising
		// the user with a scanner-missing banner on a default boot.
		status := secretscan.BackendStatus()
		b := status.Installed
		opts.RunSecrets = &b
	}
	if opts.RunOSPkg == nil {
		// Default: true iff ospkg.Available() says so (Linux with a
		// covered distro and osv-scanner installed). Tests pin false.
		available, _ := ospkg.Available()
		opts.RunOSPkg = &available
	}
	if opts.RunDeps == nil {
		// Default: true iff osv-scanner is on PATH. The package
		// ecosystem dispatch (npm/pip/etc.) is fully handled by
		// osv-scanner; we just need to provide it filesystem roots.
		status := depscan.BackendStatus(depscan.BackendOSVScanner)
		b := status.Installed
		opts.RunDeps = &b
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
	}
	return &Orchestrator{opts: opts, log: logger}, nil
}

// Name implements daemon.Subsystem.
func (o *Orchestrator) Name() string { return "orchestrator" }

// Run implements daemon.Subsystem. Performs an initial scan
// immediately, then re-scans on:
//
//   - the internal Interval ticker (safety net), AND
//   - every receive on ExternalTriggers (Phase 3 watcher events)
//
// runMu inside runOnce serializes concurrent cycles, so a watcher
// trigger fired while the periodic ticker is mid-scan is queued
// behind it rather than dropping or interleaving.
func (o *Orchestrator) Run(ctx context.Context) error {
	o.log.Info(
		"orchestrator starting",
		"roots", o.opts.Roots,
		"interval", o.opts.Interval,
		"run_secrets", *o.opts.RunSecrets,
		"external_triggers", o.opts.ExternalTriggers != nil,
	)

	// Initial scan.
	if err := o.runOnce(ctx); err != nil {
		o.log.Error("initial scan failed", "err", err)
		// Non-fatal: the orchestrator keeps running so subsequent
		// cycles get a chance.
	}

	tick := time.NewTicker(o.opts.Interval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			o.log.Debug("scan triggered by interval", "interval", o.opts.Interval)
			if err := o.runOnce(ctx); err != nil {
				o.log.Error("scan cycle failed", "err", err)
			}
		case t, ok := <-o.opts.ExternalTriggers:
			if !ok {
				// Watcher closed its channel (daemon shutting down or
				// watcher crashed). Fall back to ticker-only mode for
				// the rest of this Run; we don't want to busy-loop on
				// a closed channel.
				o.opts.ExternalTriggers = nil
				continue
			}
			o.log.Info("scan triggered by watcher", "quiescence_ts", t)
			if err := o.runOnce(ctx); err != nil {
				o.log.Error("scan cycle failed", "err", err)
			}
		}
	}
}

// Close implements daemon.Subsystem. The orchestrator holds no
// resources beyond its goroutine + state.Store reference (owned
// elsewhere); Close is a no-op for now.
func (o *Orchestrator) Close() error { return nil }

// runMu serializes concurrent runOnce invocations. Phase 4 doesn't
// call runOnce concurrently (Run uses a ticker), but the lock makes
// the contract explicit for Phase 3 when watch events may try to
// trigger scans on top of the periodic timer.
var runMu sync.Mutex

// runOnce executes one full scan cycle:
//  1. Open a scan row in the store.
//  2. Capture the set of currently-open finding fingerprints (for
//     resolution detection at the end).
//  3. Run native rules via scan.Run.
//  4. Run TruffleHog if enabled, with AI chat transcript paths added
//     to the roots. Convert + persist findings.
//  5. Record scanner status per category.
//  6. Resolve any previously-open finding that wasn't re-detected.
//  7. Complete the scan.
//
// On any persistence failure mid-cycle, we still try to complete the
// scan (so the in_progress row doesn't linger). The error is logged
// and returned for the caller.
func (o *Orchestrator) runOnce(ctx context.Context) error {
	runMu.Lock()
	defer runMu.Unlock()

	cycleStart := time.Now()
	scanID, err := o.opts.Store.OpenScan("all")
	if err != nil {
		return fmt.Errorf("open scan: %w", err)
	}
	o.log.Info("scan cycle started", "scan_id", scanID, "roots", o.opts.Roots)

	// Snapshot of previously-open fingerprints — anything in this set
	// that we DON'T re-detect this cycle gets resolved at the end.
	previouslyOpen := map[string]struct{}{}
	if existing, err := o.opts.Store.SnapshotFindings(ctx); err == nil {
		for _, f := range existing {
			if f.Open() {
				previouslyOpen[f.Fingerprint] = struct{}{}
			}
		}
	} else {
		o.log.Warn("snapshot existing findings failed; resolution detection skipped this cycle", "err", err)
	}

	// Track which fingerprints we saw this cycle.
	seen := map[string]struct{}{}

	// --- Native rules + correlate (AI-Agent category) ----------------
	nativeStatus := state.ScannerStatus{ScanID: scanID, Category: "ai-agent", Status: "ok"}
	if err := o.runNative(ctx, scanID, seen); err != nil {
		nativeStatus.Status = "error"
		nativeStatus.ErrorText = err.Error()
		o.log.Error("native scan failed", "err", err)
	}
	if err := o.opts.Store.RecordScannerStatus(nativeStatus); err != nil {
		o.log.Warn("record scanner status (native)", "err", err)
	}

	// --- TruffleHog (Secrets category) -------------------------------
	secretsStatus := state.ScannerStatus{ScanID: scanID, Category: "secrets"}
	if *o.opts.RunSecrets {
		if err := o.runSecrets(ctx, scanID, seen); err != nil {
			secretsStatus.Status = "error"
			secretsStatus.ErrorText = err.Error()
			o.log.Error("secrets scan failed", "err", err)
		} else {
			secretsStatus.Status = "ok"
		}
	} else {
		secretsStatus.Status = "unavailable"
		secretsStatus.ErrorText = "trufflehog not installed; run `audr update-scanners` to enable secret scanning"
	}
	if err := o.opts.Store.RecordScannerStatus(secretsStatus); err != nil {
		o.log.Warn("record scanner status (secrets)", "err", err)
	}

	// --- OSV dependency scanner (Deps category) ----------------------
	// Calls osv-scanner against the configured roots; converts each
	// returned vulnerability into a kind="dep-package" state.Finding
	// with {ecosystem, name, version, manifest_path} locator.
	depsStatus := state.ScannerStatus{ScanID: scanID, Category: "deps"}
	if !*o.opts.RunDeps {
		depsStatus.Status = "unavailable"
		depsStatus.ErrorText = "osv-scanner not installed; run `audr update-scanners --backend osv-scanner --yes`"
	} else {
		if err := o.runDeps(ctx, scanID, seen); err != nil {
			depsStatus.Status = "error"
			depsStatus.ErrorText = err.Error()
			o.log.Error("deps scan failed", "err", err)
		} else {
			depsStatus.Status = "ok"
		}
	}
	if err := o.opts.Store.RecordScannerStatus(depsStatus); err != nil {
		o.log.Warn("record scanner status (deps)", "err", err)
	}

	// --- OS-package enumerator (OS-Pkg category) ---------------------
	// Linux distros covered by OSV (dpkg / rpm / apk): enumerate
	// installed packages, feed them to osv-scanner via CycloneDX SBOM,
	// upsert any returned vulnerabilities as kind="os-package"
	// state.Findings. macOS / Windows / unknown distros: record
	// "unavailable" with a friendly reason.
	osPkgStatus := state.ScannerStatus{ScanID: scanID, Category: "os-pkg"}
	if !*o.opts.RunOSPkg {
		osPkgStatus.Status = "unavailable"
		_, osPkgStatus.ErrorText = ospkg.Available()
		if osPkgStatus.ErrorText == "" {
			osPkgStatus.ErrorText = "OS-package CVE detection disabled by configuration"
		}
	} else {
		if err := o.runOSPkg(ctx, scanID, seen); err != nil {
			osPkgStatus.Status = "error"
			osPkgStatus.ErrorText = err.Error()
			o.log.Error("os-pkg scan failed", "err", err)
		} else {
			osPkgStatus.Status = "ok"
		}
	}
	if err := o.opts.Store.RecordScannerStatus(osPkgStatus); err != nil {
		o.log.Warn("record scanner status (os-pkg)", "err", err)
	}

	// --- Resolution detection ----------------------------------------
	// Any previously-open finding not re-detected this cycle is now
	// resolved. This is what produces the strike-through animation on
	// the dashboard when the user fixes a finding (or via Claude
	// Code's AI prompt).
	resolved := 0
	for fp := range previouslyOpen {
		if _, stillOpen := seen[fp]; stillOpen {
			continue
		}
		changed, err := o.opts.Store.ResolveFinding(fp)
		if err != nil {
			o.log.Warn("resolve absent finding", "fingerprint", fp, "err", err)
			continue
		}
		if changed {
			resolved++
		}
	}

	if err := o.opts.Store.CompleteScan(scanID); err != nil {
		o.log.Warn("complete scan", "err", err)
	}

	o.log.Info("scan cycle complete",
		"scan_id", scanID,
		"duration_ms", time.Since(cycleStart).Milliseconds(),
		"findings_seen", len(seen),
		"findings_resolved", resolved,
	)
	return nil
}

// runNative invokes scan.Run for the native rule engine and upserts
// its findings into the store. seen is populated with each finding's
// fingerprint so resolution detection at the end of the cycle knows
// to ignore them.
func (o *Orchestrator) runNative(ctx context.Context, scanID int64, seen map[string]struct{}) error {
	opts := o.opts.ScanOpts
	opts.Roots = o.opts.Roots
	opts.Logger = o.log
	if opts.ScanTimeout == 0 {
		opts.ScanTimeout = 5 * time.Minute
	}

	res, err := scan.Run(ctx, opts)
	if err != nil {
		// scan.Run returns partial results on timeout. Persist what we
		// got and surface the error.
		if res != nil {
			_ = o.persistFindings(scanID, res.Findings, seen)
		}
		return err
	}
	return o.persistFindings(scanID, res.Findings, seen)
}

// runSecrets invokes TruffleHog against the scan roots plus AI chat
// transcript paths and persists its findings into the secrets
// category.
func (o *Orchestrator) runSecrets(ctx context.Context, scanID int64, seen map[string]struct{}) error {
	// Discover AI chat transcript paths and extend the secret-scan
	// roots with them. This is the unique-to-audr feature: nobody
	// else scans agent transcripts for leaked credentials.
	roots := append([]string(nil), o.opts.Roots...)
	chatRoots, err := secretscan.AIChatTranscriptRoots(o.opts.HomeDir)
	if err != nil {
		o.log.Warn("discover AI chat transcript roots", "err", err)
	} else if len(chatRoots) > 0 {
		// Dedupe: if a chat root is already inside a configured root
		// (e.g., $HOME), TruffleHog would walk it twice. The
		// scanignore-based exclude file doesn't filter the AI chat
		// dirs (we WANT them scanned), but we also don't want
		// redundant work.
		for _, cr := range chatRoots {
			if !pathInsideAny(cr, roots) {
				roots = append(roots, cr)
			}
		}
	}

	findings, err := secretscan.RunBackend(ctx, secretscan.RunOptions{Roots: roots})
	if err != nil {
		return err
	}
	return o.persistFindings(scanID, findings, seen)
}

// runOSPkg enumerates installed OS packages, feeds them through
// OSV-Scanner via CycloneDX SBOM, and persists each returned
// vulnerability as a state.Finding with kind="os-package" and a
// {manager, name, version} locator. Each (package, advisory) pair
// becomes its own finding so they're independently resolvable on
// the dashboard.
//
// Bounded by a 60-second timeout because OSV-Scanner against a full
// dpkg list (~2k packages) takes ~10-30s; corrupted rpmdb cases can
// hang for minutes.
func (o *Orchestrator) runOSPkg(ctx context.Context, scanID int64, seen map[string]struct{}) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	vulns, err := ospkg.EnumerateAndScan(ctx)
	if err != nil {
		return err
	}
	o.log.Info("os-pkg scan", "vulnerabilities", len(vulns))

	for _, v := range vulns {
		locator, err := json.Marshal(map[string]any{
			"manager": string(v.Package.Manager),
			"name":    v.Package.Name,
			"version": v.Package.Version,
		})
		if err != nil {
			o.log.Warn("os-pkg: marshal locator", "err", err)
			continue
		}
		fp, err := state.Fingerprint("osv-os-package", "os-package", locator, v.AdvisoryID)
		if err != nil {
			o.log.Warn("os-pkg: fingerprint", "err", err)
			continue
		}

		title := fmt.Sprintf("%s %s — %s", v.Package.Name, v.Package.Version, v.AdvisoryID)
		desc := v.Summary
		if desc == "" {
			desc = fmt.Sprintf("OSV reported %s against the installed %s package %s %s.",
				v.AdvisoryID, v.Package.Manager, v.Package.Name, v.Package.Version)
		}
		if v.FixedIn != "" {
			desc = fmt.Sprintf("%s Fixed in %s %s.", desc, v.Package.Name, v.FixedIn)
		}

		sf := state.Finding{
			Fingerprint:   fp,
			RuleID:        fmt.Sprintf("osv-%s-%s", v.Package.Manager, v.Package.Name),
			Severity:      v.Severity,
			Category:      "os-pkg",
			Kind:          "os-package",
			Locator:       locator,
			Title:         title,
			Description:   desc,
			MatchRedacted: v.AdvisoryID,
			FirstSeenScan: scanID,
			LastSeenScan:  scanID,
		}
		seen[fp] = struct{}{}
		if _, err := o.opts.Store.UpsertFinding(sf); err != nil {
			o.log.Warn("os-pkg: upsert finding", "rule_id", sf.RuleID, "err", err)
		}
	}
	return nil
}

// runDeps invokes osv-scanner against the orchestrator's configured
// roots and persists each returned vulnerability as a state.Finding
// with kind="dep-package" and {ecosystem, name, version, manifest_path}
// locator. Each (package, advisory) pair becomes its own finding so
// they're individually resolvable.
//
// Differs from runOSPkg in that we don't build a synthetic SBOM —
// osv-scanner walks the filesystem itself looking for manifest files
// (package.json, requirements.txt, Cargo.toml, etc.) and reports
// what it finds.
func (o *Orchestrator) runDeps(ctx context.Context, scanID int64, seen map[string]struct{}) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	findings, err := depscan.RunBackend(ctx, depscan.RunOptions{
		Backend: depscan.BackendOSVScanner,
		Roots:   o.opts.Roots,
	})
	if err != nil {
		return err
	}
	o.log.Info("deps scan", "vulnerabilities", len(findings))

	for _, f := range findings {
		sf, err := depscanFindingToState(f, scanID)
		if err != nil {
			o.log.Warn("deps: convert finding", "rule_id", f.RuleID, "err", err)
			continue
		}
		seen[sf.Fingerprint] = struct{}{}
		if _, err := o.opts.Store.UpsertFinding(sf); err != nil {
			o.log.Warn("deps: upsert finding", "fingerprint", sf.Fingerprint, "err", err)
		}
	}
	return nil
}

// persistFindings converts each finding.Finding into a state.Finding
// keyed by canonical fingerprint and upserts it through the store.
// Records each fingerprint in seen for resolution detection.
func (o *Orchestrator) persistFindings(scanID int64, findings []finding.Finding, seen map[string]struct{}) error {
	for _, f := range findings {
		category := categorizeRuleID(f.RuleID)
		stateFinding, err := findingToStateFinding(f, scanID, category)
		if err != nil {
			o.log.Warn("convert finding", "rule_id", f.RuleID, "err", err)
			continue
		}
		seen[stateFinding.Fingerprint] = struct{}{}
		if _, err := o.opts.Store.UpsertFinding(stateFinding); err != nil {
			o.log.Warn("upsert finding", "rule_id", f.RuleID, "fingerprint", stateFinding.Fingerprint, "err", err)
		}
	}
	return nil
}

// pathInsideAny returns true if child is a path beneath any of
// parents. Used to dedupe AI chat roots against the user's primary
// scan roots.
func pathInsideAny(child string, parents []string) bool {
	absChild, _ := filepath.Abs(child)
	for _, p := range parents {
		absP, _ := filepath.Abs(p)
		// Ensure we're matching path components, not substrings.
		rel, err := filepath.Rel(absP, absChild)
		if err != nil {
			continue
		}
		// rel doesn't start with ".." → child is inside parent.
		if rel == "." || (len(rel) > 0 && rel[0] != '.' && !startsWithUpDir(rel)) {
			return true
		}
	}
	return false
}

func startsWithUpDir(rel string) bool {
	// rel like "../foo" or just ".."
	return len(rel) >= 2 && rel[:2] == ".."
}

// discardWriter is a tiny io.Writer that drops everything, used when
// the caller doesn't supply a logger.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
