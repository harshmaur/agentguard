package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/harshmaur/audr/internal/depscan"
	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/lowprio"
	"github.com/harshmaur/audr/internal/ospkg"
	"github.com/harshmaur/audr/internal/policy"
	"github.com/harshmaur/audr/internal/scan"
	"github.com/harshmaur/audr/internal/secretscan"
	"github.com/harshmaur/audr/internal/state"
	"github.com/harshmaur/audr/internal/triage"
	"github.com/harshmaur/audr/internal/watch"
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
// Phase 4 wires native rules + Betterleaks (with AI chat transcript
// roots from secretscan.AIChatTranscriptRoots). OSV-Scanner deps and
// the OS-package enumerator land in v1.1; for now we record their
// scanner status as "unavailable" so the dashboard's per-category
// banner fires correctly (proving the D4 contract end-to-end).
type Orchestrator struct {
	opts Options
	log  *slog.Logger

	// autoSecrets / autoDeps / autoOSPkg flag whether each scanner
	// was at its auto-default (Options.Run* nil) at construction
	// time. In auto mode the orchestrator re-probes the sidecar
	// status before every scan cycle, so installing betterleaks /
	// osv-scanner externally takes effect within one scan interval
	// instead of requiring a daemon restart (D15 from eng review).
	// When the caller pinned a value explicitly (tests, future
	// user-config override), auto mode is off and the pinned value
	// sticks.
	autoSecrets bool
	autoDeps    bool
	autoOSPkg   bool
}

// Options configures an Orchestrator. Most fields default sanely.
type Options struct {
	// Store is the destination for findings + scanner statuses. Required.
	Store *state.Store

	// Roots are the filesystem paths to scan. Empty defaults to $HOME.
	Roots []string

	// Interval between scan cycles. Defaults to 1 hour. The watcher
	// (via ExternalTriggers) is the primary scan trigger for anything
	// inside its scope — git repos, ~/.claude/~/.cursor, dotfiles —
	// firing within ~5s of the filesystem settling. The periodic
	// ticker is the catch-all for state the watcher can't observe:
	// /var/lib/dpkg/status (new apt install), the rpmdb (new yum
	// install), kernel package upgrades, etc. Pre-1.4 default was
	// 10 min, which churned CPU on idle machines; the incremental
	// scan_cache landed in 1.4 makes each cycle nearly free, but the
	// hourly default still matches user intuition about a background
	// security tool's cadence.
	Interval time.Duration

	// ExternalTriggers, when non-nil, is an additional channel the
	// orchestrator selects on alongside its internal ticker. Each
	// receive runs one scan cycle (subject to the same runMu lock
	// the periodic ticker uses). The watcher's Triggers() channel
	// feeds this; each trigger carries the deduplicated set of paths
	// that fired during the quiescence burst so RelevantPath can drop
	// cycles where nothing of interest changed.
	ExternalTriggers <-chan watch.Trigger

	// RelevantPath, when non-nil, is consulted on every external
	// trigger before running a scan. The trigger fires a scan only if
	// AT LEAST ONE path in trigger.Paths returns true. A trigger with
	// no paths at all (the watcher couldn't attribute the burst to
	// specific files) ALWAYS scans — better to over-run than miss a
	// real change.
	//
	// Daemon production: wires a filter that drops Claude transcript
	// churn, sqlite WAL rotation, log writes, etc — i.e. paths that
	// no rule cares about but that the watcher sees constantly. This
	// is the fix for "scans firing every 2 minutes because Claude
	// Code itself writes to ~/.claude/projects/X/transcripts/".
	RelevantPath func(path string) bool

	// ScanOpts is the scan.Options template applied per cycle. Roots,
	// Logger, and ScanTimeout are overridden by the orchestrator.
	ScanOpts scan.Options

	// RunSecrets enables Betterleaks secret scanning. Defaults to true
	// when betterleaks is on PATH; false otherwise. AI chat transcript
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

	// DepsRunner overrides the command runner the deps scanner uses to
	// invoke osv-scanner. nil → lowprio.Runner{} (production default).
	// Tests inject a stub so they can assert on invocation counts (to
	// verify the depscan cache is short-circuiting osv-scanner calls).
	DepsRunner depscan.CommandRunner

	// OSPkgScanner overrides the function the orchestrator uses to
	// enumerate + scan OS packages. nil → ospkg.EnumerateAndScan
	// (production). Tests inject a stub that returns canned vulns and
	// records call counts to verify the ospkg cache is short-circuiting
	// the dpkg-query / rpm / apk pipeline.
	OSPkgScanner func(ctx context.Context) ([]ospkg.Vulnerability, error)

	// OSPkgFingerprint overrides the package-DB fingerprinter. nil →
	// ospkg.PackageDBFingerprint (production). Tests return a value
	// they control so they can exercise both cache-hit and
	// fingerprint-mismatch paths without needing a real package DB.
	OSPkgFingerprint func() (string, error)

	// AudrVersion is the running binary's version. Plumbed into
	// scan.Options.AudrVersion so the per-file scan cache (v1.4
	// addition) invalidates every cached row on a binary upgrade —
	// new rules may now fire on previously-clean files, so reusing
	// pre-upgrade verdicts would silently miss findings. Empty
	// disables the per-file cache entirely.
	AudrVersion string

	// SkipTickerWhen, when non-nil, is consulted before every periodic
	// (Interval ticker) scan. Returning true suppresses that one scan
	// — the next tick re-checks. Watcher-driven (ExternalTriggers)
	// scans are NOT gated here because the watcher applies its own
	// backoff (RUN/SLOW/PAUSE) to its trigger channel; this knob
	// closes the loophole where the ticker fired regardless.
	//
	// Daemon production: wires to a closure that returns true when the
	// watcher's backoff state is PAUSE (load > 4.0 or thermal
	// pressure). Result: under sustained load the daemon stops both
	// trigger-driven AND ticker-driven scans, matching the AV/EDR
	// behavior of yielding the machine to interactive work.
	SkipTickerWhen func() bool

	// HomeDir is used to discover AI chat transcript paths. Empty
	// defaults to os.UserHomeDir().
	HomeDir string

	// StateDir is the daemon's state directory. Required when the
	// orchestrator should honor scanner.config.json (user-controllable
	// enable/disable per category). When empty, scanner config is
	// not read — all categories run subject only to sidecar
	// availability. Tests that don't care about user config can
	// leave this empty.
	StateDir string

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
		opts.Interval = 1 * time.Hour
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
	// Track which fields were at auto-default so runOnce can
	// re-probe them on every cycle (D15: installing a sidecar
	// externally should take effect within one scan interval, not
	// require a daemon restart).
	autoSecrets := opts.RunSecrets == nil
	autoDeps := opts.RunDeps == nil
	autoOSPkg := opts.RunOSPkg == nil

	if opts.RunSecrets == nil {
		// Default: true iff betterleaks is on PATH. Avoids surprising
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
	return &Orchestrator{
		opts:        opts,
		log:         logger,
		autoSecrets: autoSecrets,
		autoDeps:    autoDeps,
		autoOSPkg:   autoOSPkg,
	}, nil
}

// reprobeSidecars re-checks sidecar availability for any scanner
// that was at its auto-default at construction time. Called at the
// top of every runOnce cycle so a freshly-installed betterleaks /
// osv-scanner takes effect within one scan interval. Logs the
// transition when a sidecar flips from unavailable→available (or
// vice versa) so the daemon's log shows the moment audr noticed.
func (o *Orchestrator) reprobeSidecars() {
	if o.autoSecrets {
		newVal := secretscan.BackendStatus().Installed
		if *o.opts.RunSecrets != newVal {
			o.log.Info("sidecar transition (secrets)",
				"from", *o.opts.RunSecrets, "to", newVal)
			*o.opts.RunSecrets = newVal
		}
	}
	if o.autoDeps {
		newVal := depscan.BackendStatus(depscan.BackendOSVScanner).Installed
		if *o.opts.RunDeps != newVal {
			o.log.Info("sidecar transition (deps)",
				"from", *o.opts.RunDeps, "to", newVal)
			*o.opts.RunDeps = newVal
		}
	}
	if o.autoOSPkg {
		newVal, _ := ospkg.Available()
		if *o.opts.RunOSPkg != newVal {
			o.log.Info("sidecar transition (os-pkg)",
				"from", *o.opts.RunOSPkg, "to", newVal)
			*o.opts.RunOSPkg = newVal
		}
	}
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
			if o.opts.SkipTickerWhen != nil && o.opts.SkipTickerWhen() {
				o.log.Info("ticker scan suppressed", "reason", "backoff state requested skip")
				continue
			}
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
			if !o.triggerIsRelevant(t) {
				// No path in the burst matched the relevance filter.
				// Skip — the next watcher pulse re-evaluates fresh,
				// and the ticker is the safety net for anything we
				// genuinely missed.
				o.log.Debug("scan trigger dropped (no relevant paths)",
					"quiescence_ts", t.Time, "paths", len(t.Paths))
				continue
			}
			o.log.Info("scan triggered by watcher",
				"quiescence_ts", t.Time, "paths", len(t.Paths))
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

	// Before anything else: if any scanner was at auto-default at
	// construction, re-probe its sidecar. Catches the
	// "user installed betterleaks after daemon started" case so the
	// dashboard reflects it within one scan interval rather than
	// requiring a daemon restart (D15).
	o.reprobeSidecars()

	cycleStart := time.Now()
	scanID, err := o.opts.Store.OpenScan("all")
	if err != nil {
		return fmt.Errorf("open scan: %w", err)
	}
	o.log.Info("scan cycle started", "scan_id", scanID, "roots", o.opts.Roots)

	// Snapshot of previously-open fingerprints — anything in this set
	// that we DON'T re-detect this cycle MAY get resolved at the end,
	// but only if its scanner actually ran successfully this cycle.
	// Storing the category lets the resolution loop below check the
	// scanner's terminal status (ok / error / disabled / unavailable)
	// before resolving — see the per-category gate below.
	previouslyOpen := map[string]string{} // fingerprint → category
	if existing, err := o.opts.Store.SnapshotFindings(ctx); err == nil {
		for _, f := range existing {
			if f.Open() {
				previouslyOpen[f.Fingerprint] = f.Category
			}
		}
	} else {
		o.log.Warn("snapshot existing findings failed; resolution detection skipped this cycle", "err", err)
	}

	// Per-scanner seen sets. Each scanner gets its own map so the
	// sidecar goroutines below don't need to share mutable state;
	// runOnce unions them before the resolution loop. The state.Store
	// is already single-writer-safe (writerLoop goroutine), so the
	// Store.UpsertFinding calls inside each run* can fire concurrently
	// without a mutex.
	nativeSeen := map[string]struct{}{}
	secretsSeen := map[string]struct{}{}
	depsSeen := map[string]struct{}{}
	osPkgSeen := map[string]struct{}{}

	// Read user-controllable scanner enable/disable. When StateDir
	// is empty (tests), or the file is missing, default to "all
	// on" — the orchestrator still respects sidecar availability
	// via Options.Run* fields.
	scannerCfg := DefaultScannerConfig()
	if o.opts.StateDir != "" {
		if cfg, err := ReadScannerConfig(o.opts.StateDir); err != nil {
			o.log.Warn("read scanner config (defaulting to all-on)", "err", err)
		} else {
			scannerCfg = cfg
		}
	}

	// markRunning records the category as currently executing so the
	// dashboard's scan-progress strip can highlight which scanner is
	// busy mid-cycle. The terminal status (ok / error / unavailable
	// / disabled) overwrites this via the UPSERT in
	// RecordScannerStatus. Skipped when a category is disabled or
	// unavailable up-front (no point flashing "running" for half a
	// millisecond before the terminal state).
	markRunning := func(category string) {
		_ = o.opts.Store.RecordScannerStatus(state.ScannerStatus{
			ScanID:   scanID,
			Category: category,
			Status:   "running",
		})
	}

	// disabledStatus is the shape used when the user has turned a
	// category off via scanner.config.json. Distinct from
	// "unavailable" (sidecar not installed) so dashboards can show
	// different banner copy.
	disabledStatus := func(category string) state.ScannerStatus {
		return state.ScannerStatus{
			ScanID:    scanID,
			Category:  category,
			Status:    "disabled",
			ErrorText: fmt.Sprintf("%s scanner disabled by user; run `audr daemon scanners --on=%s` to re-enable", category, category),
		}
	}

	// --- Native rules + correlate (AI-Agent category) ----------------
	// Native runs first, alone. It walks the configured roots looking
	// for AI agent config files — fast (seconds), but it competes for
	// FS read bandwidth with betterleaks's $HOME walk, so we serialize
	// the two to avoid doubling page-cache pressure on the user's box.
	nativeStatus := state.ScannerStatus{ScanID: scanID, Category: "ai-agent", Status: "ok"}
	if !scannerCfg.AIAgent {
		nativeStatus = disabledStatus("ai-agent")
	} else {
		markRunning("ai-agent")
		if err := o.runNative(ctx, scanID, nativeSeen); err != nil {
			nativeStatus.Status = "error"
			nativeStatus.ErrorText = err.Error()
			o.log.Error("native scan failed", "err", err)
		}
	}
	if err := o.opts.Store.RecordScannerStatus(nativeStatus); err != nil {
		o.log.Warn("record scanner status (native)", "err", err)
	}

	// --- Sidecar scanners (secrets / deps / os-pkg) in parallel ------
	// These three are largely independent: betterleaks is CPU+disk
	// (short burst + a few HTTP roundtrips for validation), osv-scanner
	// for deps + os-pkg is dominated by network IO against api.osv.dev.
	// Running them sequentially used to burn ~30s per cycle waiting on
	// osv while the secret scanner wasn't using the network anyway.
	// State.Store is single-writer-safe (writerLoop goroutine in
	// internal/state), so concurrent UpsertFinding calls are fine
	// without a mutex.
	var (
		secretsStatus = state.ScannerStatus{ScanID: scanID, Category: "secrets"}
		depsStatus    = state.ScannerStatus{ScanID: scanID, Category: "deps"}
		osPkgStatus   = state.ScannerStatus{ScanID: scanID, Category: "os-pkg"}
		sidecarsWG    sync.WaitGroup
	)

	sidecarsWG.Add(3)
	go func() {
		defer sidecarsWG.Done()
		if !scannerCfg.Secrets {
			secretsStatus = disabledStatus("secrets")
			return
		}
		if !*o.opts.RunSecrets {
			secretsStatus.Status = "unavailable"
			secretsStatus.ErrorText = "betterleaks not installed; run `audr update-scanners` to enable secret scanning"
			return
		}
		markRunning("secrets")
		if err := o.runSecrets(ctx, scanID, secretsSeen); err != nil {
			secretsStatus.Status = "error"
			secretsStatus.ErrorText = err.Error()
			o.log.Error("secrets scan failed", "err", err)
			return
		}
		secretsStatus.Status = "ok"
	}()

	go func() {
		defer sidecarsWG.Done()
		if !scannerCfg.Deps {
			depsStatus = disabledStatus("deps")
			return
		}
		if !*o.opts.RunDeps {
			depsStatus.Status = "unavailable"
			depsStatus.ErrorText = "osv-scanner not installed; run `audr update-scanners --backend osv-scanner --yes`"
			return
		}
		markRunning("deps")
		if err := o.runDeps(ctx, scanID, depsSeen); err != nil {
			depsStatus.Status = "error"
			depsStatus.ErrorText = err.Error()
			o.log.Error("deps scan failed", "err", err)
			return
		}
		depsStatus.Status = "ok"
	}()

	go func() {
		defer sidecarsWG.Done()
		if !scannerCfg.OSPkg {
			osPkgStatus = disabledStatus("os-pkg")
			return
		}
		if !*o.opts.RunOSPkg {
			osPkgStatus.Status = "unavailable"
			_, osPkgStatus.ErrorText = ospkg.Available()
			if osPkgStatus.ErrorText == "" {
				osPkgStatus.ErrorText = "OS-package CVE detection disabled by configuration"
			}
			return
		}
		markRunning("os-pkg")
		if err := o.runOSPkg(ctx, scanID, osPkgSeen); err != nil {
			osPkgStatus.Status = "error"
			osPkgStatus.ErrorText = err.Error()
			o.log.Error("os-pkg scan failed", "err", err)
			return
		}
		osPkgStatus.Status = "ok"
	}()

	sidecarsWG.Wait()

	// Record sidecar statuses after the wait — keeps the dashboard's
	// "ok" pulse contemporaneous with the actual completion instead of
	// flashing in the middle of a still-running sibling.
	if err := o.opts.Store.RecordScannerStatus(secretsStatus); err != nil {
		o.log.Warn("record scanner status (secrets)", "err", err)
	}
	if err := o.opts.Store.RecordScannerStatus(depsStatus); err != nil {
		o.log.Warn("record scanner status (deps)", "err", err)
	}
	if err := o.opts.Store.RecordScannerStatus(osPkgStatus); err != nil {
		o.log.Warn("record scanner status (os-pkg)", "err", err)
	}

	// Union the per-scanner seen sets for resolution detection.
	seen := make(map[string]struct{}, len(nativeSeen)+len(secretsSeen)+len(depsSeen)+len(osPkgSeen))
	for _, src := range []map[string]struct{}{nativeSeen, secretsSeen, depsSeen, osPkgSeen} {
		for fp := range src {
			seen[fp] = struct{}{}
		}
	}

	// --- Resolution detection ----------------------------------------
	// Any previously-open finding not re-detected this cycle is now
	// resolved. This is what produces the strike-through animation on
	// the dashboard when the user fixes a finding (or via Claude
	// Code's AI prompt).
	//
	// Critical guard: a missing finding only means "resolved" when its
	// scanner actually ran successfully. If the scanner errored, was
	// disabled, or wasn't available, the absence from `seen` is a lack
	// of signal — not a "the issue is gone" signal. Resolving in that
	// case would mark hundreds of findings green on the dashboard the
	// moment betterleaks times out, then re-open them on the next scan
	// (often under different fingerprints, leaving phantom "resolved
	// today" entries that inflate the metric forever). Per-category
	// gate fixes that.
	okByCategory := map[string]bool{
		"ai-agent": nativeStatus.Status == "ok",
		"secrets":  secretsStatus.Status == "ok",
		"deps":     depsStatus.Status == "ok",
		"os-pkg":   osPkgStatus.Status == "ok",
	}
	resolved := 0
	skippedByCategory := map[string]int{}
	for fp, cat := range previouslyOpen {
		if _, stillOpen := seen[fp]; stillOpen {
			continue
		}
		if !okByCategory[cat] {
			skippedByCategory[cat]++
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
	for cat, n := range skippedByCategory {
		o.log.Info("skipped resolving findings (scanner did not complete OK this cycle)",
			"category", cat, "count", n, "status", scannerStatusFor(cat, nativeStatus, secretsStatus, depsStatus, osPkgStatus))
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
	// Wire the file-level cache. Daemon scans get fast cache hits on
	// unchanged files; one-shot CLI runs leave ScanOpts.Cache nil so
	// every `audr scan .` is a fresh evaluation. AudrVersion tags
	// every cached row — when the binary upgrades, the rules may have
	// changed, so every existing row is silently treated as stale.
	if opts.Cache == nil && o.opts.AudrVersion != "" {
		opts.Cache = scanFileCache{store: o.opts.Store}
		opts.AudrVersion = o.opts.AudrVersion
	}

	// Plan B3 — re-read policy at the top of every scan cycle so
	// dashboard saves take effect within one cycle without a daemon
	// restart. Missing file → DefaultPolicy → identical to v1.1.
	// Corrupt file → log a warning + fall back to defaults rather
	// than refusing to scan; the dashboard's "policy.yaml corrupt"
	// banner will surface the diagnostic to the user.
	policyPath, err := policy.Path()
	if err != nil {
		o.log.Warn("resolve policy path; using defaults this cycle", "err", err)
	} else {
		p, err := policy.Load(policyPath)
		if err != nil {
			o.log.Warn("load policy file; using defaults this cycle",
				"path", policyPath, "err", err)
			p = policy.DefaultPolicy()
		}
		eff := policy.NewEffective(p, time.Now())
		opts.Policy = eff
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

// runSecrets invokes Betterleaks against the scan roots plus AI chat
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
		// (e.g., $HOME), betterleaks would walk it twice. The
		// scanignore-based config file doesn't filter the AI chat
		// dirs (we WANT them scanned), but we also don't want
		// redundant work.
		for _, cr := range chatRoots {
			if !pathInsideAny(cr, roots) {
				roots = append(roots, cr)
			}
		}
	}

	findings, err := secretscan.RunBackend(ctx, secretscan.RunOptions{
		Roots:  roots,
		Runner: lowprio.Runner{},
		// Small validation-worker pool for the daemon's continuous
		// loop. The file walk itself is short (~2s on a realistic
		// $HOME). The dominant variable cost is validation HTTP
		// roundtrips, which DefaultDaemonJobs() caps at a conservative
		// concurrency so the daemon doesn't flood provider APIs in
		// the background. lowprio handles OS-level scheduling
		// pressure on top. Daemon scans trade latency for headroom;
		// CLI scans trade headroom for latency.
		Jobs: secretscan.DefaultDaemonJobs(),
	})
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

	fingerprinter := o.opts.OSPkgFingerprint
	if fingerprinter == nil {
		fingerprinter = ospkg.PackageDBFingerprint
	}
	scanner := o.opts.OSPkgScanner
	if scanner == nil {
		scanner = ospkg.EnumerateAndScan
	}
	const cacheScope = "ospkg:current"

	// Fingerprint first. If it matches the prior cache row, the
	// dpkg-query / rpm / apk → SBOM → osv-scanner pipeline can be
	// skipped entirely — on most dev machines the OS package set sits
	// unchanged for days, and re-running the pipeline every 10 minutes
	// only re-derives the same vulns list at full sidecar cost.
	fp, fpErr := fingerprinter()
	if fpErr != nil {
		o.log.Warn("os-pkg: fingerprint failed; running fresh", "err", fpErr)
	}

	var vulns []ospkg.Vulnerability
	cacheHit := false
	if fp != "" {
		entry, ok, gErr := o.opts.Store.GetScanCache(ctx, cacheScope)
		if gErr != nil {
			o.log.Warn("os-pkg: cache lookup failed; running fresh", "err", gErr)
		} else if ok && entry.Fingerprint == fp {
			var cached []ospkg.Vulnerability
			if uErr := json.Unmarshal(entry.Payload, &cached); uErr != nil {
				o.log.Warn("os-pkg: cache payload corrupt; running fresh", "err", uErr)
			} else {
				vulns = cached
				cacheHit = true
			}
		}
	}

	if !cacheHit {
		fresh, err := scanner(ctx)
		if err != nil {
			return err
		}
		vulns = fresh
		if fp != "" {
			payload, mErr := json.Marshal(vulns)
			if mErr != nil {
				o.log.Warn("os-pkg: marshal cache payload", "err", mErr)
			} else if pErr := o.opts.Store.PutScanCache(state.ScanCacheEntry{
				Scope:       cacheScope,
				Fingerprint: fp,
				Payload:     payload,
			}); pErr != nil {
				o.log.Warn("os-pkg: persist cache row", "err", pErr)
			}
		}
	}

	o.log.Info("os-pkg scan", "vulnerabilities", len(vulns), "cached", cacheHit)

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

	projectRoots, err := depscan.DiscoverProjectRoots(o.opts.Roots)
	if err != nil {
		return fmt.Errorf("discover project roots: %w", err)
	}
	if len(projectRoots) == 0 {
		o.log.Info("deps scan", "vulnerabilities", 0, "cached_roots", 0, "scanned_roots", 0)
		return nil
	}

	// Partition project roots into cache-hits (reuse payload, skip
	// osv-scanner) and cache-misses (fingerprint changed or no prior
	// entry — must rescan). Without this, osv-scanner re-walks every
	// lockfile in $HOME each cycle even when nothing changed.
	var cachedFindings []finding.Finding
	fingerprints := make(map[string]string, len(projectRoots))
	var staleRoots []string
	for _, root := range projectRoots {
		fp, fpErr := depscan.LockfileFingerprint(root)
		if fpErr != nil {
			o.log.Warn("deps: fingerprint failed; treating root as stale", "root", root, "err", fpErr)
			staleRoots = append(staleRoots, root)
			continue
		}
		fingerprints[root] = fp
		entry, ok, gErr := o.opts.Store.GetScanCache(ctx, depsCacheScope(root))
		if gErr != nil {
			o.log.Warn("deps: cache lookup failed; treating root as stale", "root", root, "err", gErr)
			staleRoots = append(staleRoots, root)
			continue
		}
		if !ok || entry.Fingerprint != fp || fp == "" {
			staleRoots = append(staleRoots, root)
			continue
		}
		var rfindings []finding.Finding
		if uErr := json.Unmarshal(entry.Payload, &rfindings); uErr != nil {
			o.log.Warn("deps: cache payload corrupt; treating root as stale", "root", root, "err", uErr)
			staleRoots = append(staleRoots, root)
			continue
		}
		cachedFindings = append(cachedFindings, rfindings...)
	}

	var freshFindings []finding.Finding
	if len(staleRoots) > 0 {
		runner := o.opts.DepsRunner
		if runner == nil {
			runner = lowprio.Runner{}
		}
		freshFindings, err = depscan.RunBackendOnProjectRoots(ctx, depscan.RunOptions{
			Backend: depscan.BackendOSVScanner,
			Runner:  runner,
		}, staleRoots)
		if err != nil {
			return err
		}
		// Bin fresh findings by owning project root and upsert a cache
		// row per stale root — including roots that returned zero
		// findings (their fingerprint match is what skips next cycle).
		byRoot := groupDepFindingsByRoot(freshFindings, staleRoots)
		for _, root := range staleRoots {
			fp := fingerprints[root]
			if fp == "" {
				// Fingerprint was missing for this root; nothing useful
				// to cache because we can't detect "unchanged" later.
				continue
			}
			payload, mErr := json.Marshal(byRoot[root])
			if mErr != nil {
				o.log.Warn("deps: marshal cache payload", "root", root, "err", mErr)
				continue
			}
			if pErr := o.opts.Store.PutScanCache(state.ScanCacheEntry{
				Scope:       depsCacheScope(root),
				Fingerprint: fp,
				Payload:     payload,
			}); pErr != nil {
				o.log.Warn("deps: persist cache row", "root", root, "err", pErr)
			}
		}
	}

	total := len(cachedFindings) + len(freshFindings)
	o.log.Info("deps scan",
		"vulnerabilities", total,
		"cached_roots", len(projectRoots)-len(staleRoots),
		"scanned_roots", len(staleRoots),
	)

	all := append(cachedFindings, freshFindings...)
	for _, f := range all {
		// v1.3: fill triage fields (DedupGroupKey + FixAuthority +
		// SecondaryNotify) BEFORE conversion so the state row carries
		// the rolled-up partition. depscan's OSV emitter pre-populates
		// DedupGroupKey; FixAuthority is path-derived here.
		f = triage.FillTriageFields(f, o.opts.HomeDir)
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

func depsCacheScope(projectRoot string) string {
	return "deps:" + projectRoot
}

// groupDepFindingsByRoot bins findings by which project root's tree
// they live under. Each finding has Path = the manifest file
// osv-scanner inspected; the owning root is the longest projectRoots
// prefix. A finding whose Path doesn't match any root (osv-scanner
// emitted a relative path, or the path got rewritten somewhere) falls
// back to the first root — better than dropping it, since the next
// cycle's mtime check will reproduce it.
func groupDepFindingsByRoot(findings []finding.Finding, projectRoots []string) map[string][]finding.Finding {
	sorted := append([]string(nil), projectRoots...)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	out := make(map[string][]finding.Finding, len(projectRoots))
	for _, root := range projectRoots {
		out[root] = nil
	}
	for _, f := range findings {
		matched := false
		for _, root := range sorted {
			if pathHasPathPrefix(f.Path, root) {
				out[root] = append(out[root], f)
				matched = true
				break
			}
		}
		if !matched && len(projectRoots) > 0 {
			out[projectRoots[0]] = append(out[projectRoots[0]], f)
		}
	}
	return out
}

// pathHasPathPrefix reports whether path lives under prefix as a
// directory-aligned subpath — true iff path == prefix or path starts
// with prefix + separator. Avoids false matches like "/foo-bar" being
// classified under "/foo".
func pathHasPathPrefix(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	rest := path[len(prefix):]
	if rest == "" {
		return true
	}
	return rest[0] == '/' || rest[0] == filepath.Separator
}

// persistFindings converts each finding.Finding into a state.Finding
// keyed by canonical fingerprint and upserts it through the store.
// Records each fingerprint in seen for resolution detection.
func (o *Orchestrator) persistFindings(scanID int64, findings []finding.Finding, seen map[string]struct{}) error {
	for _, f := range findings {
		// v1.3 triage: classify path → fix authority + maintainer hint
		// and fill DedupGroupKey for any rule that didn't pre-populate.
		// Secret-family rules require the YOU-forced authority — they
		// always rotate, even when the leaked path lives in a vendor dir.
		f = triage.FillTriageFields(f, o.opts.HomeDir)
		if isSecretRule(f.RuleID) {
			auth, secondary := triage.ForSecret(f.FixAuthority, f.SecondaryNotify)
			f.FixAuthority = auth
			f.SecondaryNotify = secondary
		}
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

// isSecretRule reports whether a rule emits secret-family findings.
// Secret rules need the FixAuthority=YOU clamp because a leaked key must
// be rotated regardless of which file it appeared in — the path-class
// table only tells us where to ALSO notify (SecondaryNotify).
func isSecretRule(ruleID string) bool {
	return strings.HasPrefix(ruleID, "secret-")
}

// scannerStatusFor returns the terminal status of the scanner that
// owns the given category. Used only for the diagnostic log line in
// runOnce that explains why a previously-open finding was skipped
// from resolution detection.
func scannerStatusFor(cat string, native, secrets, deps, osPkg state.ScannerStatus) string {
	switch cat {
	case "ai-agent":
		return native.Status
	case "secrets":
		return secrets.Status
	case "deps":
		return deps.Status
	case "os-pkg":
		return osPkg.Status
	default:
		return "unknown"
	}
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

// triggerIsRelevant returns true when at least one path in t passes
// the RelevantPath filter, or when no filter is set, or when t.Paths
// is empty (the watcher couldn't attribute the burst — fail safe by
// running the scan). Pure function so the Run loop stays readable.
func (o *Orchestrator) triggerIsRelevant(t watch.Trigger) bool {
	if o.opts.RelevantPath == nil {
		return true
	}
	if len(t.Paths) == 0 {
		return true
	}
	for _, p := range t.Paths {
		if o.opts.RelevantPath(p) {
			return true
		}
	}
	return false
}

// NewScanFileCache returns an adapter that lets scan.Options.Cache read
// and write the file_cache table on a state.Store. Exported so the
// one-shot CLI scan path (cmd/audr) can wire the same cache the daemon
// uses — both reuse `~/.audr/audr.db` and benefit from each other's
// cached entries.
//
// The store is expected to be already opened via state.Open. The
// adapter does not own the store and does not close it.
func NewScanFileCache(store *state.Store) scan.FileCache {
	return scanFileCache{store: store}
}

// scanFileCache adapts state.Store to scan.FileCache. The scan
// package deliberately can't import state (state imports finding;
// scan also imports finding — circular avoidance is the only motive,
// the adapter is otherwise pure passthrough).
type scanFileCache struct {
	store *state.Store
}

func (s scanFileCache) Get(ctx context.Context, path string) (scan.FileCacheEntry, bool, error) {
	row, ok, err := s.store.GetFileCache(ctx, path)
	if err != nil || !ok {
		return scan.FileCacheEntry{}, ok, err
	}
	return scan.FileCacheEntry{
		Path:        row.Path,
		MTime:       row.MTime,
		Size:        row.Size,
		Findings:    row.Findings,
		AudrVersion: row.AudrVersion,
	}, true, nil
}

func (s scanFileCache) Put(entry scan.FileCacheEntry) error {
	return s.store.PutFileCache(state.FileCacheEntry{
		Path:        entry.Path,
		MTime:       entry.MTime,
		Size:        entry.Size,
		Findings:    entry.Findings,
		AudrVersion: entry.AudrVersion,
	})
}
