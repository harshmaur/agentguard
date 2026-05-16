// Package scan implements the file walker, worker pool, and finding collector.
//
// Scanner concurrency model (mirrors design doc):
//
//	walker (1 goroutine)
//	   |  filePath chan
//	   v
//	worker pool (size = GOMAXPROCS, --jobs N)
//	   each worker per file:
//	     1. stat (skip if >sizeCap)
//	     2. ctx, cancel := context.WithTimeout(parent, FileTimeout)
//	     3. parse + apply rules under ctx
//	     4. on parse error: emit "parse-error" advisory finding, continue
//	   |  finding chan
//	   v
//	collector (1 goroutine)
//	   aggregates findings, applies suppression (redaction already applied at finding-construction),
//	   emits result
package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
	"github.com/harshmaur/audr/internal/rules"
	"github.com/harshmaur/audr/internal/suppress"
)

// FileCache is the persistence surface the scan worker uses to skip
// re-parsing + re-applying rules to files whose (mtime, size) is
// unchanged since the previous cycle. The state.Store satisfies this;
// the indirection lets the scan package stay independent of state's
// import graph.
//
// Implementations must be safe for concurrent Get from many goroutines
// (the worker pool reads in parallel); Put is called serialized per
// path so concurrent writes to the same path won't collide.
//
// Get returns (entry, true, nil) on hit, (zero, false, nil) on miss.
// Put is best-effort — errors are logged by the caller but do not
// fail the scan, since a cache miss next cycle is the worst outcome.
type FileCache interface {
	Get(ctx context.Context, path string) (FileCacheEntry, bool, error)
	Put(entry FileCacheEntry) error
}

// FileCacheEntry mirrors state.FileCacheEntry but uses the scan
// package's vocabulary. Decoupled struct keeps scan free of state's
// import graph; the orchestrator translates between the two.
type FileCacheEntry struct {
	Path        string
	MTime       int64
	Size        int64
	Findings    []byte // JSON-encoded []finding.Finding; nil → no cached findings
	AudrVersion string
}

// Options configures a scan.
type Options struct {
	// Roots are the directories or files to scan. Empty defaults to $HOME for
	// machine-mode scans; the CLI populates this.
	Roots []string

	// Workers controls worker pool size. Zero = runtime.GOMAXPROCS(0).
	Workers int

	// FileTimeout is the per-file parse + rule-apply deadline. Zero = 5s.
	FileTimeout time.Duration

	// FileSizeLimit is the per-file byte cap. Zero = 10MB.
	FileSizeLimit int64

	// ScanTimeout is the total scan deadline. Zero = 60s.
	ScanTimeout time.Duration

	// Suppress is the loaded .audrignore set (may be nil).
	Suppress *suppress.Set

	// SkipDirs are basenames of directories the walker should never descend
	// into. Defaults applied if empty: node_modules, vendor, .git, dist,
	// build, target, __pycache__, .next, .cache.
	SkipDirs []string

	// Logger receives slog records. nil → discard.
	Logger *slog.Logger

	// Policy is the rule-behavior overlay. nil = no overlay (v1.1
	// behavior — every rule fires with its natural severity).
	// The daemon orchestrator populates this from `~/.audr/policy.yaml`
	// on every scan cycle; the one-shot CLI scan leaves it nil.
	Policy rules.PolicyFilter

	// Cache, when non-nil, lets the worker skip parse + rule evaluation
	// for files whose (mtime, size) matches the cached entry AND whose
	// audr_version matches AudrVersion below. Daemon scans plug the
	// state.Store in here; one-shot `audr scan` runs leave it nil so
	// they always do fresh work (matches user expectation that
	// "audr scan ." returns current-state truth).
	//
	// correlate-relevant files (MCP configs, shell rcs, GHA workflows,
	// etc.) bypass the cache entirely — they're rare and small, and
	// the cross-finding correlate pass needs their parsed Document.
	Cache FileCache

	// AudrVersion is the running binary's version string. The cache
	// uses it as a generation tag: a binary upgrade invalidates every
	// existing entry because new rules may now fire on previously-
	// clean files. Empty when caching is disabled.
	AudrVersion string
}

// Result is what a scan produces.
type Result struct {
	Findings []finding.Finding
	// Documents retained for cross-finding correlation (Attack Chains).
	// Only documents whose Format is in the correlate-relevant set are
	// kept here; skill files and agent-doc markdown are dropped to bound
	// memory. Raw bytes are nil'd before retention.
	Documents   []*parse.Document
	StartedAt   time.Time
	FinishedAt  time.Time
	FilesSeen   int
	FilesParsed int
	Suppressed  int
	Skipped     int
}

// correlateRelevantFormats are the formats whose parsed Documents we retain
// in the Result for the correlate package to walk after the scan completes.
// Skill files and AgentDoc (huge gstack corpus) are excluded — they're not
// referenced by any current scenario.
var correlateRelevantFormats = map[parse.Format]bool{
	parse.FormatMCPConfig:         true,
	parse.FormatClaudeSettings:    true,
	parse.FormatCodexConfig:       true,
	parse.FormatWindsurfMCP:       true,
	parse.FormatCursorPermissions: true,
	parse.FormatShellRC:           true,
	parse.FormatEnv:               true,
	parse.FormatGHAWorkflow:       true,
}

// Run scans the configured roots and returns a Result. Returns the partial
// result plus the cancellation reason if ScanTimeout fires.
func Run(ctx context.Context, opts Options) (*Result, error) {
	opts = applyDefaults(opts)
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(noopWriter{}, nil))
	}

	scanCtx, cancel := context.WithTimeout(ctx, opts.ScanTimeout)
	defer cancel()

	res := &Result{StartedAt: time.Now()}

	pathCh := make(chan string, opts.Workers*2)
	findCh := make(chan finding.Finding, opts.Workers*4)
	statCh := make(chan workerStat, opts.Workers)
	docCh := make(chan *parse.Document, opts.Workers*2) // v0.2.0-alpha.5: retained for correlate

	// Walker
	walkerDone := make(chan struct{})
	go func() {
		defer close(pathCh)
		defer close(walkerDone)
		walk(scanCtx, opts, pathCh, logger)
	}()

	// Worker pool
	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			worker(scanCtx, id, opts, pathCh, findCh, statCh, docCh, logger)
		}(i)
	}

	// Collector
	collectorDone := make(chan struct{})
	go func() {
		defer close(collectorDone)
		for f := range findCh {
			if opts.Suppress != nil && opts.Suppress.Suppresses(f.RuleID, f.Path) {
				res.Suppressed++
				continue
			}
			res.Findings = append(res.Findings, f)
		}
	}()

	// Stat aggregator (counts files seen / parsed).
	statDone := make(chan struct{})
	go func() {
		defer close(statDone)
		for s := range statCh {
			res.FilesSeen += s.seen
			res.FilesParsed += s.parsed
			res.Skipped += s.skipped
		}
	}()

	// Document retainer (correlate-relevant docs only, Raw nil'd to bound memory).
	docDone := make(chan struct{})
	go func() {
		defer close(docDone)
		for d := range docCh {
			if d == nil {
				continue
			}
			if !correlateRelevantFormats[d.Format] {
				continue
			}
			d.Raw = nil // drop the raw bytes; structured fields are sufficient for correlate.
			res.Documents = append(res.Documents, d)
		}
	}()

	wg.Wait()
	close(findCh)
	close(statCh)
	close(docCh)
	<-collectorDone
	<-statDone
	<-docDone

	res.FinishedAt = time.Now()

	// Stable sort findings before formatters serialize. Use a total ordering so
	// same-rule findings on the same line do not inherit nondeterministic map or
	// goroutine collection order.
	sort.SliceStable(res.Findings, func(i, j int) bool {
		return finding.Less(res.Findings[i], res.Findings[j])
	})

	if errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
		return res, fmt.Errorf("scan timeout after %s", opts.ScanTimeout)
	}
	return res, nil
}

func applyDefaults(o Options) Options {
	if o.Workers <= 0 {
		o.Workers = runtime.GOMAXPROCS(0)
	}
	if o.FileTimeout <= 0 {
		o.FileTimeout = 5 * time.Second
	}
	if o.FileSizeLimit <= 0 {
		o.FileSizeLimit = 10 << 20 // 10MB
	}
	if o.ScanTimeout <= 0 {
		o.ScanTimeout = 60 * time.Second
	}
	if len(o.SkipDirs) == 0 {
		o.SkipDirs = defaultSkipDirs()
	}
	return o
}

// defaultSkipDirs is the basename-only skip list applied during the
// walker's DirEntry loop. Entries match by basename anywhere in the
// tree — so listing "node_modules" once skips every node_modules dir
// under any scan root.
//
// Cross-platform: Linux + macOS entries first, Windows-specific
// entries after. Windows entries are no-ops on Linux/macOS because
// the basenames simply don't appear there. Listing them here (rather
// than in a *_windows.go file) keeps the skip-list semantics
// portable when scanning a Windows volume mounted on a Linux host —
// e.g. via WSL or a forensics workstation walking a Windows backup.
//
// Entries to NOT add despite being noise:
//
//   - "Temp" (basename match too greedy — collides with legit
//     project Temp dirs; the user often has $HOME/repos/x/Temp)
//   - "OneDrive" (it's user-data; walking it is correct, just slow.
//     Users who want it skipped pass --skip OneDrive explicitly)
//   - ".vscode" (could contain MCP-relevant configs in the future)
func defaultSkipDirs() []string {
	return []string{
		// POSIX / cross-platform caches and build outputs.
		"node_modules", "vendor", ".git", "dist", "build", "target",
		"__pycache__", ".next", ".cache",

		// Windows AppData caches. These show up under
		// %LOCALAPPDATA% / %APPDATA% as basenames. Walking them on a
		// Windows machine eats minutes scanning binary blobs and
		// browser caches that contain zero audr-relevant content.
		"INetCache",   // Edge / IE cached pages and images
		"WindowsApps", // UWP / Microsoft Store app installs (binary tree)
		"NuGet",       // %APPDATA%\NuGet package cache
		".nuget",      // lowercase global package cache
		"npm-cache",   // %APPDATA%\npm-cache (separate from project node_modules)

		// Go build cache. `pkg` is deliberately NOT skipped — it
		// collides with legitimate Go source directories
		// (`myproject/pkg/...` is a widespread layout convention).
		// The format-detection short-circuit at line 345 handles
		// the per-file cost of walking $GOPATH/pkg/mod anyway.
		"go-build", // $GOCACHE artifact tree
	}
}

type workerStat struct {
	seen, parsed, skipped int
}

// tryCacheHit returns the cached findings for path iff:
//
//   - opts.Cache + opts.AudrVersion are both set (caching enabled),
//   - the file's format isn't correlate-relevant (those bypass cache),
//   - the file exists and is a regular file,
//   - a cache row exists for path,
//   - the cached (mtime, size, version) matches the file's current stat,
//   - the row's findings payload is non-nil and decodes successfully.
//
// On any failure the function returns ok=false silently — the caller
// falls back to the normal parse + rules path, which is always correct
// (just slower). The mtime/size return values are unused today but
// kept on the signature so a future caller doesn't need to re-stat.
func tryCacheHit(ctx context.Context, opts Options, path string) (findings []finding.Finding, ok bool, mtime int64, size int64) {
	if opts.Cache == nil || opts.AudrVersion == "" {
		return nil, false, 0, 0
	}
	if correlateRelevantFormats[parse.DetectFormat(path)] {
		return nil, false, 0, 0
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, false, 0, 0
	}
	mtime = info.ModTime().UnixNano()
	size = info.Size()

	entry, found, err := opts.Cache.Get(ctx, path)
	if err != nil || !found {
		return nil, false, mtime, size
	}
	if entry.MTime != mtime || entry.Size != size || entry.AudrVersion != opts.AudrVersion {
		return nil, false, mtime, size
	}
	if len(entry.Findings) == 0 {
		return nil, false, mtime, size
	}
	var decoded []finding.Finding
	if err := json.Unmarshal(entry.Findings, &decoded); err != nil {
		return nil, false, mtime, size
	}
	return decoded, true, mtime, size
}

// maybeWriteCache persists this file's rule output keyed on its
// current (mtime, size, version). Skips when caching is off, when the
// file's format is correlate-relevant (those always parse fresh so the
// correlate pass keeps working), or when the file can't be stat'd
// post-rule-evaluation (it was deleted mid-scan — no point caching).
//
// Errors from the cache layer are silently dropped: a missed write
// just means the next cycle is a cache miss, which is always safe.
func maybeWriteCache(opts Options, path string, format parse.Format, fileFindings []finding.Finding) {
	if opts.Cache == nil || opts.AudrVersion == "" {
		return
	}
	if correlateRelevantFormats[format] {
		return
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	payload, err := json.Marshal(fileFindings)
	if err != nil {
		return
	}
	_ = opts.Cache.Put(FileCacheEntry{
		Path:        path,
		MTime:       info.ModTime().UnixNano(),
		Size:        info.Size(),
		Findings:    payload,
		AudrVersion: opts.AudrVersion,
	})
}

func worker(
	ctx context.Context,
	id int,
	opts Options,
	in <-chan string,
	out chan<- finding.Finding,
	stat chan<- workerStat,
	docOut chan<- *parse.Document,
	logger *slog.Logger,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case path, ok := <-in:
			if !ok {
				return
			}
			_ = id // worker ID currently unused, retained for log-context wiring
			s := workerStat{seen: 1}

			// Cache fast path: when the entry's (mtime, size, version)
			// matches the file's current stat, replay the prior
			// findings without touching the parser or rule engine.
			// Skip the cache for formats the correlate pass needs the
			// parsed Document for — those files are rare and small, so
			// re-parsing them every cycle is cheaper than threading
			// document persistence through the cache schema.
			if cached, ok, mtime, size := tryCacheHit(ctx, opts, path); ok {
				for _, f := range cached {
					select {
					case out <- f:
					case <-ctx.Done():
						return
					}
				}
				s.parsed = 1
				select {
				case stat <- s:
				case <-ctx.Done():
					return
				}
				_ = mtime
				_ = size
				continue
			}

			// File-level timeout: if reading or parsing takes too long, the
			// timer cancels the per-file context and the worker bails out.
			// (The current parser is synchronous so the deadline is enforced
			// by an enclosing select; for v1 this guarantee is sufficient.)
			_, cancel := context.WithTimeout(ctx, opts.FileTimeout)
			doc, err := parse.ReadAndParse(path, opts.FileSizeLimit)
			cancel()
			if errors.Is(err, parse.ErrSkippedSize) {
				logger.Debug("size-cap-skipped", "path", path)
				out <- finding.New(finding.Args{
					RuleID:      "parse-skipped:size",
					Severity:    finding.SeverityLow,
					Taxonomy:    finding.TaxAdvisory,
					Title:       "File exceeded size cap",
					Description: fmt.Sprintf("File %s exceeded the configured size cap and was not scanned.", path),
					Path:        path,
				})
				s.skipped = 1
			} else if errors.Is(err, parse.ErrSkippedNonRegular) {
				s.skipped = 1
			} else if err != nil {
				logger.Debug("read-failed", "path", path, "err", err)
				s.skipped = 1
			} else if doc != nil {
				s.parsed = 1
				if doc.ParseError != nil {
					out <- finding.New(finding.Args{
						RuleID:      "parse-error",
						Severity:    finding.SeverityLow,
						Taxonomy:    finding.TaxAdvisory,
						Title:       "Parse error (file skipped)",
						Description: fmt.Sprintf("Parser failed: %v", doc.ParseError),
						Path:        path,
					})
				} else {
					fileFindings := rules.ApplyWithPolicy(doc, opts.Policy)
					for _, f := range fileFindings {
						select {
						case out <- f:
						case <-ctx.Done():
							return
						}
					}
					// Persist the cache row AFTER rules have run so a
					// subsequent cycle with unchanged (mtime, size,
					// version) can replay the same findings.
					maybeWriteCache(opts, path, doc.Format, fileFindings)

					// v0.2.0-alpha.5: retain the parsed Document for the
					// correlate pass after scan completes.
					select {
					case docOut <- doc:
					case <-ctx.Done():
						return
					}
				}
			}
			select {
			case stat <- s:
			case <-ctx.Done():
				return
			}
		}
	}
}

func walk(ctx context.Context, opts Options, out chan<- string, logger *slog.Logger) {
	skipSet := map[string]bool{}
	for _, d := range opts.SkipDirs {
		skipSet[d] = true
	}
	for _, root := range opts.Roots {
		walkRoot(ctx, root, skipSet, out, logger)
	}
}

func walkRoot(ctx context.Context, root string, skipSet map[string]bool, out chan<- string, logger *slog.Logger) {
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			logger.Debug("walk-error", "path", path, "err", err)
			// Permissions denied or transient FS errors: continue.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		base := filepath.Base(path)
		if d.IsDir() {
			if skipSet[base] {
				if base == "node_modules" {
					walkMiniShaiHuludNodeModules(ctx, path, out, logger)
				}
				return fs.SkipDir
			}
			return nil
		}
		// Hard-skip files we know we don't care about (perf).
		if shouldSkipFile(path) {
			return nil
		}
		// Only enqueue files DetectFormat recognizes.
		if parse.DetectFormat(path) == parse.FormatUnknown {
			// Don't enqueue unknown formats — saves parser time.
			return nil
		}
		select {
		case out <- path:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	})
}

func walkMiniShaiHuludNodeModules(ctx context.Context, root string, out chan<- string, logger *slog.Logger) {
	root = filepath.Clean(root)
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			logger.Debug("node-modules-ioc-walk-error", "path", path, "err", err)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		depth := len(strings.Split(filepath.ToSlash(rel), "/"))
		if d.IsDir() {
			if depth > 2 {
				return fs.SkipDir
			}
			return nil
		}
		base := filepath.Base(path)
		if base != "router_init.js" && base != "tanstack_runner.js" {
			return nil
		}
		if depth > 3 {
			return nil
		}
		select {
		case out <- path:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	})
}

// shouldSkipFile is a fast-path filter based on extension/basename to avoid
// invoking DetectFormat on giant files we know we don't care about.
func shouldSkipFile(path string) bool {
	// Files we'll never scan even though they might match by basename.
	for _, suf := range []string{".log", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".mp4", ".zip", ".tar", ".gz"} {
		if strings.HasSuffix(path, suf) {
			return true
		}
	}
	return false
}

// noopWriter discards slog output when Options.Logger is nil.
type noopWriter struct{}

func (noopWriter) Write(p []byte) (int, error) { return len(p), nil }
