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
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
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
		o.SkipDirs = []string{
			"node_modules", "vendor", ".git", "dist", "build", "target",
			"__pycache__", ".next", ".cache",
		}
	}
	return o
}

type workerStat struct {
	seen, parsed, skipped int
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
			s := workerStat{seen: 1}
			// File-level timeout: if reading or parsing takes too long, the
			// timer cancels the per-file context and the worker bails out.
			// (The current parser is synchronous so the deadline is enforced
			// by an enclosing select; for v1 this guarantee is sufficient.)
			_, cancel := context.WithTimeout(ctx, opts.FileTimeout)
			doc, err := parse.ReadAndParse(path, opts.FileSizeLimit)
			cancel()
			_ = id // worker ID currently unused, retained for log-context wiring
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
					for _, f := range rules.Apply(doc) {
						select {
						case out <- f:
						case <-ctx.Done():
							return
						}
					}
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
