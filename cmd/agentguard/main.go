// agentguard is a static-analysis scanner for AI-agent configurations.
//
// Wedge: discover MCP servers, Claude Code skills, Cursor configs, agent
// instruction docs, and GitHub Actions workflows on a developer machine or in
// a repo. Compare findings against a built-in policy. Emit SARIF / HTML /
// JSON reports.
//
// See https://agentguard.dev for the full design doc.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	_ "github.com/agentguard/agentguard/internal/rules/builtin"
	"github.com/agentguard/agentguard/internal/output"
	"github.com/agentguard/agentguard/internal/scan"
	"github.com/agentguard/agentguard/internal/suppress"
	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags "-X main.Version=...".
var Version = "0.0.0-dev"

func main() {
	root := newRootCmd()
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "agentguard",
		Short:         "Static-analysis scanner for AI-agent configurations",
		Long:          `agentguard scans MCP servers, agent skills, Claude/Cursor configs, agent instruction docs, and GitHub Actions workflows for risky configuration. It is offline-by-default and emits HTML, SARIF, and JSON reports.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       Version,
	}
	cmd.AddCommand(newScanCmd())
	cmd.AddCommand(newVersionCmd())
	return cmd
}

func newScanCmd() *cobra.Command {
	var (
		flagOutput     string
		flagFormat     string
		flagJobs       int
		flagFileTimeout time.Duration
		flagScanTimeout time.Duration
		flagSizeLimit  int64
		flagIgnore     string
		flagVerbose    bool
		flagDebug      bool
		flagLogJSON    bool
	)
	cmd := &cobra.Command{
		Use:   "scan [path...]",
		Short: "Scan paths for risky AI-agent configurations",
		Long: `Scan one or more paths (default: $HOME) for risky AI-agent configurations.

Without arguments, agentguard scans your machine: $HOME for MCP configs,
skill files, shell rc files, etc. Pass a directory to scan a single repo.

The exit code is 0 when no findings of severity higher than 'low' are
emitted, 1 otherwise. Use --output to write the report to a file instead
of stdout.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(scanFlags{
				roots:       args,
				output:      flagOutput,
				format:      flagFormat,
				jobs:        flagJobs,
				fileTimeout: flagFileTimeout,
				scanTimeout: flagScanTimeout,
				sizeLimit:   flagSizeLimit,
				ignore:      flagIgnore,
				verbose:     flagVerbose,
				debug:       flagDebug,
				logJSON:     flagLogJSON,
			})
		},
	}
	cmd.Flags().StringVarP(&flagOutput, "output", "o", "", "write report to file (default: stdout)")
	cmd.Flags().StringVarP(&flagFormat, "format", "f", "html", "report format: html | sarif | json")
	cmd.Flags().IntVar(&flagJobs, "jobs", 0, "worker pool size (default: GOMAXPROCS)")
	cmd.Flags().DurationVar(&flagFileTimeout, "file-timeout", 5*time.Second, "per-file parse + rule timeout")
	cmd.Flags().DurationVar(&flagScanTimeout, "scan-timeout", 60*time.Second, "total scan timeout")
	cmd.Flags().Int64Var(&flagSizeLimit, "file-size-limit", 10<<20, "skip files larger than this byte size")
	cmd.Flags().StringVar(&flagIgnore, "ignore-file", "", "path to .agentguardignore (default: ./.agentguardignore if present)")
	cmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "log INFO messages to stderr")
	cmd.Flags().BoolVar(&flagDebug, "debug", false, "log DEBUG messages to stderr")
	cmd.Flags().BoolVar(&flagLogJSON, "log-json", false, "emit logs as JSON instead of text")
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "agentguard %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
		},
	}
}

type scanFlags struct {
	roots       []string
	output      string
	format      string
	jobs        int
	fileTimeout time.Duration
	scanTimeout time.Duration
	sizeLimit   int64
	ignore      string
	verbose     bool
	debug       bool
	logJSON     bool
}

func runScan(f scanFlags) error {
	logger := buildLogger(f)

	roots := f.roots
	if len(roots) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("could not determine $HOME: %w", err)
		}
		roots = []string{home}
		logger.Info("scanning $HOME (no path arg)", "home", home)
	} else {
		// Expand ~ in user-provided roots.
		for i, r := range roots {
			if strings.HasPrefix(r, "~/") || r == "~" {
				home, _ := os.UserHomeDir()
				roots[i] = filepath.Join(home, strings.TrimPrefix(r, "~"))
			}
		}
	}

	// Load suppression file.
	ignorePath := f.ignore
	if ignorePath == "" {
		// Default: look for .agentguardignore in the first root if it's a dir.
		candidate := filepath.Join(roots[0], ".agentguardignore")
		if _, err := os.Stat(candidate); err == nil {
			ignorePath = candidate
		}
	}
	var supp *suppress.Set
	if ignorePath != "" {
		s, err := suppress.LoadFile(ignorePath)
		if err != nil {
			return fmt.Errorf("load ignore: %w", err)
		}
		supp = s
		logger.Info("loaded suppression file", "path", ignorePath)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	res, scanErr := scan.Run(ctx, scan.Options{
		Roots:         roots,
		Workers:       f.jobs,
		FileTimeout:   f.fileTimeout,
		FileSizeLimit: f.sizeLimit,
		ScanTimeout:   f.scanTimeout,
		Suppress:      supp,
		Logger:        logger,
	})
	if scanErr != nil {
		// scan.Run returns partial Result on timeout; report it anyway.
		fmt.Fprintf(os.Stderr, "warning: %v\n", scanErr)
	}

	report := output.Report{
		Findings:    res.Findings,
		Roots:       roots,
		StartedAt:   res.StartedAt,
		FinishedAt:  res.FinishedAt,
		FilesSeen:   res.FilesSeen,
		FilesParsed: res.FilesParsed,
		Suppressed:  res.Suppressed,
		Skipped:     res.Skipped,
		Version:     Version,
		SelfAudit:   "skipped", // populated when self-audit subcommand lands
	}

	out := io.Writer(os.Stdout)
	if f.output != "" {
		of, err := os.Create(f.output)
		if err != nil {
			return fmt.Errorf("create output: %w", err)
		}
		defer of.Close()
		out = of
	}

	switch strings.ToLower(f.format) {
	case "", "html":
		if err := output.HTML(out, report); err != nil {
			return err
		}
	case "sarif":
		if err := output.SARIF(out, report); err != nil {
			return err
		}
	case "json":
		if err := output.JSON(out, report); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q (want html | sarif | json)", f.format)
	}

	// Summary to stderr regardless of format.
	summarize(res, logger, f.output)

	// Exit code: 0 if zero high-or-critical findings, else 1.
	for _, fnd := range res.Findings {
		if fnd.Severity <= 1 { // Critical=0, High=1
			os.Exit(1)
		}
	}
	return nil
}

func summarize(res *scan.Result, logger *slog.Logger, outPath string) {
	by := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, f := range res.Findings {
		by[f.Severity.String()]++
	}
	dest := "stdout"
	if outPath != "" {
		dest = outPath
	}
	fmt.Fprintf(os.Stderr,
		"agentguard: %d findings (%d critical, %d high, %d medium, %d low) in %d files (%s) → %s\n",
		len(res.Findings),
		by["critical"], by["high"], by["medium"], by["low"],
		res.FilesParsed,
		res.FinishedAt.Sub(res.StartedAt).Round(time.Millisecond),
		dest,
	)
	logger.Debug("scan complete",
		"findings", len(res.Findings),
		"files_parsed", res.FilesParsed,
		"files_seen", res.FilesSeen,
		"suppressed", res.Suppressed,
		"skipped", res.Skipped,
	)
}

func buildLogger(f scanFlags) *slog.Logger {
	level := slog.LevelWarn
	if f.verbose {
		level = slog.LevelInfo
	}
	if f.debug {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if f.logJSON {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(h)
}
