// agentguard is a static-analysis scanner for AI-agent configurations.
//
// Wedge: discover MCP servers, Claude Code skills, Cursor configs, agent
// instruction docs, and GitHub Actions workflows on a developer machine or in
// a repo. Compare findings against a built-in policy. Emit SARIF / HTML /
// JSON reports.
//
// See https://github.com/harshmaur/agentguard for source + design doc.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/harshmaur/agentguard/internal/correlate"
	"github.com/harshmaur/agentguard/internal/finding"
	"github.com/harshmaur/agentguard/internal/output"
	_ "github.com/harshmaur/agentguard/internal/rules/builtin"
	"github.com/harshmaur/agentguard/internal/scan"
	"github.com/harshmaur/agentguard/internal/suppress"
	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags "-X main.Version=...".
var Version = "0.0.0-dev"

func main() {
	root := newRootCmd()
	err := root.Execute()
	if err == nil {
		return
	}
	// Findings-present and verify-failed are successful runs with non-zero
	// exit. The subcommand already showed the user the verdict — printing
	// "agentguard: findings present" on top would be noise.
	if errors.Is(err, errFindingsPresent) || errors.Is(err, errVerifyFailed) {
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "agentguard: %v\n", err)
	os.Exit(1)
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
	cmd.AddCommand(newVerifyCmd())
	cmd.AddCommand(newSelfAuditCmd())
	cmd.AddCommand(newVersionCmd())
	return cmd
}

func newScanCmd() *cobra.Command {
	var (
		flagOutput      string
		flagFormat      string
		flagJobs        int
		flagFileTimeout time.Duration
		flagScanTimeout time.Duration
		flagSizeLimit   int64
		flagIgnore      string
		flagVerbose     bool
		flagDebug       bool
		flagLogJSON     bool
		flagOpen        string // "auto" | "always" | "never"
		flagQuiet       bool
	)
	cmd := &cobra.Command{
		Use:   "scan [path...]",
		Short: "Scan paths for risky AI-agent configurations",
		Long: `Scan one or more paths (default: $HOME) for risky AI-agent configurations.

By default agentguard writes an HTML report to a temp file, opens it in your
default browser, and prints a readable summary to stdout.

Use -o to write the report to a specific file (browser auto-open is then off
by default; use --open=always to override). Use -f sarif|json to emit
machine-readable formats. Use -o - to stream the format output to stdout
(useful for piping into jq).

Exit code is 0 when no findings of severity higher than 'low' are emitted,
1 otherwise.`,
		Example: `  agentguard scan                              # scan $HOME, open HTML in browser
  agentguard scan ~/code/my-repo               # scan a single repo
  agentguard scan -o report.html               # write to a specific file
  agentguard scan -f sarif -o results.sarif    # SARIF for GitHub Code Scanning
  agentguard scan -f json -o - | jq            # pipe JSON to jq`,
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
				openMode:    flagOpen,
				quiet:       flagQuiet,
			})
		},
	}
	cmd.Flags().StringVarP(&flagOutput, "output", "o", "", "write report to file (default: HTML to temp file + browser; sarif/json to stdout). Use '-' to force stdout.")
	cmd.Flags().StringVarP(&flagFormat, "format", "f", "html", "report format: html | sarif | json")
	cmd.Flags().StringVar(&flagOpen, "open", "auto", "open HTML report in browser: auto | always | never")
	cmd.Flags().BoolVarP(&flagQuiet, "quiet", "q", false, "suppress the readable summary on stdout")
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
	openMode    string // "auto" | "always" | "never"
	quiet       bool
}

// outPlan captures the resolved output decisions: where the report goes,
// where the human-readable summary goes, and whether to open a browser.
type outPlan struct {
	format        string // "html" | "sarif" | "json"
	reportPath    string // file path; "" if writing to stdout
	reportToStdout bool
	printSummary  bool
	summaryDest   io.Writer // os.Stdout or os.Stderr
	openBrowser   bool
}

func resolveOutput(f scanFlags) (outPlan, error) {
	format := strings.ToLower(strings.TrimSpace(f.format))
	if format == "" {
		format = "html"
	}
	if format != "html" && format != "sarif" && format != "json" {
		return outPlan{}, fmt.Errorf("unknown format %q (want html | sarif | json)", f.format)
	}
	// Validate openMode up-front so a bad value can't influence routing
	// in the switch below.
	switch f.openMode {
	case "auto", "always", "never":
		// ok
	default:
		return outPlan{}, fmt.Errorf("--open must be auto | always | never (got %q)", f.openMode)
	}

	stdoutTTY := isTerminal(os.Stdout)

	plan := outPlan{format: format}

	switch {
	case f.output == "-":
		// Explicit pipe-to-stdout escape hatch.
		plan.reportToStdout = true
		plan.printSummary = false
		plan.openBrowser = false

	case f.output != "":
		// User picked a path. Write the report there. Summary goes to stdout.
		plan.reportPath = f.output
		plan.printSummary = !f.quiet
		plan.summaryDest = os.Stdout
		plan.openBrowser = format == "html" && f.openMode == "always" && stdoutTTY

	case format == "html":
		// HTML format never auto-dumps to stdout — that ruins terminals.
		// Always write to a temp file. Use `-o -` for the explicit pipe
		// escape hatch. Browser auto-opens if stdout is a TTY (i.e., a
		// human is watching) and --open isn't set to never.
		tmp := filepath.Join(os.TempDir(), fmt.Sprintf("agentguard-%s.html", time.Now().Format("20060102-150405")))
		plan.reportPath = tmp
		plan.printSummary = !f.quiet
		plan.summaryDest = os.Stdout
		plan.openBrowser = stdoutTTY && f.openMode != "never"

	default:
		// sarif/json without -o: write the format to stdout (data IS the
		// output). Summary goes to stderr so a pipe still gets clean data.
		plan.reportToStdout = true
		plan.printSummary = !f.quiet && stdoutTTY
		plan.summaryDest = os.Stderr
		plan.openBrowser = false
	}

	if f.openMode == "never" {
		plan.openBrowser = false
	}

	return plan, nil
}

func runScan(f scanFlags) error {
	logger := buildLogger(f)

	plan, err := resolveOutput(f)
	if err != nil {
		return err
	}

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

	// v0.2.0-alpha.5: cross-finding correlation pass produces Attack Chain
	// narratives that render at the top of the report.
	chains := correlate.Run(res.Findings, res.Documents)

	report := output.Report{
		Findings:     res.Findings,
		AttackChains: chains,
		Roots:        roots,
		StartedAt:    res.StartedAt,
		FinishedAt:   res.FinishedAt,
		FilesSeen:    res.FilesSeen,
		FilesParsed:  res.FilesParsed,
		Suppressed:   res.Suppressed,
		Skipped:      res.Skipped,
		Version:      Version,
		SelfAudit:    "skipped",
	}

	// Write the format output to its destination.
	if err := writeReport(plan, report); err != nil {
		return err
	}

	// Print readable summary.
	if plan.printSummary {
		htmlPath := ""
		if plan.format == "html" && plan.reportPath != "" {
			htmlPath = plan.reportPath
		}
		if err := output.Text(plan.summaryDest, report, htmlPath); err != nil {
			return err
		}
	}

	// Open browser if applicable.
	if plan.openBrowser && plan.reportPath != "" {
		if err := openBrowser(plan.reportPath); err != nil {
			// Non-fatal; user can open manually.
			fmt.Fprintf(os.Stderr, "agentguard: could not open browser (%v); open %s manually\n",
				err, plan.reportPath)
		}
	}

	// Exit code: 1 if any high-or-critical finding fires. Return the sentinel
	// instead of os.Exit so deferred cleanup (signal-context cancel, output
	// file Close on writeReport's defer) all run before the process exits.
	for _, fnd := range res.Findings {
		if fnd.Severity == finding.SeverityCritical || fnd.Severity == finding.SeverityHigh {
			return errFindingsPresent
		}
	}
	return nil
}

// errFindingsPresent signals a successful scan that found high-or-critical
// findings. main() detects this and exits with code 1 instead of returning
// an error message to stderr.
var errFindingsPresent = errors.New("findings present")

// writeReport emits the chosen format to either stdout or a file path.
func writeReport(plan outPlan, report output.Report) error {
	var w io.Writer
	if plan.reportToStdout {
		w = os.Stdout
	} else if plan.reportPath != "" {
		f, err := os.Create(plan.reportPath)
		if err != nil {
			return fmt.Errorf("create %s: %w", plan.reportPath, err)
		}
		defer f.Close()
		w = f
	} else {
		// Both empty — nothing to write. Should not happen.
		return errors.New("no report destination resolved")
	}

	switch plan.format {
	case "html":
		return output.HTML(w, report)
	case "sarif":
		return output.SARIF(w, report)
	case "json":
		return output.JSON(w, report)
	}
	return fmt.Errorf("unknown format %q", plan.format)
}

// isTerminal returns true if f is connected to a terminal (vs. a pipe/file).
// We avoid pulling in golang.org/x/term to keep the binary's dependency
// surface minimal; the os.Stat trick works on Unix and Windows.
func isTerminal(f *os.File) bool {
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

// openBrowser launches the platform's default opener with the file URL.
// We deliberately do NOT block on the opener — terminals shouldn't hang
// waiting for the browser.
func openBrowser(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	url := "file://" + abs

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		// Prefer xdg-open. WSL has wslview. Fall back to xdg-open and let
		// it error.
		opener := "xdg-open"
		if _, err := exec.LookPath("wslview"); err == nil {
			opener = "wslview"
		}
		cmd = exec.Command(opener, url)
	default:
		return fmt.Errorf("auto-open not supported on %s", runtime.GOOS)
	}
	// Detach: don't block, don't tie stdio.
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return err
	}
	// Reap the process in the background so it doesn't become a zombie.
	go func() { _ = cmd.Wait() }()
	return nil
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
