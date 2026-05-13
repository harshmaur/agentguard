// Package scanignore owns the canonical list of directory path-segments
// audr never scans.
//
// Two consumers today:
//
//   - audr's native walker (internal/scan) — passes these as base-name skips.
//   - TruffleHog shell-outs (internal/secretscan) — materialized to a regex
//     pattern file passed via `--exclude-paths`.
//
// Centralizing here avoids drift between the two surfaces. When the daemon
// (Phase 1+) lands, the watch+poll engine and OS-pkg enumerator also consume
// these via Defaults().
package scanignore

import (
	"fmt"
	"os"
	"regexp"
)

// Defaults returns the canonical list of path-segments audr skips during
// recursive scans. Each entry is a directory-name pattern (single segment
// or relative path under $HOME) that is never the legitimate target of a
// security scan: build artifacts, vendored code, VCS metadata, and
// per-language / per-OS cache roots.
//
// New entries belong here, not in scattered constants across scanners.
func Defaults() []string {
	return []string{
		// Build artifacts / vendored / VCS metadata
		// (parity with internal/scan/scan.go skip list)
		"node_modules",
		"vendor",
		".git",
		"dist",
		"build",
		"target",
		"__pycache__",
		".next",
		".cache",

		// Per-language tool caches and virtual envs under $HOME
		".venv",
		"venv",
		".npm/_cacache",
		".cargo/registry",
		"go/pkg",
		".gradle/caches",

		// Per-OS cache roots under $HOME
		"Library/Caches",                       // macOS user caches
		"AppData/Local/Temp",                   // Windows user temp
		"AppData/Local/Microsoft/Windows/INetCache",
	}
}

// WriteTruffleHogExcludeFile materializes Defaults() into a tempfile in the
// format TruffleHog's `--exclude-paths` expects: one regex pattern per line,
// matched anywhere in the candidate path. Returns the tempfile path and a
// cleanup func the caller MUST call (typically via defer).
//
// Each Defaults() entry becomes a regex of the form
// `(?:^|/)<escaped-segment>(?:/|$)` so that the pattern matches the segment
// as a real path component, not as a substring (e.g., `node_modules` matches
// `./node_modules/foo` but not `node_modules.lock`).
func WriteTruffleHogExcludeFile() (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "audr-trufflehog-exclude-*.txt")
	if err != nil {
		return "", nil, fmt.Errorf("create trufflehog exclude tempfile: %w", err)
	}
	cleanup = func() {
		_ = os.Remove(f.Name())
	}
	defer f.Close()

	for _, segment := range Defaults() {
		pattern := patternForSegment(segment)
		if _, err := f.WriteString(pattern + "\n"); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("write trufflehog exclude pattern: %w", err)
		}
	}

	return f.Name(), cleanup, nil
}

// patternForSegment converts a Defaults() entry into a TruffleHog-compatible
// regex pattern that matches the segment as a path component.
func patternForSegment(segment string) string {
	return `(?:^|/)` + regexp.QuoteMeta(segment) + `(?:/|$)`
}
