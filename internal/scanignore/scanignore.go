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
	"strings"
)

// Defaults returns the canonical list of path-segments audr skips during
// recursive scans. Each entry is either:
//
//   - a single-segment basename ("node_modules") matched against any
//     path component, OR
//   - a multi-segment relative path ("go/pkg", ".cargo/registry")
//     matched as a contiguous subsequence of path components.
//
// New entries belong here, not in scattered constants across scanners.
// Single-segment entries are checked with O(1) per dir during a walk;
// multi-segment entries with PathExcluded() which does a path-component
// subsequence match.
func Defaults() []string {
	return []string{
		// Build artifacts / vendored / VCS metadata.
		// Parity with internal/scan/scan.go skip list.
		"node_modules",
		"vendor",
		".git",
		"dist",
		"build",
		"target",
		"__pycache__",
		".next",
		".cache",

		// Python virtualenvs.
		".venv",
		"venv",

		// Per-language tool caches at $HOME root. These are top-level
		// dirs that are 100%-cache: skipping them whole is safe (the
		// user's actual code lives in ~/code or ~/projects, not in
		// these tool-internal dirs).
		".bun",         // Bun's install cache + globals
		".pnpm-store",  // pnpm global content-addressed cache
		".yarn",        // Yarn's cache + global/install state
		".deno",        // Deno's module cache
		".gem",         // RubyGems user cache
		".m2",          // Maven local repository
		".gradle",      // Gradle build + dependency cache
		".cargo",       // Rust crates cache (registry + git + bin)

		// Multi-segment cache paths (sub-paths within larger dirs the
		// user might legitimately also have CODE in — e.g., ~/go has
		// both pkg/mod (cache) AND src (potentially user repos)).
		"go/pkg",                       // Go module cache
		".npm/_cacache",                // npm install cache (keep .npm/global)
		".gradle/caches",               // explicit second match in case .gradle isn't matched at root
		"Library/Caches",               // macOS user caches
		"AppData/Local/Temp",           // Windows user temp
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

// PathExcluded reports whether the given path contains any of the
// Defaults() entries as path-component subsequences. Used by walkers
// to skip cache trees, build artifacts, and VCS metadata before
// descending into them.
//
// Single-segment entries (e.g., "node_modules") match if any path
// component equals them. Multi-segment entries (e.g., "go/pkg") match
// if their components appear contiguously somewhere in the path.
//
// Path is normalized to forward-slash separators before matching, so
// Windows-style paths work identically.
func PathExcluded(path string) bool {
	if path == "" {
		return false
	}
	segs := splitPathSegments(path)
	for _, entry := range Defaults() {
		entrySegs := splitPathSegments(entry)
		if len(entrySegs) == 0 {
			continue
		}
		if containsSegmentSubsequence(segs, entrySegs) {
			return true
		}
	}
	return false
}

// IsExcludedBaseName is the fast-path check: returns true iff the
// given basename matches any single-segment entry in Defaults(). Use
// this in walk callbacks where you only have the directory's
// basename without computing the full path.
//
// Multi-segment entries (e.g., "go/pkg", ".cargo/registry") return
// false here — callers that need them must use PathExcluded() with
// the full path.
func IsExcludedBaseName(name string) bool {
	for _, entry := range Defaults() {
		if !strings.ContainsRune(entry, '/') && entry == name {
			return true
		}
	}
	return false
}

// splitPathSegments normalizes a path to forward slashes and splits
// it into non-empty components.
func splitPathSegments(p string) []string {
	// Convert backslashes to slashes for Windows paths.
	p = strings.ReplaceAll(p, `\`, "/")
	parts := strings.Split(p, "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// containsSegmentSubsequence reports whether needle appears as a
// contiguous subsequence of haystack. Pure component matching, not
// substring: ["foo","bar","baz"] contains ["bar","baz"] but not
// ["bar","ba"].
func containsSegmentSubsequence(haystack, needle []string) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		ok := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
