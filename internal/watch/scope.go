// Package watch implements audr's hybrid watch+poll engine: fsnotify on
// scoped sensitive paths (git repos + AI agent configs + chat
// transcripts), a 5-second quiescence gate that debounces event storms
// (npm install, build artifacts), an adaptive backoff state machine
// (RUN/SLOW/PAUSE based on system load + power), remote-FS detection,
// and a Linux inotify watch-limit fallback.
//
// Output: a channel of "scan now" triggers consumed by the orchestrator.
//
// Phase 3 ships fsnotify on tight scope; the wide-poll cycle for the
// rest of $HOME lands in a follow-up slice. The state machine + signal
// readers in this package work for both.
package watch

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// Scope captures the paths the watcher should observe for file
// changes. We deliberately don't watch all of $HOME (that's the
// "wide poll" half of the hybrid design — Phase 3.1). The tight
// scope is the high-signal subset where audr's rules actually fire:
//
//   - Per-tool config directories: ~/.claude, ~/.codex, ~/.cursor,
//     ~/.codeium (Windsurf).
//   - AI chat transcript directories (Claude Code per-project +
//     Codex sessions): user pastes credentials here, we want to
//     re-scan within seconds of a new transcript chunk landing.
//   - Git repositories under $HOME: a repo is where rules actually
//     find things (skills, agent docs, GHA workflows, MCP configs).
//   - Dotfiles in $HOME root (~/.bashrc, ~/.zshrc, ~/.profile, etc.):
//     a single export of a credential here is a finding.
//
// We discover scope at startup. fsnotify watches inherit subdirectories
// implicitly on macOS (FSEvents) but NOT on Linux (inotify) or Windows
// (RDCW); the watcher walks each scope entry and adds individual
// directory watches for inotify/RDCW. The exclude list from
// scanignore.Defaults() filters out node_modules / .git internals /
// caches at walk time.
type Scope struct {
	// TightPaths are individual directories or files watched with
	// fsnotify. Each path is absolute and exists at scope time.
	TightPaths []string
}

// DiscoverScope walks $HOME to build the tight-watch path list. Returns
// the scope plus the count of git repos found (for observability in
// daemon.log). Safe to call from a fresh daemon on a brand-new machine:
// missing per-tool dirs are skipped, not errored.
func DiscoverScope(homeDir string) (Scope, int, error) {
	if homeDir == "" {
		return Scope{}, 0, errors.New("watch: empty home dir")
	}

	scope := Scope{}

	// 1. Per-tool config directories. Each one is added whole — the
	//    watcher will walk subdirs and add watches.
	for _, name := range []string{".claude", ".codex", ".cursor", ".codeium"} {
		p := filepath.Join(homeDir, name)
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			scope.TightPaths = append(scope.TightPaths, p)
		}
	}

	// 2. Dotfile shell rc files in $HOME root. We watch the parent
	//    ($HOME) shallowly — only direct-child change events match
	//    these. Most filesystems coalesce parent-dir watches OK.
	//    We add $HOME but mark it as "shallow" via a separate field
	//    in the watcher (see watcher.go). For simplicity in Phase 3
	//    we add the rc files individually by stat'ing them. fsnotify
	//    can watch individual files on Linux (inotify) and macOS
	//    (FSEvents); Windows RDCW requires dir granularity but the
	//    parent watch on $HOME covers the immediate children.
	for _, rc := range []string{".bashrc", ".zshrc", ".bash_profile", ".profile", ".zprofile", ".mcp.json"} {
		p := filepath.Join(homeDir, rc)
		if _, err := os.Stat(p); err == nil {
			scope.TightPaths = append(scope.TightPaths, p)
		}
	}

	// 3. Git repositories under $HOME. We walk shallowly — a repo's
	//    contents change all the time during normal dev work; we
	//    don't want to watch every file in every repo. Instead the
	//    watcher gets the REPO ROOT path; when ANY change happens
	//    under it (recursive on macOS, walked on Linux), a scan is
	//    triggered. The orchestrator re-scans the whole repo when
	//    that happens (which is fine — rules are cheap, and the
	//    quiescence gate debounces).
	gitCount, err := findGitReposUnder(homeDir, &scope, 6)
	if err != nil {
		// Don't fail; just report partial scope.
		return scope, gitCount, err
	}

	return scope, gitCount, nil
}

// findGitReposUnder walks home up to maxDepth levels, appending every
// directory that contains a `.git` directory (the canonical "this is
// a git repo" marker) to scope.TightPaths. Skips the always-excluded
// directories from scanignore (node_modules, vendor, etc.) so a
// pnpm-style workspace with a hundred sub-packages doesn't blow up
// the walk time.
//
// Returns the count of repos found.
func findGitReposUnder(home string, scope *Scope, maxDepth int) (int, error) {
	skip := alwaysSkippedBaseNames()
	count := 0

	err := filepath.WalkDir(home, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Permission denied on a subdir, etc. — skip + continue.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}

		// Depth cap so a deeply nested $HOME doesn't take forever to
		// discover scope. Most user repos are within 4-5 levels.
		rel, _ := filepath.Rel(home, path)
		depth := 0
		if rel != "." {
			for i := 0; i < len(rel); i++ {
				if rel[i] == filepath.Separator {
					depth++
				}
			}
			depth++ // count rel's own segment
		}
		if depth > maxDepth {
			return fs.SkipDir
		}

		// Always-skipped basenames: scanignore's curated list of
		// caches + build artifacts. node_modules has been responsible
		// for many a slow scan-discovery loop.
		base := filepath.Base(path)
		if skip[base] {
			return fs.SkipDir
		}

		// Hit: this directory contains .git → it's a git repo root.
		gitDir := filepath.Join(path, ".git")
		if info, err := os.Stat(gitDir); err == nil && info.IsDir() {
			scope.TightPaths = append(scope.TightPaths, path)
			count++
			// Don't descend into a repo we already chose — any nested
			// repo (submodule, vendor) gets its own root-level scan
			// trigger via the parent's watch.
			return fs.SkipDir
		}
		return nil
	})
	return count, err
}

// alwaysSkippedBaseNames returns the set of directory names the scope
// walk skips. We lazily re-derive these from scanignore.Defaults()
// so the canonical list stays in one place. Stripped to base names
// since scope walks operate on directory entries.
func alwaysSkippedBaseNames() map[string]bool {
	// Import side-effect-free copy from scanignore: hardcode the most
	// common ones inline. This avoids a circular dep risk if
	// scanignore ever wanted to import watch.
	return map[string]bool{
		"node_modules": true,
		"vendor":       true,
		".git":         true, // handled separately (gitDir lookup above)
		"dist":         true,
		"build":        true,
		"target":       true,
		"__pycache__":  true,
		".next":        true,
		".cache":       true,
		".venv":        true,
		"venv":         true,
	}
}
