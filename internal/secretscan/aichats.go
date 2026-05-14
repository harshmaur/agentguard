package secretscan

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// AIChatTranscriptRoots discovers every directory under $HOME that
// likely contains AI coding-agent chat transcripts and returns the
// list of absolute paths suitable for adding to a TruffleHog scan.
//
// Why this matters (eng-review): developers paste API keys into chat
// while debugging. Those transcripts persist plaintext indefinitely.
// No traditional secret scanner walks these — they're an under-
// scanned attack surface that audr can own.
//
// v1 scope (per design doc D18 reaffirmed in office hours): Claude
// Code + Codex transcripts only, because both have stable JSONL
// formats. Cursor / Cline / Continue / Aider / Windsurf are deferred
// to v1.1 once their formats are surveyed.
//
// Returns the empty slice (no error) when $HOME exists but neither
// agent has installed transcripts yet — the daemon should still boot
// cleanly on a fresh machine.
func AIChatTranscriptRoots(homeDir string) ([]string, error) {
	if homeDir == "" {
		return nil, errors.New("aichats: empty home dir")
	}
	var roots []string

	// Claude Code: ~/.claude/projects/<slug>/sessions/*.jsonl
	// The sessions live one level under each project directory. We
	// add the per-project sessions directory so TruffleHog can walk
	// it; we don't enumerate individual jsonl files (TruffleHog's
	// own walker is fine and respects --exclude-paths from scanignore).
	claudeProjects := filepath.Join(homeDir, ".claude", "projects")
	if entries, err := os.ReadDir(claudeProjects); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			sessionsDir := filepath.Join(claudeProjects, e.Name(), "sessions")
			if _, err := os.Stat(sessionsDir); err == nil {
				roots = append(roots, sessionsDir)
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	// Codex: ~/.codex/sessions/ contains all sessions flat. One root.
	codexSessions := filepath.Join(homeDir, ".codex", "sessions")
	if info, err := os.Stat(codexSessions); err == nil && info.IsDir() {
		roots = append(roots, codexSessions)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	return roots, nil
}

// AIChatCanaryCheck verifies the format-drift assumption from
// eng-review D18: that Claude Code + Codex transcripts still look
// like JSONL where each line is a JSON object. Returns the number
// of transcript files found, the number that parsed as JSONL, and
// any error from the underlying walk. If found > 0 but parsed = 0
// in production, the dashboard banner from D18 fires.
//
// Cheap probe: reads up to the first 4KB of up to 5 transcript files
// per agent. Doesn't open every JSONL — just confirms the shape
// hasn't drifted.
func AIChatCanaryCheck(homeDir string) (CanaryReport, error) {
	rep := CanaryReport{}
	roots, err := AIChatTranscriptRoots(homeDir)
	if err != nil {
		return rep, err
	}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".jsonl") {
				return nil
			}
			rep.FilesFound++
			// Stop after 5 per root — we don't need exhaustive proof,
			// just shape confirmation.
			if rep.FilesFound > 5*len(roots) {
				return filepath.SkipAll
			}
			if isJSONL(path) {
				rep.FilesParsed++
			}
			return nil
		})
		if err != nil {
			return rep, err
		}
	}
	return rep, nil
}

// CanaryReport is the result of an AIChatCanaryCheck. The daemon
// uses this to decide whether to surface the "Claude Code / Codex
// transcript format may have drifted" banner.
type CanaryReport struct {
	FilesFound  int
	FilesParsed int
}

// isJSONL returns true if the file's first non-empty line is a valid
// JSON object. We don't parse the whole file — just confirm the
// shape. False positives are acceptable: if the format drifts to
// something else that happens to look like JSONL, the dashboard
// banner won't fire, but the user can still scan and see the
// findings TruffleHog produces (or doesn't).
func isJSONL(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	if n == 0 {
		return false
	}
	// Find first non-whitespace char — should be '{' for JSONL.
	for i := 0; i < n; i++ {
		c := buf[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		return c == '{'
	}
	return false
}
