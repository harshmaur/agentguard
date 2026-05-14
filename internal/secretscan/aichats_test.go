package secretscan

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestAIChatTranscriptRootsFindsClaudeAndCodex(t *testing.T) {
	home := t.TempDir()

	// Plant Claude Code's layout: ~/.claude/projects/<slug>/sessions/
	must(t, os.MkdirAll(filepath.Join(home, ".claude", "projects", "audr-saas", "sessions"), 0o700))
	must(t, os.MkdirAll(filepath.Join(home, ".claude", "projects", "other-repo", "sessions"), 0o700))
	// And one project with NO sessions dir — must be skipped, not erred.
	must(t, os.MkdirAll(filepath.Join(home, ".claude", "projects", "untouched"), 0o700))

	// Codex's layout: ~/.codex/sessions/
	must(t, os.MkdirAll(filepath.Join(home, ".codex", "sessions"), 0o700))

	got, err := AIChatTranscriptRoots(home)
	if err != nil {
		t.Fatalf("AIChatTranscriptRoots: %v", err)
	}
	sort.Strings(got)

	want := []string{
		filepath.Join(home, ".claude", "projects", "audr-saas", "sessions"),
		filepath.Join(home, ".claude", "projects", "other-repo", "sessions"),
		filepath.Join(home, ".codex", "sessions"),
	}
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("got %d roots, want %d:\n  got=%v\n  want=%v", len(got), len(want), got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("roots[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestAIChatTranscriptRootsHandlesMissingDirectories(t *testing.T) {
	// Brand-new $HOME — no agent dirs exist. Should return empty, no error.
	home := t.TempDir()
	got, err := AIChatTranscriptRoots(home)
	if err != nil {
		t.Fatalf("expected nil err on fresh home, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 roots on fresh home, got %d: %v", len(got), got)
	}
}

func TestAIChatTranscriptRootsRejectsEmptyHome(t *testing.T) {
	if _, err := AIChatTranscriptRoots(""); err == nil {
		t.Fatal("expected error on empty home")
	}
}

func TestAIChatCanaryCheckCountsAndParses(t *testing.T) {
	home := t.TempDir()
	codexSessions := filepath.Join(home, ".codex", "sessions")
	must(t, os.MkdirAll(codexSessions, 0o700))

	// One JSONL-looking file.
	must(t, os.WriteFile(
		filepath.Join(codexSessions, "2026-05-13.jsonl"),
		[]byte(`{"role":"user","content":"hi"}`+"\n"),
		0o600,
	))
	// One non-JSONL (looks like a regular json file).
	must(t, os.WriteFile(
		filepath.Join(codexSessions, "bogus.jsonl"),
		[]byte(`[1,2,3]`),
		0o600,
	))
	// Non-jsonl extension — must be ignored.
	must(t, os.WriteFile(
		filepath.Join(codexSessions, "readme.md"),
		[]byte(`# notes`),
		0o600,
	))

	rep, err := AIChatCanaryCheck(home)
	if err != nil {
		t.Fatalf("canary: %v", err)
	}
	if rep.FilesFound != 2 {
		t.Errorf("FilesFound = %d, want 2 (.jsonl files)", rep.FilesFound)
	}
	if rep.FilesParsed != 1 {
		t.Errorf("FilesParsed = %d, want 1 (the one starting with `{`)", rep.FilesParsed)
	}
}

func TestIsJSONLAcceptsObjectFirstLine(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.jsonl")
	must(t, os.WriteFile(good, []byte("\n  {\"k\":1}\n"), 0o600))
	if !isJSONL(good) {
		t.Error("expected good.jsonl to parse")
	}

	bad := filepath.Join(dir, "bad.jsonl")
	must(t, os.WriteFile(bad, []byte("[1]\n"), 0o600))
	if isJSONL(bad) {
		t.Error("expected bad.jsonl (array, not object) to be rejected")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
