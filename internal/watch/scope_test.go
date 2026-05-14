package watch

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestDiscoverScopeFindsExpectedPathsOnFakeHome(t *testing.T) {
	home := t.TempDir()

	// Plant per-tool dirs.
	must(t, os.MkdirAll(filepath.Join(home, ".claude", "projects"), 0o700))
	must(t, os.MkdirAll(filepath.Join(home, ".codex", "sessions"), 0o700))
	must(t, os.MkdirAll(filepath.Join(home, ".cursor"), 0o700))
	// .codeium intentionally NOT present — must be skipped, not errored.

	// Plant dotfiles.
	must(t, os.WriteFile(filepath.Join(home, ".bashrc"), []byte("# stub\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(home, ".zshrc"), []byte("# stub\n"), 0o600))
	// .bash_profile intentionally absent.

	// Plant a couple of git repos, one nested under a non-repo dir.
	repoA := filepath.Join(home, "code", "alpha")
	must(t, os.MkdirAll(filepath.Join(repoA, ".git"), 0o700))
	repoB := filepath.Join(home, "code", "beta")
	must(t, os.MkdirAll(filepath.Join(repoB, ".git"), 0o700))

	// Plant a node_modules tree to confirm we skip it.
	nm := filepath.Join(home, "code", "alpha", "node_modules", "lodash")
	must(t, os.MkdirAll(nm, 0o700))
	must(t, os.MkdirAll(filepath.Join(nm, ".git"), 0o700)) // would match if we didn't skip

	scope, repos, err := DiscoverScope(home)
	if err != nil {
		t.Fatalf("DiscoverScope: %v", err)
	}
	if repos != 2 {
		t.Errorf("repos = %d, want 2 (alpha + beta; the node_modules .git must be skipped)", repos)
	}

	sort.Strings(scope.TightPaths)

	// Tool dirs present.
	for _, want := range []string{
		filepath.Join(home, ".claude"),
		filepath.Join(home, ".codex"),
		filepath.Join(home, ".cursor"),
	} {
		if !contains(scope.TightPaths, want) {
			t.Errorf("missing tool dir %q in scope", want)
		}
	}
	// .codeium NOT in scope (we didn't create it).
	if contains(scope.TightPaths, filepath.Join(home, ".codeium")) {
		t.Errorf(".codeium should not be in scope when it doesn't exist")
	}

	// Dotfiles present.
	for _, want := range []string{
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".zshrc"),
	} {
		if !contains(scope.TightPaths, want) {
			t.Errorf("missing dotfile %q in scope", want)
		}
	}
	if contains(scope.TightPaths, filepath.Join(home, ".bash_profile")) {
		t.Error(".bash_profile not present on disk; must not appear in scope")
	}

	// Git repos present.
	if !contains(scope.TightPaths, repoA) {
		t.Errorf("missing repo %q", repoA)
	}
	if !contains(scope.TightPaths, repoB) {
		t.Errorf("missing repo %q", repoB)
	}

	// node_modules paths NOT in scope.
	for _, p := range scope.TightPaths {
		if strings.Contains(p, "node_modules") {
			t.Errorf("scope leaked a node_modules path: %q", p)
		}
	}
}

func TestDiscoverScopeOnEmptyHomeReturnsEmpty(t *testing.T) {
	home := t.TempDir()
	scope, repos, err := DiscoverScope(home)
	if err != nil {
		t.Fatalf("DiscoverScope on empty home: %v", err)
	}
	if repos != 0 {
		t.Errorf("repos = %d, want 0", repos)
	}
	if len(scope.TightPaths) != 0 {
		t.Errorf("scope.TightPaths = %v, want empty", scope.TightPaths)
	}
}

func TestDiscoverScopeRejectsEmptyHome(t *testing.T) {
	if _, _, err := DiscoverScope(""); err == nil {
		t.Fatal("expected error on empty home")
	}
}

func TestDiscoverScopeHonorsMaxDepth(t *testing.T) {
	// A repo at depth 8 should NOT be found (default maxDepth=6 in
	// findGitReposUnder; DiscoverScope calls with that).
	home := t.TempDir()
	deep := filepath.Join(home, "a", "b", "c", "d", "e", "f", "g", "repo")
	must(t, os.MkdirAll(filepath.Join(deep, ".git"), 0o700))

	_, repos, err := DiscoverScope(home)
	if err != nil {
		t.Fatal(err)
	}
	if repos != 0 {
		t.Errorf("deep repo at depth 8 was found; depth cap not honored")
	}
}

func contains(s []string, want string) bool {
	for _, x := range s {
		if x == want {
			return true
		}
	}
	return false
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
