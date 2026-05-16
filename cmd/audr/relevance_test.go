package main

import "testing"

func TestIsScannerRelevantPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
		why  string
	}{
		// Relevant: recognized by parse.DetectFormat.
		{"/home/u/.mcp.json", true, "FormatMCPConfig"},
		{"/home/u/.claude/settings.json", true, "FormatClaudeSettings"},
		{"/home/u/.bashrc", true, "FormatShellRC"},
		{"/home/u/projects/app/.env", true, "FormatEnv"},
		{"/home/u/AGENTS.md", true, "FormatAgentDoc"},
		{"/home/u/.github/workflows/ci.yml", true, "FormatGHAWorkflow"},
		{"/home/u/.codex/config.toml", true, "FormatCodexConfig"},

		// Relevant: dependency manifests / lockfiles.
		{"/home/u/projects/app/package.json", true, "lockfile basename"},
		{"/home/u/projects/app/go.mod", true, "lockfile basename"},
		{"/home/u/projects/app/Cargo.lock", true, "lockfile basename"},
		{"/home/u/projects/app/pnpm-lock.yaml", true, "lockfile basename"},

		// Irrelevant: the noise sources the user complained about.
		{"/home/u/.claude/projects/abc/transcripts/2026-05-16.jsonl", false, "Claude transcript"},
		{"/home/u/.local/state/audr/audr.db-wal", false, "sqlite WAL"},
		{"/home/u/.local/state/audr/audr.db-shm", false, "sqlite SHM"},
		{"/home/u/.local/state/audr/daemon.log", false, "log file"},
		{"/var/log/syslog", false, "system log"},
		{"/home/u/.cache/some-tool/blob.bin", false, "generic cache"},
		{"/home/u/Downloads/movie.mp4", false, "binary media"},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			got := isScannerRelevantPath(c.path)
			if got != c.want {
				t.Errorf("isScannerRelevantPath(%q) = %v, want %v (%s)", c.path, got, c.want, c.why)
			}
		})
	}
}
