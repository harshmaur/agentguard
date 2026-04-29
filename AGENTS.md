# AGENTS.md

Instructions for AI coding agents (Claude Code, Cursor, Codex, OpenCode, Aider) working in this repo. Tiny on purpose. Read it all.

## Never commit real credentials

This is a security tool. Real credentials in test fixtures defeat the entire point.

For credential-shaped test fixtures, use repeated-character placeholders that match the format's prefix and length so the regex you're testing still fires:

- `ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` (40 chars after prefix)
- `glpat-aaaaaaaaaaaaaaaaaaaaaaaaa` (no `.NN.<hash>` checksum suffix — that suffix is the giveaway it's real)
- `sk-ant-api03-cccccccccccccccccccccccccccccccccccccc`
- `ctx7sk-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa` (UUID shape, all-`a`)
- `AKIAIOSFODNN7EXAMPLE` (canonical AWS docs example, public synthetic)

**If you capture a fixture from a real machine, redact in the same edit.** Not "later." Not "before commit." The same edit.

Before every commit, run `./audr scan .` against the working tree. Anything that fires must be redacted before the commit lands. Trust this tool — it is literally what we're building.

## Build & test

```sh
go build -o audr ./cmd/audr && go test -race -count=1 ./...
```

## Style

Match the surrounding code. New dependencies need a one-line justification in the commit message. Default to no comments; add one only when the *why* is non-obvious.
