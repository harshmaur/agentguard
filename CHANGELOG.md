# Changelog

All notable changes to AgentGuard.
Format follows [Keep a Changelog](https://keepachangelog.com/), versioning is `MAJOR.MINOR.PATCH`.

## [0.1.3] - 2026-04-28

### Fixed
- `internal/parse/skill.go` no longer races on its tool-invocation regex map. The previous code lazy-initialized regexes on first call from inside `parseSkill`; under the scanner's worker pool, concurrent workers parsing skills at the same time triggered `fatal error: concurrent map writes` and crashed the scan. All 11 regexes are now compiled once at package init via a `func() {...}()` initializer, so the runtime path is read-only — no synchronization needed.
- Added `TestParseSkill_ConcurrentSafe` regression test that runs 16 goroutines × 50 iterations through `parseSkill` under the race detector. Catches future reintroductions of the bug.

### Found in the wild
- The race fired on a real Mac dev-machine scan when the worker pool simultaneously parsed skills from a vendored gstack repo containing 75+ skill files spread across 8 harness folders. Stack trace pointed at `internal/parse/skill.go:41`. v0.1.0–0.1.2 are all affected.

## [0.1.2] - 2026-04-28

### Changed
- Install instructions in README now point at the actual GitHub raw URL (`raw.githubusercontent.com/harshmaur/agentguard/main/install.sh`) instead of the placeholder `agentguard.dev` domain.
- Added a `gh release download` flow with full SHA-256 + cosign verify steps for the period the repo is private. The CISO security team can now walk the trust chain end-to-end with copy-paste commands.
- Build-from-source instructions added to README.
- Manual-verify example bumped to v0.1.1 with a pointer to `/releases` for the latest version.

### Fixed
- `cmd/agentguard/main.go` package doc no longer references the non-existent `agentguard.dev` domain (last stale ref eliminated).
- Scan no longer calls `os.Exit(1)` directly when high/critical findings are present; instead returns a sentinel error so the signal-context defer cancel runs cleanly. Behavior unchanged from the user's perspective (still exits 1).
- Severity comparison switched from magic-number `<= 1` to named constants (`finding.SeverityCritical`, `finding.SeverityHigh`). Brittle to enum reordering otherwise.
- `--open auto|always|never` validation now runs up-front, so a malformed value can no longer influence routing decisions before being rejected.

## [0.1.1] - 2026-04-28

### Added
- `agentguard scan` default flow no longer dumps raw HTML to stdout. Writes the report to a temp file (`/tmp/agentguard-<timestamp>.html`), prints a readable summary on stdout (counts, top findings grouped by severity, report path), and auto-opens the HTML in the default browser when stdout is a TTY.
- `--open auto|always|never` flag controls browser auto-open behavior.
- `--quiet` / `-q` flag suppresses the readable summary.
- `-o -` escape hatch forces format output to stdout (useful for piping HTML into a file or tool).
- Browser launchers: `xdg-open` on Linux (with `wslview` fallback for WSL), `open` on macOS.
- Coverage tests for the output-routing logic in `cmd/agentguard/main_test.go`.

### Changed
- `-f sarif` / `-f json` without `-o` still writes to stdout (machine-readable IS the value); summary goes to stderr if a TTY, omitted if piped, so `agentguard scan -f json | jq` stays clean.

## [0.1.0] - 2026-04-28

Initial release.

### Added
- Static-analysis scanner for AI-agent configurations: MCP servers, Claude Code skills, Cursor configs, agent instruction docs, GitHub Actions workflows, shell rc files, env files.
- 10 v1 rules:
  - `mcp-unpinned-npx`, `mcp-prod-secret-env`, `mcp-shell-pipeline-command`, `mcp-plaintext-api-key`, `mcp-dynamic-config-injection`
  - `skill-shell-hijack`, `skill-undeclared-dangerous-tool`
  - `gha-write-all-permissions`, `gha-secrets-in-agent-step`
  - `shellrc-secret-export`
- Three output formats: HTML (offline-by-default, dark/light mode, screenshot-friendly), SARIF v2.1.0 (drops into GitHub Code Scanning), JSON (for piping into jq or downstream SaaS sync).
- Worker-pool concurrency model: GOMAXPROCS workers, per-file 5s timeout, 10MB size cap, 60s total scan timeout.
- Redaction at finding-construction time. Defense in depth: secrets are replaced with `<redacted:type>` markers before the Finding leaves the parser, so formatters never see raw payloads.
- Property-tested redaction across 144 fixtures: AWS keys, GitHub tokens, Stripe live/test keys, Anthropic keys, OpenAI keys, Slack tokens, Google API keys, JWTs, PEM private keys, URLs with embedded credentials, generic env-var-shaped secrets, high-entropy hex blobs.
- Suppression via `.agentguardignore`: per-rule, per-path-glob, or per-rule-and-glob.
- Defensive default skip-list for the walker: `node_modules`, `vendor`, `.git`, `dist`, `build`, `target`, `__pycache__`, `.next`, `.cache`.
- macOS + Linux binaries, both amd64 and arm64. Windows deferred to v2.
- Trust artifacts in the release pipeline: cosign keyless OIDC signatures (sigstore transparency log), SHA-256 checksums, SBOMs in both SPDX and CycloneDX formats, SLSA L2 build provenance attestation (currently soft-failed pending repo move to an org).
- One-line install: `curl -fsSL https://raw.githubusercontent.com/harshmaur/agentguard/main/install.sh | sh` (works once the repo goes public).
- Comprehensive test suite: table-driven rule tests, parser tests, full-pipeline e2e test asserting no secret leaks across HTML / SARIF / JSON.
