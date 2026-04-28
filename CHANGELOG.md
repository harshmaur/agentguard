# Changelog

All notable changes to AgentGuard.
Format follows [Keep a Changelog](https://keepachangelog.com/), versioning is `MAJOR.MINOR.PATCH`.

## [0.2.0-alpha.2] - 2026-04-28

Adds 3 Claude-side rules. All read from `ClaudeSettings.Raw` introduced in
alpha.1 — no new format detector. Validated on the Mac: 2 net-new findings
(third-party plugins + sideloaded marketplace).

### Added
- New rule: **`claude-mcp-auto-approve`** (Critical when `enableAllProjectMcpServers: true`, High when a non-empty `enabledMcpjsonServers` allowlist is present). CVE-2025-59536 MCP-consent-bypass shape: every project's `.mcp.json` auto-loads with no prompt = clone-and-pwn primitive.
- New rule: **`claude-bash-allowlist-too-broad`** (Critical for `Bash(*)` / `Bash(:*)` / `Bash()` total wildcards; High for `Bash(<dangerous-verb>:*)` patterns). Dangerous-verb list covers exfil (curl, wget, nc, scp, sftp, rsync, aws, gh, glab), shell escape (bash, sh, zsh, fish, eval, exec), privilege escalation (sudo, doas, su), and container/k8s ops (docker, kubectl). Precision-tuned: safe verbs with arg wildcards (`Bash(npm:*)`, `Bash(git:*)`, `Bash(python3 -c:*)`) and fully-specified entries (`Bash(rsync -a path/ path/)`) do NOT fire.
- New rule: **`claude-third-party-plugin-enabled`** (Medium for enabled third-party plugins; High for `extraKnownMarketplaces` entries with `source.source = "directory"` — sideloaded marketplaces). Inventory-shape rule that surfaces the plugin attack surface. Trusted marketplaces are `anthropic`, `anthropic-agent-skills`, `claude-plugins-official`.

### Found in the wild
- The Mac scan picked up 4 third-party plugins enabled (harshmaur-typescript-review, playwright-cli, coderabbit, vercel-plugin) + a sideloaded marketplace from `~/.cache/plugins/`. Neither was visible to v0.1.

## [0.2.0-alpha.1] - 2026-04-28

First v0.2 milestone. Adds Codex CLI configuration scanning + 5 high-impact
rules drawn directly from the published 2026 CVE corpus. Validated against
a real Mac dev-machine: **4 Critical findings** that v0.1 missed are now
caught.

### Added
- New format detector: **Codex CLI** (`~/.codex/config.toml`, `.codex/config.toml`). Parses approval policy, sandbox mode, `[projects."<path>"]` trust tables, and `[mcp_servers.<name>]` tables including the `[mcp_servers.<name>.http_headers]` sub-table where Codex stores plaintext API keys.
- New rule: **`claude-hook-shell-rce`** (Critical / Enforced). Catches CVE-2025-59536 (CVSS 8.7) — `.claude/settings.json` `hooks.*` entries that run shell commands on lifecycle events (SessionStart, PreToolUse, PostToolUse, Stop, Notification). Repo-controlled hooks = clone-time RCE. The same rule extends to `statusLine.command` when the field contains a complex shell pipeline (>50 chars + pipes/eval/`$()`/backticks, or curl-pipe-sh patterns).
- New rule: **`claude-skip-permission-prompt`** (Critical / Enforced). Matches `skipAutoPermissionPrompt`, `skipDangerousModePermissionPrompt`, and `dangerouslySkipPermissionPrompt` set to true — the consent-bypass shape from CVE-2025-59536.
- New rule: **`codex-approval-disabled`** (Critical when both, High when one). Flags `approval_policy = "never"` and/or `sandbox_mode = "danger-full-access"`.
- New rule: **`codex-trust-home-or-broad`** (Critical / Enforced). Flags `[projects."<path>"] trust_level = "trusted"` where the path is `$HOME`, `/`, or a single-segment-from-root parent (`/Users`, `/home`). Disables Codex's project-trust gate for everything underneath.
- New rule: **`codex-mcp-plaintext-header-key`** (Critical / Detectable). Plaintext credential in `[mcp_servers.<name>.http_headers]`. Reuses the v0.1.4 `matchesCredential` helper so all the GitLab/HF/npm/UUID-name-suffix shapes are detected here too.
- 30+ new test cases covering each rule plus an end-to-end test that asserts all 5 v0.2 rules fire on the real Mac configuration.
- New dependency: `github.com/BurntSushi/toml v1.6.0` for Codex TOML parsing. Single transitive-dep-free package; binary growth is ~140KB.

### Changed
- `ClaudeSettings` now retains the full top-level decoded JSON in a `Raw` field. Required because v0.2 rules walk fields (`statusLine`, `enabledPlugins`, `extraKnownMarketplaces`) whose shapes shift across Claude Code versions and don't warrant per-key struct fields.
- `FormatClaudeSettings` path detection extended to also pick up `settings.local.json` (project-local overrides; previously was settings.json only).

### Deferred to later v0.2 alphas
- `claude-mcp-auto-approve`, `claude-bash-allowlist-too-broad`, `claude-third-party-plugin-enabled` — claude-side rules that depend on the same `Raw` field; ship in alpha.2.
- Cursor `permissions.json` + Windsurf MCP detector + the 3 generalized MCP rules over a normalized model — alpha.3.
- Attack Chains report layer + `agent-capability-meets-readable-secret` cross-rule — alpha.4.

The v0.2.0 final ships when all alphas are merged.

## [0.1.4] - 2026-04-28

### Added
- `shellrc-secret-export` and `mcp-plaintext-api-key` rules now recognize four additional credential value shapes that were missed in v0.1.0–0.1.3: GitLab personal access tokens (`glpat-…`), GitLab project trigger tokens (`glptt-…`), Hugging Face tokens (`hf_…`), and modern npm tokens (`npm_…`).
- Both rules now also fire on env vars whose **name** ends in a credential-suggesting suffix (`_TOKEN`, `_KEY`, `_SECRET`, `_PASSWORD`, `_AUTH`, `_CREDENTIAL`, `_PAT`, `_PSK`, `AUTHTOKEN`, `APIKEY`) when the value is non-trivial (≥16 chars, ≥2 character classes). Catches UUID-shaped tokens like `FONTAWESOME_REGISTRY_AUTHTOKEN=C407A854-…` whose value alone wouldn't be recognizable as a credential but whose name removes all doubt.
- New `valueLooksLikeSecret` heuristic filters obvious non-secrets: short values, boolean-like values (`true`/`false`/`yes`/etc.), and single-class values are ignored even when paired with a credential-shaped name.
- 9 new regression test cases (`TestRule_ShellrcSecretExport_v014ExtendedShapes`) covering each new pattern + the obvious negatives (PATH-like values, short values, booleans).
- `internal/redact` matching extended for the same four new credential prefixes so report output redacts them.

### Found in the wild
- v0.1.3 scan of a real Mac dev-machine `.zprofile` exported three production tokens: a `glpat-…` GitLab PAT, a UUID-shaped FontAwesome auth token, and a `ghp_…` GitHub PAT. Only the GitHub token was caught. v0.1.4 catches all three.

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
