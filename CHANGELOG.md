# Changelog

All notable changes to Audr.
Format follows [Keep a Changelog](https://keepachangelog.com/), versioning is `MAJOR.MINOR.PATCH`.

## [0.3.1] - unreleased

Hotfix for the v0.3.0 install path.

### Fixed
- **`install.sh` was installing a directory at `~/.local/bin/audr` instead of the binary.** The release tarball wraps the `audr` binary inside `audr-vX.Y.Z-os-arch/`; install.sh's `binary=` pointed at that directory rather than at the file inside, so `mv "$binary" "$INSTALL_DIR/audr"` moved the whole directory. Latent since v0.2.x — surfaced by the v0.3.0 release smoke test. Pinned by a new regression test in `internal/installscript/` that asserts the binary path includes the `/audr` suffix.

## [0.3.0]

First public release of Audr — a static-analysis scanner for AI-agent configurations.

### Added
- **20 rules across 4 format families.** Claude Code (5), Codex CLI (2), Cursor (2), generalized MCP across Cursor/Codex/Windsurf (3), MCP supplemental (3), skill / instruction-doc (2), GitHub Actions (2), shell rc (1).
- **5 attack-chain correlations.** Critical: hook RCE in repo-shipped `.claude/settings.json`; permission-loose agent + reachable secret = exfil chain; Codex trusted `$HOME` + plaintext key = no-friction takeover. High: third-party plugin ships an unauthenticated MCP server; same credential reused across N harnesses.
- **Forensic-document HTML report.** Per-finding "what an attacker gets" callout, severity-tinted left borders, file-by-file forensic narrative. Reads like a court exhibit, not a scanner dump. Embedded fonts as base64 data URIs — zero external requests.
- **`audr scan` subcommand.** Default scans `$HOME`, opens HTML in browser. Output formats: HTML, SARIF (GitHub Code Scanning compatible), JSON (pipe to `jq`). Exit code 1 on any high or critical finding.
- **`audr verify <tarball>` subcommand.** Verify a downloaded release tarball against `SHA256SUMS`. If `cosign` is on PATH and `.sig` + `.crt` files are alongside, also runs `cosign verify-blob` against the sigstore transparency log. Flags: `--sums`, `--cert-identity-regexp`, `--cert-oidc-issuer`.
- **`audr self-audit` subcommand.** Prints the SHA-256 of the running binary plus its full rule + chain manifest. `--json` for diffing between machines or feeding a CMDB. Diff the JSON output between two installs to confirm they're identical.
- **`.audrignore` suppression file.** Per-rule and per-path-glob suppression syntax. Loaded automatically from the scan root if present.
- **Signed releases.** Every release artifact ships with cosign-signed `.sig` and `.crt`, SHA256SUMS, SBOMs (SPDX + CycloneDX), and SLSA L2 build provenance via `actions/attest-build-provenance`.
- **License: FSL-1.1-MIT.** Functional Source License with MIT future grant. Source is fully readable, internal use OK, redistribution OK; the only restriction is reselling Audr as a competing commercial service. Two years after each release, that release reverts to plain MIT. Same model used by Sentry, Convex, GitButler, Keygen.
- **`AGENTS.md`.** Cross-tool instructions for Claude Code, Cursor, Codex, OpenCode, Aider. Headline rule: never commit real credentials to test fixtures — use repeated-character placeholders that match the format's prefix and length so the regex still fires.
- **CI self-scan gate.** `.github/workflows/ci.yml` runs `./audr scan .` on every PR and fails the build on any finding. The scanner now gates its own source.
- **`internal/suppress` test coverage.** Full table-driven coverage of `LoadFile`, rule parsing, and path-glob matching (previously zero coverage).
- **`install.sh` cosign cert-identity-regexp regression test.** Shell-only logic in `install.sh` is now exercised by a Go test that runs the script with a stub `cosign` and asserts the exact regexp argument. Prevents silent verification bypass from a future typo.
- **`docs/sample-report.html` staleness gate.** CI regenerates the sample report from the current template + fixture and diffs it against the committed copy. PR fails if the committed sample is stale.
