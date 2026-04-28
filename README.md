# AgentGuard

**Static-analysis scanner for AI-agent configurations.**

Scan MCP servers, Claude Code skills, Cursor / Codex / Windsurf configs,
agent instruction docs, and GitHub Actions workflows for risky configuration.
Offline by default. Single static Go binary, no `npm`/`pip`. Emits HTML,
SARIF, and JSON reports.

```
==> Permission-loose agent + reachable secret = exfil chain.
    5 attack chains, 48 findings across 36 files.

Attack chains (5):
  - [CRITICAL] Permission-loose agent + reachable secret = exfil chain
    Attacker gets: One prompt injection reads SSH keys, .env files,
                   and plaintext API keys without prompting
  - [CRITICAL] Codex: trusted $HOME + plaintext key = no-friction takeover
  - [CRITICAL] Cloning a malicious repo can RCE this dev box
  - [HIGH]     Third-party plugin ships an unauthenticated MCP server
  - [HIGH]     Same credential `CONTEXT7_API_KEY` reused across 2 harnesses

Report: /tmp/agentguard-scan.html
```

---

## Why

AI coding agents — Claude Code, Cursor, Codex, Windsurf, OpenCode — and
MCP servers are spreading across dev fleets faster than security teams can
review them. Permissions are scattered across machines, repos, dotfiles,
CI configs, IDE settings, and team docs. CISOs cannot answer:

- Which agents on our fleet can read production secrets?
- Which MCP servers are running across the company?
- Which configs were installed from unknown sources?
- Which repos allow autonomous edits without review?

AgentGuard is the inventory + policy check designed for this gap. It cedes
OSS-vuln scanning to Snyk and broad cloud posture to Wiz; the wedge is
**AI-agent-config posture management**.

---

## Install

```sh
# macOS + Linux:
curl -fsSL https://raw.githubusercontent.com/harshmaur/agentguard/main/install.sh | sh
```

The script downloads the latest signed release tarball from GitHub Releases,
verifies the SHA-256 against the published `SHA256SUMS`, verifies the cosign
signature against the sigstore transparency log if `cosign` is on PATH, then
installs the binary to `~/.local/bin/agentguard`.

**Build from source:**

```sh
git clone https://github.com/harshmaur/agentguard
cd agentguard
go build -o agentguard ./cmd/agentguard
./agentguard version
```

---

## Run

```sh
# Scan your machine ($HOME). Writes HTML to /tmp/, opens in your browser,
# prints a forensic summary on stdout.
agentguard scan

# Scan a specific tree.
agentguard scan ~/code/my-repo

# Output formats.
agentguard scan -f sarif -o scan.sarif    # GitHub Code Scanning compatible
agentguard scan -f html  -o scan.html     # forensic-document HTML report
agentguard scan -f json  -o -  | jq       # pipe JSON to stdout

# Suppress findings (per-rule or per-path globs).
echo 'mcp-unpinned-npx **/old-mcp.json' > .agentguardignore
agentguard scan
```

Exit code is `1` if any high or critical finding fires, else `0`. CI usage:

```yaml
- run: agentguard scan -f sarif -o agentguard.sarif .
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: agentguard.sarif }
```

---

## Attack Chains

Beyond per-finding rules, AgentGuard runs a correlation pass that fires
**attacker-POV narratives** when specific findings co-occur. Each chain
combines findings into an end-to-end story so a CISO sees the actual risk,
not just rows in a table:

| Chain | Severity | Triggers |
|---|---|---|
| Cloning a malicious repo can RCE this dev box | Critical | hook RCE in repo-shipped `.claude/settings.json` |
| Permission-loose agent + reachable secret = exfil chain | Critical | consent-bypass / broad allowlist + readable secrets |
| Codex: trusted `$HOME` + plaintext key = no-friction takeover | Critical | trust=trusted on broad path + plaintext key in same file |
| Third-party plugin ships an unauthenticated MCP server | High | enabled plugin + bundled `.mcp.json` with no auth |
| Same credential reused across N harnesses | High | same env-var name in 2+ harness configs |

Each chain renders in HTML with a forensic-style "Attacker gets:" call-out
and full prose walkthrough; the same outcome line shows on stdout.

---

## What it scans

| Path | Format | What gets parsed |
|---|---|---|
| `~/.claude/`, `.claude/`, `.mcp.json` | Claude Code (JSON) | hooks, statusLine, permissions allowlist, MCP servers, enabledPlugins, marketplaces |
| `~/.codex/config.toml`, `.codex/config.toml` | Codex CLI (TOML) | approval_policy, sandbox_mode, trust_level, MCP servers, http_headers |
| `~/.cursor/`, `.cursor/` | Cursor (JSON) | mcpAllowlist, terminalAllowlist, MCP wildcards |
| `~/.codeium/windsurf/mcp_config.json` | Windsurf (JSON) | MCP servers, alwaysAllow, headers |
| `**/.claude/skills/**/*.md` | Skill (Markdown + frontmatter) | shell-hijack patterns, undeclared dangerous tools |
| `.github/workflows/*.yml` | GitHub Actions | `permissions: write-all`, secrets exposed to agent steps |
| `~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.zprofile` | Shell rc | exported credentials |

Cursor, Codex, and Windsurf MCP configs share a normalized model — adding
the next harness costs one parser, zero new rules.

Always-skipped directories (defensive default): `node_modules`, `vendor`,
`.git`, `dist`, `build`, `target`, `__pycache__`, `.next`, `.cache`.

---

## Ruleset

**Claude Code (5)**
- `claude-hook-shell-rce` — Critical — hook / statusLine / shell-shaped fields run shell commands (CVE-2025-59536)
- `claude-skip-permission-prompt` — Critical — `skipAutoPermissionPrompt` / `skipDangerousModePermissionPrompt` removes consent gate
- `claude-mcp-auto-approve` — High — MCP server marked auto-approve
- `claude-bash-allowlist-too-broad` — High — `permissions.allow` permits dangerous-verb arg-wildcards
- `claude-third-party-plugin-enabled` — Medium / Advisory — plugin from non-Anthropic marketplace

**Codex CLI (2)**
- `codex-approval-disabled` — Critical — `approval_policy = "never"`
- `codex-trust-home-or-broad` — Critical — `trust_level = "trusted"` on `$HOME` or broader

**Cursor (2)**
- `cursor-allowlist-too-broad` — Critical — terminal allowlist with dangerous-verb arg-wildcards
- `cursor-mcp-wildcard` — High — MCP wildcard match

**MCP — generalized across Cursor / Codex / Windsurf (3)**
- `mcp-plaintext-api-key` — Critical — plaintext credential in MCP server config
- `mcp-unpinned-npx` — High — unpinned `npx ... @latest` MCP server
- `mcp-unauth-remote-url` — High — remote MCP URL without auth header

**MCP supplemental (3)**
- `mcp-prod-secret-env` — Critical — production-shape secret in env block
- `mcp-shell-pipeline-command` — High — shell pipeline as command
- `mcp-dynamic-config-injection` — High — config field interpolated from env / argv

**Skill / instruction-doc (2)**
- `skill-shell-hijack` — High — `curl|bash`, `eval`, base64-decode pattern in skill body
- `skill-undeclared-dangerous-tool` — Medium — skill uses Bash/Edit/Write but doesn't declare in frontmatter

**GitHub Actions (2)**
- `gha-write-all-permissions` — High — `permissions: write-all` at workflow or job scope
- `gha-secrets-in-agent-step` — High — secret passed to a step that invokes a coding agent

**Shell rc (1)**
- `shellrc-secret-export` — High — exported credential matching a known token shape

**Total: 20 rules, 4 format families, 5 attack chains.** Every finding ships
with a `taxonomy` label:

- **enforced** — failed scan can break CI / block commit
- **detectable** — reliably found, but workflow (review/alert/education) must act
- **advisory** — cannot reliably detect; documented as best practice

The CISO sale depends on this label being trustworthy.

---

## Trust artifacts (verify before installing)

The trust paradox: a security tool from a stranger on LinkedIn is itself a
supply-chain risk. AgentGuard takes that seriously.

- **Source on GitHub.** Every rule, parser, and output formatter is
  inspectable. Read the code before installing.
- **Signed releases via cosign.** Every release artifact has a detached
  `.sig` and `.crt` on the GitHub Release page.
- **SLSA L2 build provenance** (v0.2.4+). Build attestations via
  `actions/attest-build-provenance`. Verify with `gh attestation verify`.
- **Reproducible builds.** Built with `-trimpath -buildvcs=false` and a
  pinned Go toolchain.
- **SBOM published.** SPDX + CycloneDX, every release.
- **Zero telemetry.** Runs entirely offline; the rendered HTML report
  embeds its fonts as base64 data URIs and makes zero external requests.

### Manual verify (CISO security-team workflow)

```sh
VERSION=v0.2.4
ARCH=darwin-arm64   # or linux-amd64, linux-arm64, darwin-amd64
BASE="https://github.com/harshmaur/agentguard/releases/download/${VERSION}"

curl -fsSL -O "${BASE}/agentguard-${VERSION}-${ARCH}.tar.gz"
curl -fsSL -O "${BASE}/agentguard-${VERSION}-${ARCH}.tar.gz.sig"
curl -fsSL -O "${BASE}/agentguard-${VERSION}-${ARCH}.tar.gz.crt"
curl -fsSL -O "${BASE}/SHA256SUMS"

# 1) SHA-256 matches the published sums file
shasum -a 256 -c SHA256SUMS --ignore-missing

# 2) cosign verifies against sigstore transparency log
cosign verify-blob \
  --certificate "agentguard-${VERSION}-${ARCH}.tar.gz.crt" \
  --signature   "agentguard-${VERSION}-${ARCH}.tar.gz.sig" \
  --certificate-identity-regexp 'https://github.com/harshmaur/agentguard/.+' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "agentguard-${VERSION}-${ARCH}.tar.gz"

# 3) SLSA L2 build provenance (v0.2.4+)
gh attestation verify "agentguard-${VERSION}-${ARCH}.tar.gz" \
  --repo harshmaur/agentguard

# 4) (belt-and-suspenders) build from source and compare hashes
git clone --depth 1 --branch "${VERSION}" https://github.com/harshmaur/agentguard
cd agentguard
CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -ldflags="-s -w -X main.Version=${VERSION}" \
  -o agentguard ./cmd/agentguard
shasum -a 256 agentguard
```

---

## Suppression

```
# rule-id alone disables a rule globally
mcp-unpinned-npx

# path glob alone suppresses ALL rules under that path
testdata/**

# rule-id + glob disables a rule under a path
gha-write-all-permissions .github/workflows/release.yml
```

Inline `# agentguard:disable=rule-id` is on the v0.3 list.

---

## Roadmap

- **v0.2 (shipped):** 4 format families (Claude / Codex / Cursor / Windsurf),
  20 rules, normalized MCP model, 5 attack chains, forensic-document HTML
  report, signed binary + cosign + SBOM + SLSA L2.
- **v0.3:** more harness detectors (Cline / Continue / Roo / Kilo / Aider /
  OpenClaw / Hermes / Goose), tool-description prompt-injection rules,
  inline suppression syntax, fleet aggregation, Windows support.
- **v0.4+ (paid SaaS):** fleet visibility, drift detection, central policy
  distribution, approved registry, SOC 2 / ISO compliance reports, SSO,
  SIEM integration, premium rule packs + threat intel.

---

## License

TBD — pending procurement-legal review with two design partners. Likely
[BSL](https://mariadb.com/bsl11/) or [FSL](https://fsl.software/) so the
source is fully readable but commercial reselling as a competing SaaS is
restricted for 2-4 years before reverting to permissive. Track at
[#1](https://github.com/harshmaur/agentguard/issues/1).

---

## Contributing

```sh
go build -o agentguard ./cmd/agentguard
go test -race -count=1 ./...

# Run against the dirty fixture
./agentguard scan -f html -o /tmp/r.html testdata/laptops/dirty
```

A new rule = a struct in `internal/rules/builtin/{format-family}.go`
implementing the `rules.Rule` interface, registered in the `builtins()`
slice. Every rule ships with three table-driven test cases (positive,
negative, edge).
