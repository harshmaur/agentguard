# AgentGuard

**Static-analysis scanner for AI-agent configurations.**

Scan MCP servers, Claude Code skills, Cursor configs, agent instruction docs,
and GitHub Actions workflows for risky configuration. Offline by default.
Emits HTML, SARIF, and JSON reports. Built on a single static Go binary so a
CISO can drop it into a fleet without `npm install` or `pip install`.

```
agentguard: 16 findings (2 critical, 12 high, 2 medium, 0 low) in 4 files (2ms) → /tmp/scan.html
```

---

## Why

AI coding agents (Claude Code, Cursor, Codex, Windsurf, OpenCode) and MCP
servers are spreading across dev fleets faster than security teams can review
them. Permissions are scattered across machines, repos, dotfiles, CI configs,
IDE settings, and team docs. CISOs cannot answer basic questions:

- Which agents on our fleet can read production secrets?
- Which MCP servers are running across the company?
- Which configs were installed from unknown sources?
- Which repos allow autonomous edits without review?

AgentGuard is the inventory + policy check designed for exactly this gap.
It cedes OSS-vuln scanning to Snyk and broad cloud posture to Wiz; the
wedge is **AI-agent-config posture management**.

---

## Quick start

```sh
# Install (macOS + Linux). Verifies SHA-256 + cosign signature.
curl -fsSL https://agentguard.dev/install.sh | sh

# Scan your machine ($HOME).
agentguard scan

# Scan a single repo.
agentguard scan ~/code/my-repo

# Output formats.
agentguard scan -f sarif -o scan.sarif    # GitHub Code Scanning compatible
agentguard scan -f html  -o scan.html     # screenshot-friendly report
agentguard scan -f json  -o scan.json     # for piping / SaaS sync

# Suppress findings (per-rule or per-path globs).
echo 'mcp-unpinned-npx **/old-mcp.json' > .agentguardignore
agentguard scan
```

Exit code is `1` if any high or critical finding fires, else `0`. Useful in CI:

```yaml
- run: agentguard scan -f sarif -o agentguard.sarif .
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: agentguard.sarif }
```

---

## What it scans

| Path | Format | Rules apply |
|------|--------|-------------|
| `~/.claude/`, `~/.cursor/`, `.mcp.json` | MCP config (JSON) | unpinned npx, prod secret env, plaintext API keys, shell pipelines, dynamic config injection |
| `**/.claude/skills/**/*.md` | Skill (Markdown + frontmatter) | shell-hijack patterns (`curl|bash`, `eval`, base64-decode), undeclared dangerous tools |
| `.github/workflows/*.yml` | GitHub Actions | `permissions: write-all`, secrets exposed to agent steps |
| `~/.bashrc`, `~/.zshrc`, `~/.profile` | Shell rc | exported credentials |
| `.env*` | Env file | secret-shaped values |
| `AGENTS.md`, `CLAUDE.md`, `CODEX.md`, `.cursorrules` | Agent instruction docs | (rules in v1.1) |

Always-skipped directories (defensive default): `node_modules`, `vendor`,
`.git`, `dist`, `build`, `target`, `__pycache__`, `.next`, `.cache`.

---

## v1 ruleset

| ID | Severity | Taxonomy |
|----|----------|----------|
| `mcp-unpinned-npx` | high | enforced |
| `mcp-prod-secret-env` | critical | enforced |
| `mcp-shell-pipeline-command` | high | detectable |
| `mcp-plaintext-api-key` | critical | detectable |
| `mcp-dynamic-config-injection` | high | detectable |
| `skill-shell-hijack` | high | detectable |
| `skill-undeclared-dangerous-tool` | medium | detectable |
| `gha-write-all-permissions` | high | enforced |
| `gha-secrets-in-agent-step` | high | detectable |
| `shellrc-secret-export` | high | detectable |

**Taxonomy** is the honest claim about what AgentGuard can do:
- **enforced** — failed scan can break CI / block commit. The customer can write a policy that prevents the violation reaching production.
- **detectable** — reliably found, but workflow (review/alert/education) must act.
- **advisory** — cannot reliably detect; documented as best practice.

The CISO sale depends on this label being trustworthy.

---

## Trust artifacts (verify before installing)

The trust paradox: a security tool from a stranger on LinkedIn is itself a
supply-chain risk. AgentGuard takes that seriously.

- **Source on GitHub.** Every rule, parser, and output formatter is
  inspectable. Read the code before installing.
- **Signed releases via cosign.** Every release artifact has a detached
  `.sig` and `.crt` on the GitHub Release page.
- **Reproducible builds.** Built with `-trimpath -buildvcs=false` and a
  pinned Go toolchain. CI builds from source twice and asserts the binary
  hashes match.
- **SBOM published.** SPDX + CycloneDX, every release. Audit dependencies.
- **SLSA Level 2 provenance.** Build attestations via the official SLSA
  generator action.
- **No telemetry by default.** AgentGuard runs entirely offline. The
  `--share-anon` flag is wired but no-op in v1 (will become opt-in
  community telemetry in v2 SaaS).

### Manual verify (CISO security team workflow)

```sh
# Download release artifacts.
VERSION=v0.1.0
ARCH=darwin-arm64
BASE="https://github.com/harshmaur/agentguard/releases/download/${VERSION}"
curl -fsSL -O "${BASE}/agentguard-${VERSION}-${ARCH}.tar.gz"
curl -fsSL -O "${BASE}/agentguard-${VERSION}-${ARCH}.tar.gz.sig"
curl -fsSL -O "${BASE}/agentguard-${VERSION}-${ARCH}.tar.gz.crt"

# Verify checksum.
curl -fsSL -O "${BASE}/SHA256SUMS"
shasum -a 256 -c SHA256SUMS --ignore-missing

# Verify cosign signature against sigstore transparency log.
cosign verify-blob \
  --certificate "agentguard-${VERSION}-${ARCH}.tar.gz.crt" \
  --signature   "agentguard-${VERSION}-${ARCH}.tar.gz.sig" \
  --certificate-identity-regexp 'https://github.com/harshmaur/agentguard/.+' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "agentguard-${VERSION}-${ARCH}.tar.gz"

# Optional: build from source and compare hashes.
git clone --depth 1 --branch "${VERSION}" https://github.com/harshmaur/agentguard
cd agentguard && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -X main.Version=${VERSION}" -o agentguard ./cmd/agentguard
shasum -a 256 agentguard
```

---

## Suppression

Two paths:

**`.agentguardignore` (project file):**

```
# rule-id alone disables a rule globally
mcp-unpinned-npx

# path glob alone suppresses ALL rules under that path
testdata/**

# rule-id + glob disables a rule under a path
gha-write-all-permissions .github/workflows/release.yml
```

**Inline (planned for v1.1):** `# agentguard:disable=rule-id` next to a
matched line. Not yet implemented.

---

## Roadmap

- **v1 (this release):** machine + repo scan, 10 rules, HTML/SARIF/JSON,
  signed binary, cosign verify, SBOM, SLSA L2, suppression file.
- **v1.1:** user-editable policy YAML, GitHub Action template, more rules
  (5-10 added during parser hardening).
- **v2:** Windows support, BYOD privacy mode (`--byod`), inline suppression,
  fuzz harness expanded.
- **v3 (paid SaaS):** fleet visibility, drift detection, central policy
  distribution, approved registry, SOC 2 / ISO compliance reports, SSO,
  SIEM integration, premium rule packs + threat intel.

See the design doc in `2026-04-27-agentguard.md` for the full plan and the
reasoning behind the wedge.

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
# Build
go build -o agentguard ./cmd/agentguard

# Test
go test -race -count=1 ./...

# Run against the dirty fixture
./agentguard scan -f html -o /tmp/r.html testdata/laptops/dirty
```

A new rule = a struct in `internal/rules/builtin/` that implements the
`rules.Rule` interface, registered in the `builtins()` slice. Every rule
ships with three table-driven test cases (positive, negative, edge).
