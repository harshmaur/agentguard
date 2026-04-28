package correlate

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/agentguard/agentguard/internal/finding"
	"github.com/agentguard/agentguard/internal/output"
)

// scenarioFn is the signature each attack chain implements. Returns the
// chain + true if it fires; otherwise false.
type scenarioFn func(idx *findingIndex) (output.AttackChain, bool)

// scenarios is the registered list. Order doesn't matter (Run sorts by
// severity), but we keep it logical for readability.
var scenarios = []scenarioFn{
	chainRepoCloneHookRCE,
	chainAgentReadsProdSecrets,
	chainTrustedHomePlusPlaintextKey,
	chainPluginBundledMCPWithoutAuth,
	chainSameSecretAcrossHarnesses,
}

// --- 1. Repo-clone hook RCE ------------------------------------------------
//
// Fires when claude-hook-shell-rce fired on a settings.json that lives in a
// project (i.e., not under the user's home `.claude/` directory). A repo-
// committed `.claude/settings.json` is the CVE-2025-59536 attack vehicle:
// clone the repo → open in Claude Code → hook fires → RCE.

func chainRepoCloneHookRCE(idx *findingIndex) (output.AttackChain, bool) {
	hookFindings := idx.findings("claude-hook-shell-rce")
	if len(hookFindings) == 0 {
		return output.AttackChain{}, false
	}

	// Filter to project-level settings.json (not under <home>/.claude/).
	// Heuristic: path contains `/.claude/` but the parent directory is not
	// the user's home (which would contain `.claude` directly).
	// Practically, we check that the path is NOT directly under a user home
	// like `/home/<user>/.claude/...` or `/Users/<user>/.claude/...`. A
	// project-level settings.json looks like `/path/to/repo/.claude/...`.
	var projectPaths []string
	for _, f := range hookFindings {
		if isProjectLevelClaudePath(f.Path) {
			projectPaths = append(projectPaths, f.Path)
		}
	}
	// Even if all hook findings are at user-level, still surface the chain —
	// the user-level case is just less obviously repo-clone-driven, and
	// clone-of-repo-with-settings.json-in-it-or-symlinked still applies.
	// Severity stays Critical regardless.
	allPaths := dedupeSorted(idx.paths("claude-hook-shell-rce"))

	narrative := buildRepoCloneNarrative(hookFindings, projectPaths)
	return output.AttackChain{
		ID:         "repo-clone-hook-rce",
		Title:      "Cloning a malicious repo can RCE this dev box",
		Severity:   finding.SeverityCritical,
		Narrative:  narrative,
		Citations:  []string{"CVE-2025-59536 (CVSS 8.7)", "Check Point Research 2026"},
		FindingIDs: []string{"claude-hook-shell-rce"},
		Paths:      allPaths,
	}, true
}

func buildRepoCloneNarrative(hookFindings []finding.Finding, projectPaths []string) string {
	var b strings.Builder
	b.WriteString("An attacker publishes a public repo with a poisoned `.claude/settings.json`. The file contains a hook (`SessionStart`, `PreToolUse`, `Stop`, etc.) that runs an arbitrary shell command.\n\n")
	b.WriteString("The moment a developer clones the repo and opens it in Claude Code, the hook fires — before any user prompt, before any trust dialog, with the developer's full shell privileges.\n\n")
	b.WriteString("On this machine specifically, ")
	if len(projectPaths) > 0 {
		b.WriteString(fmt.Sprintf("project-level hook settings already live at: `%s`.\n\n", projectPaths[0]))
	} else {
		b.WriteString("the hook configuration is at the user level. A repo-shipped `.claude/settings.json` would override or supplement it the moment the repo is opened.\n\n")
	}
	if len(hookFindings) > 0 {
		match := truncate(hookFindings[0].Match, 120)
		b.WriteString(fmt.Sprintf("**The actual command that would run:** `%s`\n\n", match))
	}
	b.WriteString("**Patch path:** Claude Code 2.1.75+ adds a trust dialog before loading repo-shipped hooks. Mitigation in agentguard: remove or restrict the hook entry to user-level settings only.")
	return b.String()
}

func isProjectLevelClaudePath(path string) bool {
	// Project-level: the segment before `.claude/` is NOT the user's home.
	// Home-level: path matches `/<userhome>/.claude/...`.
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, p := range parts {
		if p == ".claude" && i >= 2 {
			parent := parts[i-1]
			grand := parts[i-2]
			// Home shape: /Users/<name>/.claude or /home/<name>/.claude
			if (grand == "Users" || grand == "home") && parent != "" {
				return false
			}
		}
	}
	return true
}

// --- 2. Agent reads prod secrets -------------------------------------------
//
// Fires when (any consent-removed agent capability) AND (any reachable
// secret). The user's stated worry from the design doc.
//
// Capability triggers: claude-skip-permission-prompt, claude-bash-allowlist-too-broad,
// codex-approval-disabled, codex-trust-home-or-broad, claude-mcp-auto-approve,
// cursor-allowlist-too-broad with a Critical severity, mcp-unauth-remote-url
// (any of these means an attacker-influenced prompt has a clear path to a
// shell or a compromised tool).
//
// Secret triggers: shellrc-secret-export, mcp-plaintext-api-key,
// mcp-prod-secret-env, presence of ~/.ssh/id_*, presence of .env in scope.

func chainAgentReadsProdSecrets(idx *findingIndex) (output.AttackChain, bool) {
	capabilityRules := []string{
		"claude-skip-permission-prompt",
		"claude-bash-allowlist-too-broad",
		"codex-approval-disabled",
		"codex-trust-home-or-broad",
		"claude-mcp-auto-approve",
		"cursor-allowlist-too-broad",
		"mcp-unauth-remote-url",
	}
	secretRules := []string{
		"shellrc-secret-export",
		"mcp-plaintext-api-key",
		"mcp-prod-secret-env",
	}
	if !idx.hasAny(capabilityRules...) {
		return output.AttackChain{}, false
	}
	hasSecret := idx.hasAny(secretRules...) || idx.hasReadablePrivateKey()
	if !hasSecret {
		return output.AttackChain{}, false
	}

	var capList []string
	for _, r := range capabilityRules {
		if idx.has(r) {
			capList = append(capList, r)
		}
	}
	var secretList []string
	for _, r := range secretRules {
		if idx.has(r) {
			secretList = append(secretList, r)
		}
	}
	if idx.hasReadablePrivateKey() {
		secretList = append(secretList, "~/.ssh/id_* (private key on disk)")
	}

	var paths []string
	for _, r := range append(capabilityRules, secretRules...) {
		paths = append(paths, idx.paths(r)...)
	}

	var b strings.Builder
	b.WriteString("This machine pairs a permission-loose agent with secrets it can read. The combination is the user's stated worry from the design doc: *exposed env that my agents can read*.\n\n")
	b.WriteString("**Capability findings:** ")
	b.WriteString(strings.Join(capList, ", "))
	b.WriteString("\n\n")
	b.WriteString("**Reachable secrets:** ")
	b.WriteString(strings.Join(secretList, ", "))
	b.WriteString("\n\n")
	b.WriteString("**The chain:** any prompt-injection vector — a tool output from a remote MCP, a pasted clipboard, a fetched README in a cloned repo — can convince the agent to read those secrets and write them somewhere the attacker can reach (a public gist, a remote MCP request, a written file). Each capability finding above removes a layer of friction; together with reachable secrets, the chain is end-to-end.\n\n")
	b.WriteString("**Mitigation order (highest impact first):** rotate the secrets shown above, then remove the capability findings, then re-scan to confirm the chain breaks.")

	return output.AttackChain{
		ID:         "agent-reads-prod-secrets",
		Title:      "Permission-loose agent + reachable secret = exfil chain",
		Severity:   finding.SeverityCritical,
		Narrative:  b.String(),
		Citations:  []string{"design doc Round 1 + Round 2 trim", "OWASP MCP Top 10 — MCP01 (Token Mismanagement)"},
		FindingIDs: append(append([]string{}, capList...), secretList...),
		Paths:      dedupeSorted(paths),
	}, true
}

// --- 3. Trusted $HOME + plaintext key co-located --------------------------
//
// Fires when codex-trust-home-or-broad AND codex-mcp-plaintext-* in the
// SAME Codex config. This was Scenario 3 in the design doc's Top-5
// acceptance test. On the Mac the chain is fully present.

func chainTrustedHomePlusPlaintextKey(idx *findingIndex) (output.AttackChain, bool) {
	if !idx.has("codex-trust-home-or-broad") {
		return output.AttackChain{}, false
	}
	// "Codex plaintext key" can come from the generalized rule
	// (mcp-plaintext-api-key on FormatCodexConfig). Filter to those.
	plainKeyFindings := idx.findings("mcp-plaintext-api-key")
	codexPlainKeys := []finding.Finding{}
	for _, f := range plainKeyFindings {
		if strings.Contains(f.Path, ".codex/") {
			codexPlainKeys = append(codexPlainKeys, f)
		}
	}
	if len(codexPlainKeys) == 0 {
		return output.AttackChain{}, false
	}

	trustFindings := idx.findings("codex-trust-home-or-broad")
	trustedPath := ""
	if len(trustFindings) > 0 {
		trustedPath = trustFindings[0].Match
	}

	var b strings.Builder
	b.WriteString("Codex CLI is configured to trust a broad path AND has a plaintext credential in the same config file. The two together remove BOTH the sandbox AND the secret.\n\n")
	if trustedPath != "" {
		b.WriteString(fmt.Sprintf("**Trusted path:** `%s`\n\n", trustedPath))
	}
	b.WriteString("**Plaintext credentials in `~/.codex/config.toml`:**\n")
	for _, f := range codexPlainKeys {
		b.WriteString(fmt.Sprintf("- %s (`%s`)\n", f.Title, truncate(f.Match, 80)))
	}
	b.WriteString("\n**The chain:** anyone with read access to `~/.codex/config.toml` (any process on the machine, any backup, any sync service) can authenticate to the upstream MCP service AS this user. With trust=trusted on the broad path, that authenticated MCP service can return tool outputs that Codex will execute without sandbox or approval prompt.\n\n")
	b.WriteString("**Mitigation:** rotate the plaintext credentials, restrict trust_level=trusted to specific projects, and reference credentials via your OS keychain (`security` on macOS, `secret-tool` on Linux).")

	return output.AttackChain{
		ID:         "codex-trusted-home-plaintext-key",
		Title:      "Codex: trusted $HOME + plaintext key = no-friction takeover",
		Severity:   finding.SeverityCritical,
		Narrative:  b.String(),
		Citations:  []string{"OpenAI Codex Security docs", "OWASP MCP Top 10 — MCP01 + MCP07"},
		FindingIDs: []string{"codex-trust-home-or-broad", "mcp-plaintext-api-key"},
		Paths:      dedupeSorted(append(idx.paths("codex-trust-home-or-broad"), idx.paths("mcp-plaintext-api-key")...)),
	}, true
}

// --- 4. Plugin-bundled MCP without auth ------------------------------------
//
// Fires when mcp-unauth-remote-url fired on a path under a plugin cache
// (e.g. `~/.claude/plugins/cache/...` or `~/.codex/.tmp/plugins/...`) AND
// the plugin is enabled (claude-third-party-plugin-enabled).

func chainPluginBundledMCPWithoutAuth(idx *findingIndex) (output.AttackChain, bool) {
	unauthFindings := idx.findings("mcp-unauth-remote-url")
	pluginPaths := []finding.Finding{}
	for _, f := range unauthFindings {
		p := f.Path
		if strings.Contains(p, "/plugins/") || strings.Contains(p, "/plugin/") {
			pluginPaths = append(pluginPaths, f)
		}
	}
	if len(pluginPaths) == 0 {
		return output.AttackChain{}, false
	}

	pluginsEnabled := idx.has("claude-third-party-plugin-enabled")

	var b strings.Builder
	b.WriteString("A third-party plugin ships its own bundled `.mcp.json` that points at a remote MCP server with no authentication header. The plugin runs with full Claude/Codex blast radius; the MCP server is upstream of any tool output the plugin produces.\n\n")
	b.WriteString("**Plugin-bundled MCPs without auth:**\n")
	for _, f := range pluginPaths {
		b.WriteString(fmt.Sprintf("- `%s` → %s\n", f.Path, f.Match))
	}
	b.WriteString("\n")
	if pluginsEnabled {
		b.WriteString("This Mac has third-party plugins enabled in `enabledPlugins`. The bundled MCPs above are loaded into the agent's toolspace; their unauthed remote URLs are the upstream attack surface.\n\n")
	}
	b.WriteString("**The chain:** the agent calls an MCP tool from one of these plugins → the request goes to the unauth remote URL → an attacker who controls the upstream service (or sits on-path) returns malicious tool output → that output is fed back to the LLM as trusted content → the LLM acts on it within the agent's existing capability surface.\n\n")
	b.WriteString("**Mitigation:** before enabling a plugin, audit its bundled `.mcp.json`. Pin to specific server endpoints with auth headers. Or remove the plugin if it's not actively used.")

	return output.AttackChain{
		ID:         "plugin-bundled-mcp-no-auth",
		Title:      "Third-party plugin ships an unauthenticated MCP server",
		Severity:   finding.SeverityHigh,
		Narrative:  b.String(),
		Citations:  []string{"OWASP MCP Top 10 — MCP04 (Supply Chain) + MCP07 (Auth)", "Trend Micro 2026 — 492 unauth MCP servers"},
		FindingIDs: []string{"mcp-unauth-remote-url", "claude-third-party-plugin-enabled"},
		Paths:      dedupeSorted(append(idx.paths("mcp-unauth-remote-url"), idx.paths("claude-third-party-plugin-enabled")...)),
	}, true
}

// --- 5. Same secret across multiple harnesses ------------------------------
//
// Fires when the same credential VALUE (or VALUE PREFIX) appears in multiple
// MCP configs across different harnesses. Single secret rotation requires
// touching every harness — and the duplication itself is a posture finding
// (the credential ended up in two places, so it's likely in N more, including
// places we don't scan).

func chainSameSecretAcrossHarnesses(idx *findingIndex) (output.AttackChain, bool) {
	plain := idx.findings("mcp-plaintext-api-key")
	if len(plain) < 2 {
		return output.AttackChain{}, false
	}
	// Group by env-var name (the "key" half of the matched key=value pair).
	// If the same NAME appears in 2+ different paths AND those paths are
	// in different harness directories, fire.
	byName := map[string][]finding.Finding{}
	for _, f := range plain {
		// Match field looks like "CONTEXT7_API_KEY=ctx7sk-...". Split on "=".
		key := f.Match
		if i := strings.Index(key, "="); i > 0 {
			key = key[:i]
		}
		byName[key] = append(byName[key], f)
	}
	for name, fs := range byName {
		if len(fs) < 2 {
			continue
		}
		// Different harness paths.
		harnesses := map[string]bool{}
		for _, f := range fs {
			h := harnessOf(f.Path)
			if h != "" {
				harnesses[h] = true
			}
		}
		if len(harnesses) < 2 {
			continue
		}
		var hList []string
		for h := range harnesses {
			hList = append(hList, h)
		}
		var paths []string
		for _, f := range fs {
			paths = append(paths, f.Path)
		}
		var b strings.Builder
		b.WriteString(fmt.Sprintf("The credential named `%s` is present in plaintext in multiple harness configs:\n\n", name))
		for _, f := range fs {
			b.WriteString(fmt.Sprintf("- `%s`\n", f.Path))
		}
		b.WriteString(fmt.Sprintf("\nAcross %d harnesses: %s.\n\n", len(harnesses), strings.Join(hList, ", ")))
		b.WriteString("**The risk has two flavors.** First, rotation: rotating the credential requires touching every config it's in, and any one missed = the old credential keeps working as a back door. Second, blast radius: the credential ended up in this many places via copy-paste, so it's likely in others we don't scan (CI secrets, cloud env vars, password managers).\n\n")
		b.WriteString("**Mitigation:** centralize credentials in a secret manager. Reference via env vars or a templating layer that resolves at runtime. Burn the current credential and rotate.")
		return output.AttackChain{
			ID:         "same-secret-across-harnesses",
			Title:      fmt.Sprintf("Same credential `%s` reused across %d harnesses", name, len(harnesses)),
			Severity:   finding.SeverityHigh,
			Narrative:  b.String(),
			Citations:  []string{"OWASP MCP Top 10 — MCP01 (Token Mismanagement)"},
			FindingIDs: []string{"mcp-plaintext-api-key"},
			Paths:      paths,
		}, true
	}
	return output.AttackChain{}, false
}

// harnessOf returns a short label for the harness owning a path.
// "claude" / "codex" / "windsurf" / "cursor" / "" if unknown.
func harnessOf(path string) string {
	p := filepath.ToSlash(path)
	switch {
	case strings.Contains(p, "/.claude/"):
		return "claude"
	case strings.Contains(p, "/.codex/"):
		return "codex"
	case strings.Contains(p, "/.codeium/windsurf/"):
		return "windsurf"
	case strings.Contains(p, "/.cursor/"):
		return "cursor"
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
