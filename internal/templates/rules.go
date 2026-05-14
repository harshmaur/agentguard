package templates

import (
	"fmt"

	"github.com/harshmaur/audr/internal/state"
)

// registerNativeRules installs handlers for the 20 v0.2 built-in
// audr rules. Each handler reads the finding's locator to produce
// a path-aware human-step list + a paste-ready AI prompt.
//
// Mini-Shai-Hulud and OpenClaw-specific rules (added post-v0.2)
// don't have hand-authored templates here — they fall through to
// the AI-agent category fallback in fallback.go which produces a
// useful generic prompt based on Title + Description.
func registerNativeRules(r *Registry) {
	// --- Codex CLI ---------------------------------------------------
	r.registerRule("codex-trust-home-or-broad", codexTrustHomeOrBroad)
	r.registerRule("codex-approval-disabled", codexApprovalDisabled)

	// --- Claude Code -------------------------------------------------
	r.registerRule("claude-hook-shell-rce", claudeHookShellRCE)
	r.registerRule("claude-skip-permission-prompt", claudeSkipPermissionPrompt)
	r.registerRule("claude-mcp-auto-approve", claudeMCPAutoApprove)
	r.registerRule("claude-bash-allowlist-too-broad", claudeBashAllowlistTooBroad)
	r.registerRule("claude-third-party-plugin-enabled", claudeThirdPartyPluginEnabled)

	// --- Cursor ------------------------------------------------------
	r.registerRule("cursor-allowlist-too-broad", cursorAllowlistTooBroad)
	r.registerRule("cursor-mcp-wildcard", cursorMCPWildcard)

	// --- MCP (cross-harness) ----------------------------------------
	r.registerRule("mcp-plaintext-api-key", mcpPlaintextAPIKey)
	r.registerRule("mcp-unpinned-npx", mcpUnpinnedNpx)
	r.registerRule("mcp-unauth-remote-url", mcpUnauthRemoteURL)
	r.registerRule("mcp-prod-secret-env", mcpProdSecretEnv)
	r.registerRule("mcp-shell-pipeline-command", mcpShellPipelineCommand)
	r.registerRule("mcp-dynamic-config-injection", mcpDynamicConfigInjection)

	// --- Skill / agent-doc ------------------------------------------
	r.registerRule("skill-shell-hijack", skillShellHijack)
	r.registerRule("skill-undeclared-dangerous-tool", skillUndeclaredDangerousTool)

	// --- GitHub Actions ---------------------------------------------
	r.registerRule("gha-write-all-permissions", ghaWriteAllPermissions)
	r.registerRule("gha-secrets-in-agent-step", ghaSecretsInAgentStep)

	// --- Shell rc ---------------------------------------------------
	r.registerRule("shellrc-secret-export", shellrcSecretExport)
}

// --- Codex CLI ------------------------------------------------------

func codexTrustHomeOrBroad(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	if path == "" {
		path = "~/.codex/config.toml"
	}
	human := fmt.Sprintf(`1. Open %s
2. Find the [projects."<path>"] block whose trust_level = "trusted" covers $HOME or a broad parent
3. Change trust_level to "on_request" (or remove the block to let Codex prompt per-project)
4. Move any api_key field out of the same file into ~/.codex/secrets.toml (chmod 0600) or an environment variable
5. Run: codex doctor to confirm the new config parses cleanly`, path)
	ai := fmt.Sprintf(`In %s, find every [projects."<path>"] block whose trust_level = "trusted" covers $HOME, /, /Users, /home, or a single-segment-from-root parent. For each one, either change trust_level to "on_request" or delete the block entirely. If the same file contains a plaintext api_key, move it to ~/.codex/secrets.toml (mode 0600) or replace with an env-var reference. Preserve all other settings. Confirm the resulting TOML parses with `+"`codex doctor`"+`. Do not modify any other file.`, path)
	return human, ai, true
}

func codexApprovalDisabled(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	if path == "" {
		path = "~/.codex/config.toml"
	}
	human := fmt.Sprintf(`1. Open %s
2. Find the approval_policy and sandbox_mode keys
3. Set approval_policy = "on-request" (or "untrusted" for tighter control)
4. Set sandbox_mode = "workspace-write" (the documented safe default)
5. Run: codex doctor`, path)
	ai := fmt.Sprintf(`In %s, set approval_policy to "on-request" and sandbox_mode to "workspace-write". These are the safer defaults; the current values bypass Codex's approval gate. Preserve all other keys in the file. Confirm the file parses with `+"`codex doctor`"+`.`, path)
	return human, ai, true
}

// --- Claude Code ----------------------------------------------------

func claudeHookShellRCE(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	if path == "" {
		path = "~/.claude/settings.json"
	}
	human := fmt.Sprintf(`1. Open %s
2. Locate the hook or statusLine entry whose command runs a shell expression with untrusted input
3. Replace the shell-expression form with a fixed argv (e.g., change "echo $USER_INPUT" to a static command, or remove the hook entirely if it's not load-bearing)
4. Save and restart Claude Code
5. CVE-2025-59536 reference: hooks/statusLine fields that run shell commands are RCE-equivalent when the repo (or someone you trust) can write to this file`, path)
	ai := fmt.Sprintf(`%s contains a Claude Code hook or statusLine entry whose command runs a shell expression that could be RCE-equivalent (CVE-2025-59536 class). Read the file, identify the offending entry by its hook/statusLine field, and either: (a) replace the shell-form command with a fixed argv array, or (b) delete the entry if it's not actively used. Preserve all other settings. Do not modify any other file.`, path)
	return human, ai, true
}

func claudeSkipPermissionPrompt(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	if path == "" {
		path = "~/.claude/settings.json"
	}
	human := fmt.Sprintf(`1. Open %s
2. Remove any "skipAutoPermissionPrompt": true or "skipDangerousModePermissionPrompt": true entries
3. Save the file
4. Restart Claude Code if it's running`, path)
	ai := fmt.Sprintf(`In %s, find the skipAutoPermissionPrompt and skipDangerousModePermissionPrompt fields (if present) and set them to false, or remove them entirely so Claude Code falls back to the default consent flow. Preserve all other settings. Confirm the file parses as valid JSON.`, path)
	return human, ai, true
}

func claudeMCPAutoApprove(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	if path == "" {
		path = "~/.claude/settings.json"
	}
	human := fmt.Sprintf(`1. Open %s
2. Locate the mcpServers entry marked auto-approve (or with permissive defaults)
3. Remove the auto-approve flag, or scope it to a specific tool/scope list rather than wildcard
4. Restart Claude Code`, path)
	ai := fmt.Sprintf(`In %s, find the MCP server entry that has auto-approve enabled and either disable it or restrict it to an explicit allowlist of tools. The current setting lets the MCP server run arbitrary tools without consent. Preserve all other settings.`, path)
	return human, ai, true
}

func claudeBashAllowlistTooBroad(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	if path == "" {
		path = "~/.claude/settings.json"
	}
	human := fmt.Sprintf(`1. Open %s
2. Find the permissions.allow entries with broad bash patterns like "Bash(rm:*)" or "Bash(curl:*)"
3. Narrow each entry to specific commands you actually want auto-approved (e.g., "Bash(git status)", "Bash(npm test)")
4. Save and restart Claude Code`, path)
	ai := fmt.Sprintf(`In %s under permissions.allow, find Bash() entries that allow dangerous verbs with arg-wildcards (rm:*, curl:*, sudo:*, sh:*, etc.) and replace each with a tighter pattern matching only the specific commands the user actually wants pre-approved. Preserve all non-Bash permission entries.`, path)
	return human, ai, true
}

func claudeThirdPartyPluginEnabled(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	if path == "" {
		path = "~/.claude/settings.json"
	}
	human := fmt.Sprintf(`1. Open %s
2. Find the enabledPlugins entry for the third-party (non-Anthropic) marketplace
3. If you don't recognize or trust the source, remove that single plugin entry from enabledPlugins
4. Save the file and restart Claude Code`, path)
	ai := fmt.Sprintf(`In %s, list the entries in enabledPlugins that come from non-Anthropic marketplaces. Ask the user whether to keep them. If the user says remove, take that plugin out of enabledPlugins while preserving all other entries. Do not modify any other file.`, path)
	return human, ai, true
}

// --- Cursor ---------------------------------------------------------

func cursorAllowlistTooBroad(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	if path == "" {
		path = "~/.cursor/settings.json"
	}
	human := fmt.Sprintf(`1. Open %s
2. Find the terminalAllowlist entries with broad patterns (e.g., "rm:*", "sudo:*", "curl:*")
3. Narrow each to the specific commands you actually want auto-approved
4. Restart Cursor`, path)
	ai := fmt.Sprintf(`In %s, find terminalAllowlist entries with dangerous-verb arg-wildcards (rm:*, sudo:*, curl:*, etc.) and replace each with a narrower pattern. Preserve all other settings.`, path)
	return human, ai, true
}

func cursorMCPWildcard(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	if path == "" {
		path = "~/.cursor/mcp.json"
	}
	human := fmt.Sprintf(`1. Open %s
2. Find the MCP entry with a wildcard match (e.g., "*" in mcpAllowlist)
3. Replace the wildcard with the specific MCP server names you actually trust
4. Restart Cursor`, path)
	ai := fmt.Sprintf(`In %s, find the wildcard ("*") match in the MCP allowlist and replace it with an explicit list of MCP server names. The user should review which servers are running and keep only the ones they recognize. Preserve other settings.`, path)
	return human, ai, true
}

// --- MCP (cross-harness) --------------------------------------------

func mcpPlaintextAPIKey(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	human := fmt.Sprintf(`1. Open %s
2. Find the MCP server entry whose env block contains a plaintext API key
3. ROTATE the key at the provider's dashboard first (treat it as compromised)
4. Move the key to a secrets manager (1Password CLI, macOS Keychain, env file outside this config) and reference it via env-var substitution
5. Restart the MCP-consuming agent`, path)
	ai := fmt.Sprintf(`%s contains an MCP server config with a plaintext API key in its env block. The key should be considered compromised. Help the user: (1) print the URL where they rotate the key at the provider's dashboard, (2) edit the file to replace the literal key with an env-var reference (e.g., "${MY_API_KEY}"), and (3) suggest a secrets-manager-backed env source. Do not modify any other file.`, path)
	return human, ai, true
}

func mcpUnpinnedNpx(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	line := loc.Int("line")
	lineSuffix := ""
	if line > 0 {
		lineSuffix = fmt.Sprintf(" (line %d)", line)
	}
	human := fmt.Sprintf(`1. Open %s%s
2. Find the MCP entry using "npx <package>@latest" or "npx <package>" (no version)
3. Look up the package's current stable version on npmjs.com
4. Replace @latest with the exact version (e.g., @1.4.2)
5. Restart the MCP-consuming agent`, path, lineSuffix)
	ai := fmt.Sprintf(`In %s, an MCP server is invoked with "npx <package>@latest" which downloads and executes whatever is currently published on npm. Look up the package's latest stable version (use a specific semver, not @latest) and edit the file to pin to that exact version. Preserve all other settings.`, path)
	return human, ai, true
}

func mcpUnauthRemoteURL(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	human := fmt.Sprintf(`1. Open %s
2. Find the MCP server entry pointing at a remote HTTPS URL with no Authorization header
3. Either: (a) add an Authorization header to the headers block (e.g., "Bearer ${MY_TOKEN}"), or (b) replace the remote URL with a local equivalent if one exists
4. If the URL is for a third-party service you don't fully trust, consider removing the MCP entry entirely`, path)
	ai := fmt.Sprintf(`In %s, find the MCP server entry with a remote HTTPS URL and no Authorization header. Either add a Bearer token via the headers block (referencing an env var, never a literal token) or remove the entry if the user doesn't recognize the host. Preserve all other settings.`, path)
	return human, ai, true
}

func mcpProdSecretEnv(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	human := fmt.Sprintf(`1. Open %s
2. Find the env block containing a production-shaped secret (key with prod-/PROD-/_prod_ in the name, or a known production credential value)
3. ROTATE the credential first — it's been on disk in a config file an attacker may have read
4. Replace the literal value with an env-var reference and load it from a secrets manager
5. Restart the MCP-consuming agent`, path)
	ai := fmt.Sprintf(`In %s, an MCP env block contains what looks like a production credential. Help the user (1) rotate the credential at its provider, (2) replace the literal in the file with an env-var reference, (3) point at a secrets-manager-backed loader. Do not modify any other file.`, path)
	return human, ai, true
}

func mcpShellPipelineCommand(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	human := fmt.Sprintf(`1. Open %s
2. Find the MCP "command" field containing a shell pipeline (uses |, ;, &&, ||, $(...), or backticks)
3. Replace the shell-form command with a fixed argv array, or split the work into a small wrapper script you commit explicitly
4. Restart the MCP-consuming agent`, path)
	ai := fmt.Sprintf(`In %s, an MCP "command" field uses shell metacharacters (|, ;, &&, $(...) etc.) which gives the running process shell-equivalent semantics. Convert the command to a fixed argv array or move the pipeline into a separate script. Preserve all other settings.`, path)
	return human, ai, true
}

func mcpDynamicConfigInjection(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	human := fmt.Sprintf(`1. Open %s
2. Find the MCP field whose value is interpolated from env/argv at config-load time
3. Replace the dynamic interpolation with a static value, or move the dynamic decision into a small wrapper script with explicit allowlists
4. Restart the MCP-consuming agent`, path)
	ai := fmt.Sprintf(`In %s, an MCP config field is interpolated from environment or argv at load time, which lets a malicious caller alter the MCP's behavior. Replace the dynamic source with a static value, or constrain it to an explicit allowlist via a wrapper. Preserve other settings.`, path)
	return human, ai, true
}

// --- Skill / agent-doc ----------------------------------------------

func skillShellHijack(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	human := fmt.Sprintf(`1. Open %s
2. Identify the shell-hijack pattern: curl|bash, eval, base64-decode-then-execute, etc.
3. Replace it with a vetted equivalent that doesn't fetch + execute remote code in one step (download first, verify checksum, then execute)
4. Save the skill and re-validate by running the skill in a sandbox`, path)
	ai := fmt.Sprintf(`%s contains a skill body with a shell-hijack pattern (curl|bash, eval of remote content, base64-decode-and-execute, or similar). Rewrite the offending command to (a) download the asset to a tempfile, (b) compute and verify a checksum, (c) only then execute. Preserve the rest of the skill body.`, path)
	return human, ai, true
}

func skillUndeclaredDangerousTool(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	human := fmt.Sprintf(`1. Open %s
2. Find the frontmatter "tools:" field at the top of the file
3. Add Bash, Edit, and/or Write to the tools list (whichever the skill body actually uses)
4. Save the file. Restart your coding agent if it caches skill metadata.`, path)
	ai := fmt.Sprintf(`The skill at %s uses Bash, Edit, or Write tools in its body but doesn't declare them in the frontmatter. Read the skill body, identify which of those tools it actually invokes, and update the frontmatter "tools:" field to include them. Preserve all other frontmatter fields and the skill body.`, path)
	return human, ai, true
}

// --- GitHub Actions -------------------------------------------------

func ghaWriteAllPermissions(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	human := fmt.Sprintf(`1. Open %s
2. Find the top-level permissions: write-all (or per-job permissions: write-all)
3. Replace with the minimum permissions actually needed (e.g., contents: read, pull-requests: write)
4. Commit the change`, path)
	ai := fmt.Sprintf(`In the GitHub Actions workflow %s, find permissions: write-all entries (at workflow or job scope) and replace them with the minimum permissions the workflow actually needs. Look at what the workflow does (does it write commits? upload artifacts? comment on PRs?) and grant only those scopes. Preserve all other workflow content.`, path)
	return human, ai, true
}

func ghaSecretsInAgentStep(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	human := fmt.Sprintf(`1. Open %s
2. Find the step that invokes a coding agent (Claude/Codex/Cursor/Aider/etc.) AND passes secrets via env or with: inputs
3. Remove the secrets from that step. If the agent legitimately needs them, scope to a single secret rather than the full secrets context.
4. Consider whether this step should run in a separate, secret-less job that the agent triggers via output instead`, path)
	ai := fmt.Sprintf(`In %s, find any workflow step that invokes a coding agent (Claude Code, Codex, Cursor, Aider, etc.) AND has access to secrets via env or inputs. Move the secrets out: either scope to a single named secret if absolutely required, or split the secret-using work into a separate job. Preserve the rest of the workflow.`, path)
	return human, ai, true
}

// --- Shell rc -------------------------------------------------------

func shellrcSecretExport(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	human := fmt.Sprintf(`1. ROTATE the credential at its provider first — anything on disk in a shell rc has been seen by every process you've launched
2. Open %s
3. Remove the export statement for the credential
4. Add the credential to a secrets manager (1Password CLI, macOS Keychain, .envrc with direnv + age, etc.) and reference it just-in-time
5. Source the file or open a new shell session to confirm the credential is no longer exported`, path)
	ai := fmt.Sprintf(`%s contains an export statement for a token-shaped credential. Help the user (1) rotate the credential at its provider, (2) print the URL where they do that, (3) remove the export line from the file, and (4) suggest a secrets-manager-backed alternative for surfacing it on demand. Do not modify any other file.`, path)
	return human, ai, true
}
