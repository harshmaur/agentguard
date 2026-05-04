// Package builtin registers Audr's built-in rule corpus.
//
// Import this package for side effects (`_ "...internal/rules/builtin"`)
// so init() registers every rule with the global registry.
//
// File organization mirrors internal/parse/: one file per format-family.
// claude.go owns rules over Claude Code settings, codex.go owns Codex
// CLI rules, etc. mcp.go owns rules that operate over the normalized
// MCP server model and fire across .mcp.json + Codex TOML + Windsurf JSON.
package builtin

import (
	"github.com/harshmaur/audr/internal/rules"
)

func init() {
	for _, r := range builtins() {
		rules.Register(r)
	}
}

// builtins returns the rule list. Order doesn't affect runtime; rules are
// registered by ID. The list groups by format-family for readability.
//
// Stable contract: rule IDs do NOT change across releases. Adding a new
// rule appends to the appropriate group. Removing a rule is a breaking
// change and must be announced in CHANGELOG.
func builtins() []rules.Rule {
	return []rules.Rule{
		// MCP rules — fire across all MCP-bearing config formats.
		mcpUnpinnedNPX{},
		mcpProdSecretEnv{},
		mcpShellPipelineCommand{},
		mcpPlaintextAPIKey{},
		mcpDynamicConfigInjection{},
		mcpUnauthRemoteURL{},

		// Claude Code rules.
		claudeHookShellRCE{},
		claudeSkipPermissionPrompt{},
		claudeMCPAutoApprove{},
		claudeBashAllowlistTooBroad{},
		claudeThirdPartyPluginEnabled{},

		// Codex CLI rules.
		codexApprovalDisabled{},
		codexTrustHomeOrBroad{},

		// Cursor permissions.json rules.
		cursorAllowlistTooBroad{},
		cursorMCPWildcard{},

		// Skill (markdown) rules.
		skillShellHijack{},
		skillUndeclaredDangerousTool{},

		// GitHub Actions rules.
		ghaWriteAllPermissions{},
		ghaSecretsInAgentStep{},

		// Shell rc rules.
		shellrcSecretExport{},

		// package.json version posture rules.
		openclawUnboundBootstrapSetupCode{},
		openclawConfigPatchConsentBypass{},
		openclawWebsocketUpgradeExhaustion{},
		openclawNodePairApproveScopeBypass{},
		openclawPluginAuthOperatorWriteBypass{},
		openclawTeamsWebhookPreauthBodyDos{},
		openclawBundledHooksEnvOverride{},
	}
}
