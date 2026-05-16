package templates

import (
	"fmt"
	"strings"

	"github.com/harshmaur/audr/internal/state"
)

// registerSecretHandlers installs handlers for kind="file" findings
// produced by Betterleaks. The rule IDs are:
//
//   secret-betterleaks-valid       — Betterleaks validated the secret is live
//   secret-betterleaks-unverified  — looks like a secret but Betterleaks
//                                    couldn't actively validate
//
// The remediation is the same shape regardless of validation status
// (rotate first, scrub second), but the urgency differs — valid
// secrets are critical, unverified are advisory.
func registerSecretHandlers(r *Registry) {
	r.registerRule("secret-betterleaks-valid", secretRotation(true))
	r.registerRule("secret-betterleaks-unverified", secretRotation(false))
}

func secretRotation(verified bool) Handler {
	return func(f state.Finding, loc Locator) (string, string, bool) {
		path := loc.String("path")
		line := loc.Int("line")
		ruleName := extractRuleNameFromMatch(f.MatchRedacted)
		provider := rotationProvider(ruleName)

		urgency := "Probable"
		if verified {
			urgency = "ACTIVE"
		}

		lineSuffix := ""
		if line > 0 {
			lineSuffix = fmt.Sprintf(" (line %d)", line)
		}

		human := fmt.Sprintf(`%s secret detected at %s%s — rule: %s

1. ROTATE FIRST. Open %s and create a new credential. Treat the leaked one as compromised: it should be invalidated server-side before you do anything else.
2. Remove the leaked value from the file: edit %s%s and replace the literal value with an env-var reference (or delete the line if the file shouldn't carry secrets).
3. If the file is git-tracked, scrub git history too (consider git-filter-repo or BFG; alternatively, force-push a rewritten history if collaborators are coordinated).
4. Audit for sibling copies: grep for the same value across $HOME, other repos, recent Slack/email/Notion exports.
5. Rerun audr scan to confirm the finding cleared.`,
			urgency, path, lineSuffix, ruleLabel(ruleName),
			provider, path, lineSuffix)

		ai := fmt.Sprintf(`A %s secret was detected at %s%s. Betterleaks rule: %s. The leaked value should already be considered compromised.

Help me handle this:
1. Print the URL for rotating credentials at %s and tell me to do that FIRST before touching the file.
2. Once I confirm rotation, edit %s to replace the literal credential at line %d with an env-var reference (or delete the line entirely if the file shouldn't carry secrets). Preserve everything else in the file.
3. Grep the rest of $HOME for the same redacted-shape value so I can find sibling copies in other repos / transcripts / config files. Do not print the redacted value back to me; reason about it abstractly.
4. If the file is in a git repository, suggest the rewrite path (filter-repo / BFG) with one example command — but do NOT run it.
5. Tell me to rerun "audr open" to confirm the finding clears once I fix the file.

Do not modify any file other than %s.`,
			strings.ToLower(urgency), path, lineSuffix, ruleLabel(ruleName),
			provider, path, line, path)

		return human, ai, true
	}
}

// extractRuleNameFromMatch parses Betterleaks' Match field as
// emitted by audr's normalizer: `rule=<rule-id> secret=[REDACTED]`.
// Returns the rule-id for routing to the right provider rotation URL.
func extractRuleNameFromMatch(match string) string {
	for _, part := range strings.Fields(match) {
		if strings.HasPrefix(part, "rule=") {
			return strings.TrimPrefix(part, "rule=")
		}
	}
	return ""
}

// rotationProvider maps a Betterleaks rule-id to the URL where the
// user rotates that credential. We cover the most common ~15 rules
// from betterleaks's default ruleset by hit-frequency on real dev
// machines. Unknown rules fall back to a generic message.
//
// Rule IDs are betterleaks's stable identifiers (lowercase-kebab),
// not human display names. Source of truth:
// https://github.com/betterleaks/betterleaks/blob/main/config/betterleaks.toml
func rotationProvider(rule string) string {
	switch strings.ToLower(rule) {
	case "aws-access-token", "aws-secret-access-key":
		return "the AWS IAM console (https://console.aws.amazon.com/iam/) — rotate via Users → Security credentials → Access keys → Make inactive + Create new"
	case "github-pat", "github-oauth", "github-app-token", "github-fine-grained-pat":
		return "https://github.com/settings/tokens — find the leaked token, click Delete, generate a fresh PAT with the same scope set"
	case "openai-api-key":
		return "https://platform.openai.com/api-keys — revoke the leaked key, create a new one"
	case "anthropic-api-key":
		return "https://console.anthropic.com/settings/keys — revoke the leaked key, create a fresh one"
	case "stripe-access-token", "stripe-restricted-key":
		return "https://dashboard.stripe.com/apikeys — Roll the key (test or live tab as appropriate)"
	case "slack-bot-token", "slack-user-token", "slack-app-token", "slack-config-access-token":
		return "https://api.slack.com/apps/<your-app> → OAuth & Permissions → Reinstall App (or rotate the bot/user token)"
	case "gcp-api-key", "gcp-service-account":
		return "https://console.cloud.google.com/iam-admin/serviceaccounts — find the service account, Keys tab, Delete the leaked key, Add a new one"
	case "discord-bot-token", "discord-api-token", "discord-webhook":
		return "https://discord.com/developers/applications/<app>/bot → Reset Token"
	case "twilio-api-key":
		return "https://console.twilio.com/us1/account/keys-credentials/api-keys — disable the leaked key, create new"
	case "sendgrid-api-token":
		return "https://app.sendgrid.com/settings/api_keys — delete the leaked key, create new"
	case "private-key":
		return "the system where this private key is trusted — revoke it from the authorized_keys / known issuer list, then generate a fresh keypair"
	case "jwt":
		return "the JWT issuer's signing-key rotation flow — invalidate the signing secret/key, force re-auth of clients, then issue tokens under the new key"
	case "telegram-bot-api-token":
		return "https://t.me/BotFather → /revoke → pick the bot → confirm revoke, then /token to issue a fresh one"
	case "openrouter-api-key":
		return "https://openrouter.ai/keys — delete the leaked key, create a new one"
	case "cloudflare-api-key", "cloudflare-global-api-key", "cloudflare-origin-ca-key":
		return "https://dash.cloudflare.com/profile/api-tokens — delete the leaked token, create a fresh one with the same scope"
	case "generic-api-key":
		return "the provider's API-keys / credentials management page — Betterleaks' generic-api-key rule fires on high-entropy values without a specific provider signature, so the rotation flow depends on which service the key actually belongs to"
	default:
		return "the provider's API-keys / credentials management page (look up where this rule's credential type rotates)"
	}
}

func ruleLabel(rule string) string {
	if rule == "" {
		return "(unknown)"
	}
	return rule
}
