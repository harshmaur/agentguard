package templates

import (
	"fmt"
	"strings"

	"github.com/harshmaur/audr/internal/state"
)

// registerSecretHandlers installs handlers for kind="file" findings
// produced by TruffleHog. The rule IDs are:
//
//   secret-trufflehog-verified   — TruffleHog verified the secret is live
//   secret-trufflehog-unverified — looks like a secret but TruffleHog
//                                  couldn't actively verify with the provider
//
// The remediation is the same shape regardless of verification status
// (rotate first, scrub second), but the urgency differs — verified
// secrets are critical, unverified are advisory.
func registerSecretHandlers(r *Registry) {
	r.registerRule("secret-trufflehog-verified", secretRotation(true))
	r.registerRule("secret-trufflehog-unverified", secretRotation(false))
}

func secretRotation(verified bool) Handler {
	return func(f state.Finding, loc Locator) (string, string, bool) {
		path := loc.String("path")
		line := loc.Int("line")
		detector := extractDetectorFromMatch(f.MatchRedacted)
		provider := rotationProvider(detector)

		urgency := "Probable"
		if verified {
			urgency = "ACTIVE"
		}

		lineSuffix := ""
		if line > 0 {
			lineSuffix = fmt.Sprintf(" (line %d)", line)
		}

		human := fmt.Sprintf(`%s secret detected at %s%s — detector: %s

1. ROTATE FIRST. Open %s and create a new credential. Treat the leaked one as compromised: it should be invalidated server-side before you do anything else.
2. Remove the leaked value from the file: edit %s%s and replace the literal value with an env-var reference (or delete the line if the file shouldn't carry secrets).
3. If the file is git-tracked, scrub git history too (consider git-filter-repo or BFG; alternatively, force-push a rewritten history if collaborators are coordinated).
4. Audit for sibling copies: grep for the same value across $HOME, other repos, recent Slack/email/Notion exports.
5. Rerun audr scan to confirm the finding cleared.`,
			urgency, path, lineSuffix, detectorLabel(detector),
			provider, path, lineSuffix)

		ai := fmt.Sprintf(`A %s secret was detected at %s%s. TruffleHog detector: %s. The leaked value should already be considered compromised.

Help me handle this:
1. Print the URL for rotating credentials at %s and tell me to do that FIRST before touching the file.
2. Once I confirm rotation, edit %s to replace the literal credential at line %d with an env-var reference (or delete the line entirely if the file shouldn't carry secrets). Preserve everything else in the file.
3. Grep the rest of $HOME for the same redacted-shape value so I can find sibling copies in other repos / transcripts / config files. Do not print the redacted value back to me; reason about it abstractly.
4. If the file is in a git repository, suggest the rewrite path (filter-repo / BFG) with one example command — but do NOT run it.
5. Tell me to rerun "audr open" to confirm the finding clears once I fix the file.

Do not modify any file other than %s.`,
			strings.ToLower(urgency), path, lineSuffix, detectorLabel(detector),
			provider, path, line, path)

		return human, ai, true
	}
}

// extractDetectorFromMatch parses TruffleHog's Match field. depscan-
// style format: `detector=<name> secret=<redacted>`. We extract the
// detector for routing to the right provider rotation URL.
func extractDetectorFromMatch(match string) string {
	for _, part := range strings.Fields(match) {
		if strings.HasPrefix(part, "detector=") {
			return strings.TrimPrefix(part, "detector=")
		}
	}
	return ""
}

// rotationProvider maps a TruffleHog detector name to the URL where
// the user rotates that credential. We cover the most common ~10
// detectors by hit-frequency on real dev machines. Unknown detectors
// fall back to a generic message.
func rotationProvider(detector string) string {
	switch strings.ToLower(detector) {
	case "aws", "awsaccesskey":
		return "the AWS IAM console (https://console.aws.amazon.com/iam/) — rotate via Users → Security credentials → Access keys → Make inactive + Create new"
	case "github", "githubtoken":
		return "https://github.com/settings/tokens — find the leaked token, click Delete, generate a fresh PAT with the same scope set"
	case "githubapp":
		return "https://github.com/settings/apps/<app-name> — rotate the client secret via Settings → Generate a new client secret"
	case "openai":
		return "https://platform.openai.com/api-keys — revoke the leaked key, create a new one"
	case "anthropic", "anthropicapikey":
		return "https://console.anthropic.com/settings/keys — revoke the leaked key, create a fresh one"
	case "stripe", "stripeapikey", "stripeapikey_live":
		return "https://dashboard.stripe.com/apikeys — Roll the key (test or live tab as appropriate)"
	case "slack", "slacktoken":
		return "https://api.slack.com/apps/<your-app> → OAuth & Permissions → Reinstall App (or rotate the bot/user token)"
	case "gcp", "gcpserviceaccountkey":
		return "https://console.cloud.google.com/iam-admin/serviceaccounts — find the service account, Keys tab, Delete the leaked key, Add a new one"
	case "discord", "discordbottoken":
		return "https://discord.com/developers/applications/<app>/bot → Reset Token"
	case "twilio", "twilioapikey":
		return "https://console.twilio.com/us1/account/keys-credentials/api-keys — disable the leaked key, create new"
	case "sendgrid", "sendgridapikey":
		return "https://app.sendgrid.com/settings/api_keys — delete the leaked key, create new"
	default:
		return "the provider's API-keys / credentials management page (look up where this detector type rotates keys)"
	}
}

func detectorLabel(detector string) string {
	if detector == "" {
		return "(unknown)"
	}
	return detector
}
