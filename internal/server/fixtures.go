package server

// demoFindings + demoRemediation are the hardcoded findings the Phase 2
// visual slice serves so the user can see the dashboard rendering real
// data before Phase 4 wires actual scan results.
//
// The shapes here are the same as what Phase 4 will produce — Phase 4's
// job is to populate the same FindingView / RemediationResponse from
// the scan engine, not to redefine the wire contract.

func demoFindings() []FindingView {
	return []FindingView{
		{
			Fingerprint: "demo-codex-trust",
			RuleID:      "codex-trust-home-or-broad",
			Severity:    "critical",
			Category:    "ai-agent",
			Kind:        "file",
			Locator:     map[string]any{"path": "~/.codex/config.toml", "line": 12},
			Title:       `Codex trust_level = "trusted" on $HOME with plaintext API key in same file`,
			Description: "A single prompt injection running in any Codex session can read every file in your $HOME — SSH keys, .env files, shell history — with no consent prompt. The plaintext API key in the same file means stealing it requires zero additional access.",
			MatchRedacted: `trust_level="trusted" + api_key=sk-ant-***...ab12`,
			FirstSeen:   "2026-05-13T14:02:00Z",
		},
		{
			Fingerprint: "demo-anthropic-key-in-chat",
			RuleID:      "secret-trufflehog-verified",
			Severity:    "critical",
			Category:    "secrets",
			Kind:        "file",
			Locator:     map[string]any{"path": "~/.claude/projects/audr-saas/sessions/2026-04-22T15-04.jsonl", "line": 118},
			Title:       "Anthropic API key in Claude Code chat transcript",
			Description: "An API key was pasted into a Claude Code chat session and persisted in the transcript JSONL. AI chat transcripts are an under-scanned attack surface — they live plaintext on disk indefinitely.",
			MatchRedacted: "sk-ant-***...XYZ4",
			FirstSeen:   "2026-05-13T09:14:00Z",
		},
		{
			Fingerprint: "demo-mcp-unpinned",
			RuleID:      "mcp-unpinned-npx",
			Severity:    "high",
			Category:    "ai-agent",
			Kind:        "file",
			Locator:     map[string]any{"path": "~/.cursor/mcp.json", "line": 34},
			Title:       "Unpinned `npx ...@latest` MCP server in third-party plugin",
			Description: "An MCP server is invoked via `npx <package>@latest`, which downloads and executes whatever the upstream maintainer publishes on each agent start. A supply-chain compromise of that package becomes an immediate compromise of your dev machine.",
			FirstSeen:   "2026-05-11T11:23:00Z",
		},
		{
			Fingerprint: "demo-openssl-cve",
			RuleID:      "osv-dpkg-openssl",
			Severity:    "high",
			Category:    "os-pkg",
			Kind:        "os-package",
			Locator:     map[string]any{"manager": "dpkg", "name": "openssl", "version": "3.0.7"},
			Title:       "openssl 3.0.7 — 4 CVEs (CVE-2026-43581 critical)",
			Description: "OSV reports 4 active CVEs against the installed openssl 3.0.7 from dpkg. One is rated critical; the remaining three are high severity affecting TLS handshakes.",
			FirstSeen:   "2026-04-27T08:00:00Z",
		},
		{
			Fingerprint: "demo-lodash-cve",
			RuleID:      "osv-npm-lodash",
			Severity:    "high",
			Category:    "deps",
			Kind:        "dep-package",
			Locator:     map[string]any{"ecosystem": "npm", "name": "lodash", "version": "4.17.20", "manifest_path": "~/code/dashboard-app/package-lock.json"},
			Title:       "lodash 4.17.20 — prototype pollution CVE-2020-8203",
			Description: "Prototype pollution in lodash <= 4.17.20 lets an attacker modify Object.prototype via crafted input. Affects any code using lodash.set / lodash.merge with untrusted keys.",
			FirstSeen:   "2026-04-27T08:00:00Z",
		},
		{
			Fingerprint: "demo-skill-undeclared",
			RuleID:      "skill-undeclared-dangerous-tool",
			Severity:    "medium",
			Category:    "ai-agent",
			Kind:        "file",
			Locator:     map[string]any{"path": "~/.claude/skills/old-helper/SKILL.md", "line": 1},
			Title:       "Skill uses Bash/Edit/Write but doesn't declare in frontmatter",
			Description: "A Claude Code skill body uses Bash, Edit, or Write tools without listing them in the frontmatter declaration. Users can't audit the tool surface before invoking the skill.",
			FirstSeen:   "2026-04-27T08:00:00Z",
		},
		{
			Fingerprint: "demo-curl-cve",
			RuleID:      "osv-dpkg-curl",
			Severity:    "medium",
			Category:    "os-pkg",
			Kind:        "os-package",
			Locator:     map[string]any{"manager": "dpkg", "name": "curl", "version": "7.81.0"},
			Title:       "curl 7.81.0 — CVE-2024-2398 medium severity",
			Description: "HTTP/2 push handling in curl <= 7.81.0 can lead to memory disclosure under specific request patterns.",
			FirstSeen:   "2026-04-27T08:00:00Z",
		},
		{
			Fingerprint: "demo-third-party-plugin",
			RuleID:      "claude-third-party-plugin-enabled",
			Severity:    "low",
			Category:    "ai-agent",
			Kind:        "file",
			Locator:     map[string]any{"path": "~/.claude/settings.json", "line": 47},
			Title:       "Third-party plugin from non-Anthropic marketplace enabled",
			Description: "A plugin from a marketplace other than the Anthropic-published one is enabled. Plugins from unknown marketplaces aren't vetted by Anthropic; treat them as untrusted code with your $HOME's read access.",
			FirstSeen:   "2026-04-27T08:00:00Z",
		},
	}
}

func demoRemediation(fingerprint string) (RemediationResponse, bool) {
	for _, r := range []RemediationResponse{
		{
			Fingerprint: "demo-codex-trust",
			HumanSteps: `1. Open ~/.codex/config.toml
2. Change trust_level = "trusted" to trust_level = "on_request"
3. Move the api_key field into ~/.codex/secrets.toml (chmod 0600) or reference an env var
4. Run: codex doctor — confirm the new config parses cleanly`,
			AIPrompt: `In ~/.codex/config.toml, find the [workspace] block where trust_level = "trusted" and change it to trust_level = "on_request". Then move any api_key field out of this file into ~/.codex/secrets.toml (create it with mode 0600) or reference an environment variable. Preserve all other settings. Confirm the resulting TOML parses with ` + "`codex doctor`" + `. Do not modify any other file.`,
		},
		{
			Fingerprint: "demo-anthropic-key-in-chat",
			HumanSteps: `1. Rotate the leaked Anthropic API key at https://console.anthropic.com/settings/keys
2. Delete the offending transcript file: rm ~/.claude/projects/audr-saas/sessions/2026-04-22T15-04.jsonl
3. Audit any other transcripts that might contain the same key: grep -l sk-ant- ~/.claude/projects/**/*.jsonl
4. Configure Claude Code to redact secrets going forward (optional)`,
			AIPrompt: `An Anthropic API key was committed to a Claude Code session transcript at ~/.claude/projects/audr-saas/sessions/2026-04-22T15-04.jsonl line 118. The key is already considered compromised. Help me: (1) delete that transcript file, (2) grep other transcripts under ~/.claude/projects for any line matching sk-ant- to confirm no other copies exist, and (3) print the URL where I rotate the key. Do not modify any other files.`,
		},
		{
			Fingerprint: "demo-mcp-unpinned",
			HumanSteps: `1. Open ~/.cursor/mcp.json
2. Find the MCP server entry using "npx ...@latest" at line 34
3. Replace @latest with a pinned version (e.g., @1.4.0). Source the exact version from the package's npm page.
4. Restart Cursor to pick up the change.`,
			AIPrompt: `In ~/.cursor/mcp.json line 34, an MCP server is invoked with "npx <package>@latest" which pulls whatever is currently published on npm. Look up the package's latest stable version (semver, not @latest) and edit the file to pin to that exact version. Preserve all other settings in the file. Do not modify any other file.`,
		},
		{
			Fingerprint: "demo-openssl-cve",
			HumanSteps: `1. Run: sudo apt update
2. Run: sudo apt upgrade openssl
3. Restart services that link openssl (or reboot): sudo systemctl restart <service> per as needed`,
			AIPrompt: `The installed openssl package version 3.0.7 has 4 active CVEs (one critical). Help me update it on this Debian/Ubuntu system: print the exact commands to run (apt update + apt upgrade openssl), then list which long-running services on this machine likely link openssl and should be restarted afterward.`,
		},
		{
			Fingerprint: "demo-lodash-cve",
			HumanSteps: `1. cd ~/code/dashboard-app
2. Run: npm update lodash
3. Verify the new version: npm ls lodash
4. Run tests to confirm nothing broke: npm test`,
			AIPrompt: `In ~/code/dashboard-app, the lodash dependency is pinned to 4.17.20 in package-lock.json which has CVE-2020-8203 (prototype pollution). Help me upgrade it to the latest patch on the same major version: run npm update lodash, verify the lockfile now points at >= 4.17.21, and run the test suite to confirm nothing regressed.`,
		},
		{
			Fingerprint: "demo-skill-undeclared",
			HumanSteps: `1. Open ~/.claude/skills/old-helper/SKILL.md
2. Look at the frontmatter (the YAML between the opening ---). Find the "tools:" field.
3. Add the tools the skill actually uses: Bash, Edit, Write (whichever apply).
4. Save and re-run /sync-gbrain or restart Claude Code if it caches skills.`,
			AIPrompt: `The Claude Code skill at ~/.claude/skills/old-helper/SKILL.md uses Bash, Edit, or Write tools in its body but doesn't declare them in the frontmatter. Read the SKILL.md, identify which of those tools the body actually uses, and update the frontmatter "tools:" field to include them. Preserve all other frontmatter fields and the skill body. Do not modify any other file.`,
		},
		{
			Fingerprint: "demo-curl-cve",
			HumanSteps: `1. Run: sudo apt update
2. Run: sudo apt upgrade curl
3. Verify: curl --version`,
			AIPrompt: `The installed curl 7.81.0 has CVE-2024-2398. Help me update it on this Debian/Ubuntu system: print the apt commands to run and the verification command to confirm the new version is in place.`,
		},
		{
			Fingerprint: "demo-third-party-plugin",
			HumanSteps: `1. Open ~/.claude/settings.json
2. Find the enabledPlugins entry at line 47
3. If you don't recognize the marketplace, remove the plugin entry from enabledPlugins.
4. Save the file. Restart Claude Code.`,
			AIPrompt: `In ~/.claude/settings.json line 47, a plugin from a non-Anthropic marketplace is enabled. Read the plugin name + marketplace URL from the file, then ask me whether to keep it. If I say remove, edit the file to take that single plugin out of enabledPlugins, preserving all other settings. Do not modify any other file.`,
		},
	} {
		if r.Fingerprint == fingerprint {
			return r, true
		}
	}
	return RemediationResponse{}, false
}

func demoMetrics(findings []FindingView) SnapshotMetrics {
	m := SnapshotMetrics{}
	for _, f := range findings {
		m.OpenTotal++
		switch f.Severity {
		case "critical":
			m.OpenCritical++
		case "high":
			m.OpenHigh++
		case "medium":
			m.OpenMedium++
		case "low":
			m.OpenLow++
		}
	}
	return m
}
