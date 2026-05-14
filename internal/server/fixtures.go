package server

import (
	"context"
	"fmt"
	"time"

	"github.com/harshmaur/audr/internal/state"
)

// DemoFindings + DemoRemediation are the hardcoded findings the
// Phase 2 visual slice seeds into the state store so the dashboard
// has content to render. They live here because the package already
// owns the wire-shape types; Phase 4 swaps the seeder for real
// scanners and the templates for the real remediation library.
//
// The DemoRemediation type implements RemediationLookup.

// DemoFindings returns the eight in-tree demo findings. Each
// finding's fingerprint is the deterministic SHA-256 of (rule_id,
// kind, canonicalized locator, ""), matching what state.Fingerprint
// produces — so re-seeding into a store with these findings is
// idempotent.
func DemoFindings() ([]state.Finding, error) {
	specs := []struct {
		ruleID        string
		severity      string
		category      string
		kind          string
		locator       string
		title         string
		description   string
		matchRedacted string
		firstSeen     time.Time
	}{
		{
			ruleID: "codex-trust-home-or-broad", severity: "critical", category: "ai-agent", kind: "file",
			locator: `{"path":"~/.codex/config.toml","line":12}`,
			title:   `Codex trust_level = "trusted" on $HOME with plaintext API key in same file`,
			description: "A single prompt injection running in any Codex session can read every file in your $HOME — SSH keys, .env files, shell history — with no consent prompt. The plaintext API key in the same file means stealing it requires zero additional access.",
			matchRedacted: `trust_level="trusted" + api_key=sk-ant-***...ab12`,
			firstSeen:     time.Date(2026, 5, 13, 14, 2, 0, 0, time.UTC),
		},
		{
			ruleID: "secret-trufflehog-verified", severity: "critical", category: "secrets", kind: "file",
			locator: `{"path":"~/.claude/projects/audr-saas/sessions/2026-04-22T15-04.jsonl","line":118}`,
			title:   "Anthropic API key in Claude Code chat transcript",
			description: "An API key was pasted into a Claude Code chat session and persisted in the transcript JSONL. AI chat transcripts are an under-scanned attack surface — they live plaintext on disk indefinitely.",
			matchRedacted: "sk-ant-***...XYZ4",
			firstSeen:     time.Date(2026, 5, 13, 9, 14, 0, 0, time.UTC),
		},
		{
			ruleID: "mcp-unpinned-npx", severity: "high", category: "ai-agent", kind: "file",
			locator: `{"path":"~/.cursor/mcp.json","line":34}`,
			title:   "Unpinned `npx ...@latest` MCP server in third-party plugin",
			description: "An MCP server is invoked via `npx <package>@latest`, which downloads and executes whatever the upstream maintainer publishes on each agent start. A supply-chain compromise of that package becomes an immediate compromise of your dev machine.",
			firstSeen: time.Date(2026, 5, 11, 11, 23, 0, 0, time.UTC),
		},
		{
			ruleID: "osv-dpkg-openssl", severity: "high", category: "os-pkg", kind: "os-package",
			locator: `{"manager":"dpkg","name":"openssl","version":"3.0.7"}`,
			title:   "openssl 3.0.7 — 4 CVEs (CVE-2026-43581 critical)",
			description: "OSV reports 4 active CVEs against the installed openssl 3.0.7 from dpkg. One is rated critical; the remaining three are high severity affecting TLS handshakes.",
			firstSeen: time.Date(2026, 4, 27, 8, 0, 0, 0, time.UTC),
		},
		{
			ruleID: "osv-npm-lodash", severity: "high", category: "deps", kind: "dep-package",
			locator: `{"ecosystem":"npm","name":"lodash","version":"4.17.20","manifest_path":"~/code/dashboard-app/package-lock.json"}`,
			title:   "lodash 4.17.20 — prototype pollution CVE-2020-8203",
			description: "Prototype pollution in lodash <= 4.17.20 lets an attacker modify Object.prototype via crafted input. Affects any code using lodash.set / lodash.merge with untrusted keys.",
			firstSeen: time.Date(2026, 4, 27, 8, 0, 0, 0, time.UTC),
		},
		{
			ruleID: "skill-undeclared-dangerous-tool", severity: "medium", category: "ai-agent", kind: "file",
			locator: `{"path":"~/.claude/skills/old-helper/SKILL.md","line":1}`,
			title:   "Skill uses Bash/Edit/Write but doesn't declare in frontmatter",
			description: "A Claude Code skill body uses Bash, Edit, or Write tools without listing them in the frontmatter declaration. Users can't audit the tool surface before invoking the skill.",
			firstSeen: time.Date(2026, 4, 27, 8, 0, 0, 0, time.UTC),
		},
		{
			ruleID: "osv-dpkg-curl", severity: "medium", category: "os-pkg", kind: "os-package",
			locator: `{"manager":"dpkg","name":"curl","version":"7.81.0"}`,
			title:   "curl 7.81.0 — CVE-2024-2398 medium severity",
			description: "HTTP/2 push handling in curl <= 7.81.0 can lead to memory disclosure under specific request patterns.",
			firstSeen: time.Date(2026, 4, 27, 8, 0, 0, 0, time.UTC),
		},
		{
			ruleID: "claude-third-party-plugin-enabled", severity: "low", category: "ai-agent", kind: "file",
			locator: `{"path":"~/.claude/settings.json","line":47}`,
			title:   "Third-party plugin from non-Anthropic marketplace enabled",
			description: "A plugin from a marketplace other than the Anthropic-published one is enabled. Plugins from unknown marketplaces aren't vetted by Anthropic; treat them as untrusted code with your $HOME's read access.",
			firstSeen: time.Date(2026, 4, 27, 8, 0, 0, 0, time.UTC),
		},
	}

	out := make([]state.Finding, 0, len(specs))
	for _, spec := range specs {
		fp, err := state.Fingerprint(spec.ruleID, spec.kind, []byte(spec.locator), spec.matchRedacted)
		if err != nil {
			return nil, fmt.Errorf("demo: fingerprint for %s: %w", spec.ruleID, err)
		}
		out = append(out, state.Finding{
			Fingerprint:   fp,
			RuleID:        spec.ruleID,
			Severity:      spec.severity,
			Category:      spec.category,
			Kind:          spec.kind,
			Locator:       []byte(spec.locator),
			Title:         spec.title,
			Description:   spec.description,
			MatchRedacted: spec.matchRedacted,
			FirstSeenAt:   spec.firstSeen.Unix(),
		})
	}
	return out, nil
}

// SeedDemoFindings is what the daemon's CLI wiring calls at startup
// in Phase 2: opens a fresh scan, upserts each demo finding referencing
// that scan, completes the scan. Idempotent against repeat daemon
// starts (fingerprints don't change; UpsertFinding deduplicates).
func SeedDemoFindings(_ context.Context, store *state.Store) error {
	findings, err := DemoFindings()
	if err != nil {
		return err
	}
	scanID, err := store.OpenScan("all")
	if err != nil {
		return fmt.Errorf("seed: open scan: %w", err)
	}
	for i := range findings {
		findings[i].FirstSeenScan = scanID
		findings[i].LastSeenScan = scanID
		if _, err := store.UpsertFinding(findings[i]); err != nil {
			return fmt.Errorf("seed: upsert %s: %w", findings[i].Fingerprint, err)
		}
	}
	if err := store.CompleteScan(scanID); err != nil {
		return fmt.Errorf("seed: complete scan: %w", err)
	}
	// Record demo scanner statuses so the dashboard renders the per-
	// category indicators.
	for _, category := range []string{"ai-agent", "deps", "secrets", "os-pkg"} {
		if err := store.RecordScannerStatus(state.ScannerStatus{
			ScanID: scanID, Category: category, Status: "ok",
		}); err != nil {
			return fmt.Errorf("seed: record scanner status %s: %w", category, err)
		}
	}
	return nil
}

// DemoRemediation implements RemediationLookup with the eight
// hand-authored remediation pairs for the demo findings. Real
// templates live in internal/templates (Phase 6).
type DemoRemediation struct {
	byFingerprint map[string]demoRemediationEntry
}

type demoRemediationEntry struct {
	human string
	ai    string
}

// NewDemoRemediation builds the lookup table. We compute the
// fingerprint for each entry using state.Fingerprint, matching what
// DemoFindings produces — guarantees the table key equals the
// fingerprint the dashboard sends back on /api/remediation/:fp.
func NewDemoRemediation() (*DemoRemediation, error) {
	type entry struct {
		ruleID        string
		kind          string
		locator       string
		matchRedacted string
		human         string
		ai            string
	}
	entries := []entry{
		{
			ruleID: "codex-trust-home-or-broad", kind: "file",
			locator:       `{"path":"~/.codex/config.toml","line":12}`,
			matchRedacted: `trust_level="trusted" + api_key=sk-ant-***...ab12`,
			human: `1. Open ~/.codex/config.toml
2. Change trust_level = "trusted" to trust_level = "on_request"
3. Move the api_key field into ~/.codex/secrets.toml (chmod 0600) or reference an env var
4. Run: codex doctor — confirm the new config parses cleanly`,
			ai: `In ~/.codex/config.toml, find the [workspace] block where trust_level = "trusted" and change it to trust_level = "on_request". Then move any api_key field out of this file into ~/.codex/secrets.toml (create it with mode 0600) or reference an environment variable. Preserve all other settings. Confirm the resulting TOML parses with ` + "`codex doctor`" + `. Do not modify any other file.`,
		},
		{
			ruleID: "secret-trufflehog-verified", kind: "file",
			locator:       `{"path":"~/.claude/projects/audr-saas/sessions/2026-04-22T15-04.jsonl","line":118}`,
			matchRedacted: "sk-ant-***...XYZ4",
			human: `1. Rotate the leaked Anthropic API key at https://console.anthropic.com/settings/keys
2. Delete the offending transcript file: rm ~/.claude/projects/audr-saas/sessions/2026-04-22T15-04.jsonl
3. Audit any other transcripts that might contain the same key: grep -l sk-ant- ~/.claude/projects/**/*.jsonl
4. Configure Claude Code to redact secrets going forward (optional)`,
			ai: `An Anthropic API key was committed to a Claude Code session transcript at ~/.claude/projects/audr-saas/sessions/2026-04-22T15-04.jsonl line 118. The key is already considered compromised. Help me: (1) delete that transcript file, (2) grep other transcripts under ~/.claude/projects for any line matching sk-ant- to confirm no other copies exist, and (3) print the URL where I rotate the key. Do not modify any other files.`,
		},
		{
			ruleID: "mcp-unpinned-npx", kind: "file",
			locator: `{"path":"~/.cursor/mcp.json","line":34}`,
			human: `1. Open ~/.cursor/mcp.json
2. Find the MCP server entry using "npx ...@latest" at line 34
3. Replace @latest with a pinned version (e.g., @1.4.0). Source the exact version from the package's npm page.
4. Restart Cursor to pick up the change.`,
			ai: `In ~/.cursor/mcp.json line 34, an MCP server is invoked with "npx <package>@latest" which pulls whatever is currently published on npm. Look up the package's latest stable version (semver, not @latest) and edit the file to pin to that exact version. Preserve all other settings in the file. Do not modify any other file.`,
		},
		{
			ruleID: "osv-dpkg-openssl", kind: "os-package",
			locator: `{"manager":"dpkg","name":"openssl","version":"3.0.7"}`,
			human: `1. Run: sudo apt update
2. Run: sudo apt upgrade openssl
3. Restart services that link openssl (or reboot): sudo systemctl restart <service> per as needed`,
			ai: `The installed openssl package version 3.0.7 has 4 active CVEs (one critical). Help me update it on this Debian/Ubuntu system: print the exact commands to run (apt update + apt upgrade openssl), then list which long-running services on this machine likely link openssl and should be restarted afterward.`,
		},
		{
			ruleID: "osv-npm-lodash", kind: "dep-package",
			locator: `{"ecosystem":"npm","name":"lodash","version":"4.17.20","manifest_path":"~/code/dashboard-app/package-lock.json"}`,
			human: `1. cd ~/code/dashboard-app
2. Run: npm update lodash
3. Verify the new version: npm ls lodash
4. Run tests to confirm nothing broke: npm test`,
			ai: `In ~/code/dashboard-app, the lodash dependency is pinned to 4.17.20 in package-lock.json which has CVE-2020-8203 (prototype pollution). Help me upgrade it to the latest patch on the same major version: run npm update lodash, verify the lockfile now points at >= 4.17.21, and run the test suite to confirm nothing regressed.`,
		},
		{
			ruleID: "skill-undeclared-dangerous-tool", kind: "file",
			locator: `{"path":"~/.claude/skills/old-helper/SKILL.md","line":1}`,
			human: `1. Open ~/.claude/skills/old-helper/SKILL.md
2. Look at the frontmatter (the YAML between the opening ---). Find the "tools:" field.
3. Add the tools the skill actually uses: Bash, Edit, Write (whichever apply).
4. Save and re-run /sync-gbrain or restart Claude Code if it caches skills.`,
			ai: `The Claude Code skill at ~/.claude/skills/old-helper/SKILL.md uses Bash, Edit, or Write tools in its body but doesn't declare them in the frontmatter. Read the SKILL.md, identify which of those tools the body actually uses, and update the frontmatter "tools:" field to include them. Preserve all other frontmatter fields and the skill body. Do not modify any other file.`,
		},
		{
			ruleID: "osv-dpkg-curl", kind: "os-package",
			locator: `{"manager":"dpkg","name":"curl","version":"7.81.0"}`,
			human: `1. Run: sudo apt update
2. Run: sudo apt upgrade curl
3. Verify: curl --version`,
			ai: `The installed curl 7.81.0 has CVE-2024-2398. Help me update it on this Debian/Ubuntu system: print the apt commands to run and the verification command to confirm the new version is in place.`,
		},
		{
			ruleID: "claude-third-party-plugin-enabled", kind: "file",
			locator: `{"path":"~/.claude/settings.json","line":47}`,
			human: `1. Open ~/.claude/settings.json
2. Find the enabledPlugins entry at line 47
3. If you don't recognize the marketplace, remove the plugin entry from enabledPlugins.
4. Save the file. Restart Claude Code.`,
			ai: `In ~/.claude/settings.json line 47, a plugin from a non-Anthropic marketplace is enabled. Read the plugin name + marketplace URL from the file, then ask me whether to keep it. If I say remove, edit the file to take that single plugin out of enabledPlugins, preserving all other settings. Do not modify any other file.`,
		},
	}

	out := &DemoRemediation{byFingerprint: make(map[string]demoRemediationEntry, len(entries))}
	for _, e := range entries {
		fp, err := state.Fingerprint(e.ruleID, e.kind, []byte(e.locator), e.matchRedacted)
		if err != nil {
			return nil, fmt.Errorf("demo remediation fingerprint for %s: %w", e.ruleID, err)
		}
		out.byFingerprint[fp] = demoRemediationEntry{human: e.human, ai: e.ai}
	}
	return out, nil
}

// Lookup implements RemediationLookup. The full state.Finding is
// passed in but DemoRemediation only uses the Fingerprint — its
// canned entries are keyed exactly by hash.
func (d *DemoRemediation) Lookup(f state.Finding) (string, string, bool) {
	if d == nil {
		return "", "", false
	}
	e, ok := d.byFingerprint[f.Fingerprint]
	if !ok {
		return "", "", false
	}
	return e.human, e.ai, true
}
