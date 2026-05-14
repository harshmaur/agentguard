package templates

import (
	"fmt"

	"github.com/harshmaur/audr/internal/state"
)

// registerShaiHulud installs handlers for the Mini-Shai-Hulud
// supply-chain attack detectors (6 rules in audr v0.2+). Unlike
// language-package CVEs, each rule corresponds to a distinct attack
// artifact left on disk by the worm campaign — different remediation
// per vector.
//
// Mini-Shai-Hulud is a publicly-disclosed npm worm that targets
// developer machines through compromised packages. Audr detects the
// indicators an infected machine leaves behind: persistence hooks in
// Claude Code, VS Code task triggers, GitHub Actions workflows that
// exfiltrate secrets, dropped payload filenames, etc.
//
// Reference: README "Audr is not trying to rebuild every specialist
// scanner..." section. For more context: audr blog / advisory.
func registerShaiHulud(r *Registry) {
	r.registerRule("mini-shai-hulud-malicious-optional-dependency", shaiHuludOptionalDep)
	r.registerRule("mini-shai-hulud-claude-persistence", shaiHuludClaudePersistence)
	r.registerRule("mini-shai-hulud-vscode-persistence", shaiHuludVSCodePersistence)
	r.registerRule("mini-shai-hulud-token-monitor-persistence", shaiHuludTokenMonitor)
	r.registerRule("mini-shai-hulud-dropped-payload", shaiHuludDroppedPayload)
	r.registerRule("mini-shai-hulud-workflow-secret-exfil", shaiHuludWorkflowExfil)
}

func shaiHuludOptionalDep(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	if path == "" {
		path = "<package.json>"
	}
	human := fmt.Sprintf(`MINI SHAI-HULUD: malicious optionalDependency found in %s.

This package.json declares @tanstack/setup pointing at an attacker-staged
TanStack router commit. If `+"`npm install`"+` ran in this directory,
the worm payload may have executed already.

1. STOP. Do not run `+"`npm install`"+` again in this tree until step 4 is done.

2. Open %s and remove the @tanstack/setup entry from optionalDependencies.
   If you need legitimate @tanstack/router functionality, depend on the
   official package, not a "setup" sibling.

3. Pin every @tanstack/* dependency to a known-clean version (check
   the audr blog / Mini Shai-Hulud advisory for the safe-version cutoff
   per package).

4. Wipe the install state:
     rm -rf node_modules package-lock.json
     npm install     # only after the package.json fix in step 2

5. IF this machine ran `+"`npm install`"+` on the infected tree:
   a. Treat this as a credential-compromise incident.
   b. Audit ~/.gitconfig, ~/.npmrc, ~/.ssh/ for any unauthorized changes.
   c. Rotate any credentials that were in env or in shell config when the
      install ran. The worm extracts NPM_TOKEN, GITHUB_TOKEN, and other
      common credential env-vars.
   d. Rerun `+"`audr scan`"+` on $HOME to surface any persistence indicators
      (claude / vscode / gh-token-monitor / dropped payloads).`, path, path)

	ai := fmt.Sprintf(`A Mini Shai-Hulud supply-chain attack indicator was detected at %s.

Before any code change, confirm with the user that they understand this
is potential malware exposure, not a routine dep upgrade. Then:

1. Read %s. Locate the optionalDependencies."@tanstack/setup" entry and
   show me the value (verbatim — it should reference a github:tanstack/
   router commit).
2. Remove that single entry from optionalDependencies. Preserve every
   other field in the package.json.
3. Audit the rest of the dependencies and devDependencies block for any
   @tanstack/* entries that look unusual (unexpected versions, GitHub
   refs where npm refs would be normal). List them; ASK me to confirm
   each before changing.
4. Delete node_modules and package-lock.json in this directory.
5. Print (do NOT run) the commands to rotate the most common
   credentials the worm targets: NPM_TOKEN, GITHUB_TOKEN, any cloud
   provider keys that were in env when install ran.

CRITICAL: do not run `+"`npm install`"+` in the background or as part
of this turn. The user needs to verify the cleanup before reinstalling.
Do not modify any file outside this package.json.`, path, path)
	return human, ai, true
}

func shaiHuludClaudePersistence(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	if path == "" {
		path = "<~/.claude/settings.json or ~/.claude/skills/...>"
	}
	human := fmt.Sprintf(`MINI SHAI-HULUD: Claude Code persistence hook detected at %s.

The worm installs a SessionStart hook (or similar) so its payload re-
executes every time Claude Code launches. The hook lives in your
Claude config and survives terminal restarts, reboots, even Claude
Code upgrades.

1. Open %s. Look for a hooks block — specifically SessionStart or
   any hook whose command fetches and executes remote content
   (curl|bash, eval, base64-decode-then-execute).

2. Remove the offending hook block. Preserve every other setting.

3. Audit the rest of ~/.claude/ for similar hooks in:
     - ~/.claude/settings.json (and settings.local.json)
     - ~/.claude/projects/*/settings*.json
     - ~/.claude/skills/*/SKILL.md (frontmatter and body)

4. After cleaning all Claude configs, restart Claude Code so it
   re-reads its settings without the persistence hook.

5. This is a credential-compromise indicator. Rotate any credentials
   you used Claude Code to handle in the last weeks: API keys, OAuth
   tokens, anything pasted into chat (audr's secret scanner can help
   identify those — see `+"`audr scan --secrets`"+`).`, path, path)

	ai := fmt.Sprintf(`Mini Shai-Hulud persistence indicator: a Claude Code hook at %s
runs shell commands at every session start. This is malware staging.

1. Read %s. Locate the hooks block. Identify the SessionStart hook (or
   similar) whose command fetches+executes remote content. Show me the
   exact command field VERBATIM (so I can correlate with the advisory).
2. Remove that single hook entry. Preserve all other settings.
3. Run `+"`grep -r 'SessionStart' ~/.claude/`"+` and show me everything
   that matches. There may be sibling hooks in per-project settings or
   skill bodies.
4. Print the list of files that would need similar cleanup. Do NOT
   modify them — list them so I can review each.
5. Print rotation steps for any sensitive credentials the user
   typically interacts with through Claude Code (API keys, cloud
   tokens). Do not modify ANY file except %s.`, path, path, path)
	return human, ai, true
}

func shaiHuludVSCodePersistence(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	if path == "" {
		path = "<.vscode/tasks.json>"
	}
	human := fmt.Sprintf(`MINI SHAI-HULUD: VS Code folder-open persistence detected at %s.

The worm registers a VS Code task that runs whenever this folder is
opened in VS Code. Anyone who clones + opens this repo executes the
payload.

1. Open %s. Find the offending task (typically has "runOptions":
   {"runOn": "folderOpen"} or a problematic command).

2. Remove the task entry. Preserve other tasks.

3. Audit the parent directory for related files:
     - .vscode/tasks.json
     - .vscode/launch.json (debug config that auto-runs)
     - .vscode/settings.json (workspaceTrustedFolders)

4. If this repo has been opened in VS Code already, the task may have
   already run. Treat as credential-compromise:
     - Check ~/.vscode/extensions/ for unexpected extensions installed
       around the time you opened this repo.
     - Rotate credentials that were in env or VS Code's settings.

5. If this repo is publicly accessible (GitHub, etc.), notify anyone
   else who may have cloned + opened it — they're all exposed.`, path, path)

	ai := fmt.Sprintf(`A VS Code folder-open persistence task was detected at %s. This is a
Mini Shai-Hulud worm indicator — opening this folder in VS Code runs
the malicious task automatically.

1. Read %s. Show me the offending task's "command" and "runOptions"
   fields verbatim.
2. Remove that single task. Preserve every other task in tasks.json.
3. List every other file in this directory's .vscode/ subfolder
   (launch.json, settings.json) — print what you find so I can review
   for related persistence indicators.
4. If this is a git repo, run `+"`git log --diff-filter=A -- .vscode/tasks.json`"+`
   to show when the task entry was added and by whom. Show me the
   commit + author.
5. Do NOT modify any file outside the offending tasks.json without
   showing me a diff first.`, path, path)
	return human, ai, true
}

func shaiHuludTokenMonitor(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	if path == "" {
		path = "<a LaunchAgent / systemd user unit / scheduled task>"
	}
	human := fmt.Sprintf(`MINI SHAI-HULUD: gh-token-monitor persistence service detected at %s.

The worm installs a long-running service that monitors your shell for
gh CLI invocations and exfiltrates the GITHUB_TOKEN. This is a
critical credential-monitoring backdoor.

1. STOP using gh CLI until the service is removed. Every invocation
   may leak your token.

2. Unload + remove the service definition at %s:
     - macOS LaunchAgent: launchctl unload %s, then rm %s
     - systemd --user: systemctl --user stop <unit>; systemctl --user disable <unit>; rm %s
     - Windows scheduled task: schtasks /Delete /TN <name> /F

3. Check for the matching binary (the service's program path).
   Identify it, delete it. The advisory lists known payload paths.

4. ROTATE your GitHub token NOW. Visit https://github.com/settings/tokens.
   Assume the leaked token has been used: review your repos for
   unauthorized pushes / branch creations / org membership changes.

5. If you have other gh-style CLI tokens (npm, gitlab, etc.) audited
   on this machine, treat them as potentially exposed and rotate as
   well.`, path, path, path, path, path)

	ai := fmt.Sprintf(`A Mini Shai-Hulud gh-token-monitor service was detected at %s. This
monitors gh CLI invocations and exfiltrates GITHUB_TOKEN.

Before doing anything else: TELL the user not to run gh commands
until this is fixed.

Then:
1. Identify the service type (LaunchAgent vs systemd --user vs
   Scheduled Task) from %s's directory + format.
2. Print the EXACT commands to unload+remove that service. Do not run
   them yourself — the user needs to do this manually with sudo
   awareness.
3. Read %s and show me the executable path the service runs. Print
   the rm command for that binary too.
4. Print the GitHub URL where the user rotates their PAT:
   https://github.com/settings/tokens
5. Print the URL for reviewing recent GitHub activity:
   https://github.com/settings/security-log
6. Do NOT modify any file. Do NOT run any commands. This is an
   incident-response situation; the user makes every decision.`, path, path, path)
	return human, ai, true
}

func shaiHuludDroppedPayload(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	if path == "" {
		path = "<dropped payload file>"
	}
	human := fmt.Sprintf(`MINI SHAI-HULUD: dropped payload filename match at %s.

The worm leaves payload files behind on infected machines. This file
matches a known dropped-payload name from the advisory.

1. Do NOT execute this file. Do not "open" it in a file manager
   either — some payloads exploit file-preview handlers.

2. From a terminal, inspect (but do not execute) the file:
     file %s
     head -c 4096 %s | xxd | head -30   # binary inspection
     stat %s   # check timestamps — when was it dropped?

3. If you confirm it's the worm payload (not a false positive on
   filename), delete it:
     rm %s

4. Audit for sibling files in the same directory and at the typical
   drop locations:
     - macOS: ~/Library/Application Support/<bogus name>/
     - Linux: ~/.config/<bogus name>/ or /tmp/<bogus name>/
     - Windows: %%APPDATA%%\\<bogus name>\\

5. This is a confirmed compromise indicator. Run a full audr scan
   and audit:
     audr scan --secrets ~     # find any secret exfiltration prep
     audr scan ~/.claude ~/.codex ~/.cursor   # find other persistence`, path, path, path, path, path)

	ai := fmt.Sprintf(`A Mini Shai-Hulud dropped payload was found at %s.
This is binary malware, not source code to be edited.

Before anything else: WARN the user this is potential malware.

1. Print these inspection commands so the user can run them — do NOT
   run them yourself:
     file %s
     stat %s
     head -c 4096 %s | xxd | head -30
2. Tell the user that if they confirm the file is the payload, the
   removal command is: rm %s
3. List the typical sibling payload locations per OS:
     macOS:   ~/Library/Application Support/
     Linux:   ~/.config/ and /tmp/
     Windows: %%APPDATA%%\\
4. Suggest follow-up scans: `+"`audr scan --secrets ~`"+`,
   `+"`audr scan ~/.claude ~/.codex ~/.cursor`"+`.
5. Do NOT modify any file. Do NOT execute the dropped file under any
   circumstances.`, path, path, path, path, path)
	return human, ai, true
}

func shaiHuludWorkflowExfil(_ state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	if path == "" {
		path = "<.github/workflows/...yml>"
	}
	human := fmt.Sprintf(`MINI SHAI-HULUD: GitHub Actions workflow serializes secrets at %s.

The worm modifies workflows to dump the entire ${{ secrets }} or
${{ toJSON(secrets) }} payload, then exfiltrates it. If this workflow
has run on GitHub-hosted runners, your repo's secrets are compromised.

1. Open %s. Locate the step that references toJSON(secrets) or that
   serializes the secrets context to env / output / artifact.

2. Remove that step. Preserve every other step in the workflow.

3. Check the workflow's run history:
   https://github.com/<owner>/<repo>/actions
   If the malicious workflow has ever succeeded, your secrets are
   already exfiltrated.

4. ROTATE every secret stored in the affected repo's "Secrets and
   variables" settings page. Treat the leaked set as comprehensively
   compromised.

5. Audit recently-added workflows in .github/workflows/ for similar
   patterns. Also check for unauthorized workflow_dispatch events
   that may have triggered the exfiltration.`, path, path)

	ai := fmt.Sprintf(`A GitHub Actions workflow at %s exfiltrates secrets — Mini Shai-Hulud
worm indicator.

1. Read %s. Show me the offending step verbatim — specifically the
   step that references toJSON(secrets) or that dumps the secrets
   context to env/output/artifact.
2. Remove that single step. Preserve all other steps.
3. List every workflow file in .github/workflows/. For each, scan for
   the same pattern. Show me a table: file → has_secrets_exfil_pattern
   yes/no.
4. Print the URL where the user reviews + rotates repository secrets:
   https://github.com/<owner>/<repo>/settings/secrets/actions
5. Print the URL where the user reviews recent Actions runs (the
   compromised workflow may have already run):
   https://github.com/<owner>/<repo>/actions
6. Do NOT modify any file outside the offending workflow.`, path, path)
	return human, ai, true
}
