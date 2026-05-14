package templates

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/harshmaur/audr/internal/state"
)

// openclawUpgradeHandler routes every `openclaw-*` rule to a single
// parameterized template. Each OpenClaw finding's Title says "OpenClaw
// before <version> has ..." and its Description carries the CVE. The
// remediation is always the same shape — upgrade the openclaw entry
// in package.json to the named version — so we paramaterize a single
// recipe off the finding's metadata rather than duplicating 15 nearly-
// identical handlers.
//
// If the version isn't extractable from the title (future rule shapes
// or a malformed title), we fall back to "upgrade to the latest
// patched release" and surface the original SuggestedFix verbatim so
// no information is lost.
func openclawUpgradeHandler(f state.Finding, loc Locator) (string, string, bool) {
	path := loc.String("path")
	if path == "" {
		path = "<package.json>"
	}
	fixedVersion := extractOpenClawFixedVersion(f.Title)
	if fixedVersion == "" {
		fixedVersion = extractOpenClawFixedVersion(f.Description)
	}

	versionLine := "the latest patched OpenClaw release"
	if fixedVersion != "" {
		versionLine = fmt.Sprintf("OpenClaw %s or later", fixedVersion)
	}

	human := fmt.Sprintf(`%s

Detected at: %s
Advisory:    %s

1. Identify your package manager from the lockfile next to %s:
     package-lock.json  → npm
     pnpm-lock.yaml     → pnpm
     yarn.lock          → yarn (classic or berry)
     bun.lockb          → bun

2. Run the manager-specific WHY first to confirm whether openclaw is a
   direct dep or a transitive of another package:
     npm:  npm why openclaw
     pnpm: pnpm why openclaw
     yarn: yarn why openclaw
     bun:  bun pm ls | grep openclaw

3. UPGRADE openclaw to %s.
   - If direct: edit %s and bump openclaw's version range, then run
     the manager's install.
   - If transitive (npm why prints a parent): upgrade the PARENT
     package whose updated release includes the patched openclaw.
   - If the parent hasn't released a fix yet: pin the transitive
     directly via your manager's override mechanism:
       npm:   "overrides":     { "openclaw": ">=%s" }
       pnpm:  "pnpm": { "overrides": { "openclaw": ">=%s" } }
       yarn:  "resolutions":  { "openclaw": ">=%s" }     (yarn berry)
       bun:   "overrides":     { "openclaw": ">=%s" }

4. After installing, re-run the WHY command from step 2 and confirm
   it now shows a version >= %s.

5. Re-run audr to confirm this finding clears.`,
		f.Title,
		path,
		f.Description,
		path,
		versionLine,
		path,
		safeVersionFloor(fixedVersion),
		safeVersionFloor(fixedVersion),
		safeVersionFloor(fixedVersion),
		safeVersionFloor(fixedVersion),
		safeVersionFloor(fixedVersion),
	)

	ai := fmt.Sprintf(`A vulnerable OpenClaw version was detected in %s.

Finding:    %s
Advisory:   %s
Goal:       bring this package.json (and any transitive dependants) up
            to %s.

Steps — in this exact order:

1. Read %s. Show me the openclaw entry verbatim — both its position
   (direct in "dependencies"/"devDependencies", or absent because it's
   a transitive) and the current version range.

2. Detect the package manager from the lockfile in the same directory
   (package-lock.json → npm, pnpm-lock.yaml → pnpm, yarn.lock → yarn,
   bun.lockb → bun). Print which manager you detected and why.

3. Run the manager's "why" command for openclaw and SHOW ME its
   output before proposing any edit:
     npm:  npm why openclaw
     pnpm: pnpm why openclaw
     yarn: yarn why openclaw
     bun:  bun pm ls | grep -B1 openclaw

4. Based on the why-output, choose the correct fix:
   (a) Direct dependency → propose a diff that bumps openclaw to
       %s in package.json, then run the manager's install.
   (b) Transitive dependency with a patched parent available →
       propose upgrading the parent (NOT openclaw directly), so the
       fix flows through normal dependency resolution.
   (c) Transitive dependency, parent has no fix yet → propose adding
       a manager-specific override pinning openclaw to >=%s.

5. Re-run the why command and confirm the resolved version is now
   >= %s. Re-run audr to confirm the finding clears.

DO NOT skip the why-output step. The naive "upgrade openclaw"
manifest edit silently does the wrong thing when openclaw is
transitive — the dep resolver will still pull the vulnerable version
through the parent unless you upgrade the parent or use an override.`,
		path,
		f.Title,
		f.Description,
		versionLine,
		path,
		versionLine,
		safeVersionFloor(fixedVersion),
		safeVersionFloor(fixedVersion),
	)
	return human, ai, true
}

// openclawTitleVersion matches "before <version>" in rule titles like
// "OpenClaw before 2026.3.22 has unbound bootstrap setup codes". Also
// matches the SuggestedFix variant "Upgrade OpenClaw to 2026.3.22 or
// later ...". Version shape is calver (YYYY.M.D) but we accept any
// dotted numeric sequence so this survives rule additions.
var openclawTitleVersion = regexp.MustCompile(
	`(?:before|to)\s+([0-9]+(?:\.[0-9]+){1,3})`,
)

func extractOpenClawFixedVersion(s string) string {
	m := openclawTitleVersion.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// safeVersionFloor returns the version when known, otherwise a sentinel
// the caller can render inline ("the patched version") without forcing
// the template to branch all over.
func safeVersionFloor(v string) string {
	if v == "" {
		return "the patched version"
	}
	return v
}
