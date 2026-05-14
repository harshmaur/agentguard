package templates

import (
	"fmt"

	"github.com/harshmaur/audr/internal/state"
)

// registerOSPkgHandlers installs handlers for kind="os-package"
// findings. The orchestrator mints rule_ids like "osv-dpkg-openssl"
// or "osv-rpm-glibc"; we prefix-match on the manager.
//
// Per Phase 4 + Premise 3: only Linux managers (dpkg/rpm/apk) produce
// CVE-shaped findings. brew/winget are fix-command rendering only —
// they could surface here in v1.1 if Phase 6 templates layer in
// per-OS update commands for known package names.
func registerOSPkgHandlers(r *Registry) {
	r.registerPrefix("osv-dpkg-", osPkgHandler("dpkg"))
	r.registerPrefix("osv-rpm-", osPkgHandler("rpm"))
	r.registerPrefix("osv-apk-", osPkgHandler("apk"))
}

// osPkgHandler returns a Handler closure parameterized by the
// manager. Each handler emits the canonical upgrade command for the
// manager and a verification step.
func osPkgHandler(manager string) Handler {
	return func(f state.Finding, loc Locator) (string, string, bool) {
		name := loc.String("name")
		version := loc.String("version")
		advisoryID := f.MatchRedacted
		if name == "" {
			return "", "", false
		}
		recipe := osPkgUpgradeRecipe(manager, name)

		human := fmt.Sprintf(`Vulnerable OS package: %s %s%s

1. %s
2. %s
3. Verify the new version: %s
4. If %s is linked into long-running services, restart those services (or reboot) so the fix takes effect`,
			name, version, advisoryFooter(advisoryID),
			recipe.refreshCommand, recipe.upgradeCommand, recipe.verifyCommand, name)

		ai := fmt.Sprintf(`A vulnerable %s package was flagged: %s %s%s.

Help me update it. The exact commands depend on the running OS — confirm with the user first if you're not sure which one applies, then:
1. Refresh the package index: %q
2. Upgrade the package: %q
3. Verify the new installed version: %q
4. List any long-running daemons on this machine that link this package (systemctl-style enumeration is fine) and restart them so the fix takes effect.

This is a SYSTEM-LEVEL change; it will need sudo. Do not run the commands without showing them to the user first.`,
			osPkgManagerLabel(manager), name, version, advisoryFooter(advisoryID),
			recipe.refreshCommand, recipe.upgradeCommand, recipe.verifyCommand)
		return human, ai, true
	}
}

type osPkgRecipe struct {
	refreshCommand string
	upgradeCommand string
	verifyCommand  string
}

// osPkgUpgradeRecipe returns the (refresh, upgrade, verify) commands
// for a given OS package manager. dpkg → apt; rpm → dnf with yum
// fallback; apk → apk itself.
func osPkgUpgradeRecipe(manager, name string) osPkgRecipe {
	switch manager {
	case "dpkg":
		return osPkgRecipe{
			refreshCommand: "sudo apt update",
			upgradeCommand: fmt.Sprintf("sudo apt upgrade %s", name),
			verifyCommand:  fmt.Sprintf("dpkg-query -W -f='${Version}\\n' %s", name),
		}
	case "rpm":
		return osPkgRecipe{
			refreshCommand: "sudo dnf check-update   # or: sudo yum check-update",
			upgradeCommand: fmt.Sprintf("sudo dnf upgrade %s   # or: sudo yum update %s", name, name),
			verifyCommand:  fmt.Sprintf("rpm -q %s", name),
		}
	case "apk":
		return osPkgRecipe{
			refreshCommand: "sudo apk update",
			upgradeCommand: fmt.Sprintf("sudo apk upgrade %s", name),
			verifyCommand:  fmt.Sprintf("apk info -v %s", name),
		}
	default:
		return osPkgRecipe{
			refreshCommand: "Update your package index (apt update / dnf check-update / apk update)",
			upgradeCommand: fmt.Sprintf("Upgrade %s with your package manager", name),
			verifyCommand:  fmt.Sprintf("Confirm the new version of %s is installed", name),
		}
	}
}

func osPkgManagerLabel(manager string) string {
	switch manager {
	case "dpkg":
		return "Debian/Ubuntu (dpkg/apt)"
	case "rpm":
		return "Red Hat–family (rpm/dnf/yum)"
	case "apk":
		return "Alpine (apk)"
	default:
		return "OS"
	}
}
