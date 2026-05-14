//go:build darwin

package main

import (
	"os/exec"
	"strings"
)

// preflightNotifications returns user-visible warnings about macOS
// notification environment state that would make a toast appear to
// succeed silently. The actually-observed failure modes:
//
//   - beeep on macOS shells out to osascript, which attributes the
//     notification to Script Editor — NOT to audr. If the user has
//     never granted Script Editor notification permission, macOS
//     silently swallows the toast. The fix is to allow Script
//     Editor in System Settings → Notifications.
//   - Focus / Do Not Disturb modes suppress popups; notifications
//     queue in Notification Center (right-edge swipe) but never pop.
//
// Empty slice = environment looks fine. Caller prints the list as
// per-item warnings before firing the test toast.
//
// Future: when terminal-notifier or .app bundle support lands,
// this preflight should also check whether THAT identity is
// permitted, not Script Editor's.
func preflightNotifications() []string {
	var warnings []string

	// Focus mode detection: `defaults read com.apple.donotdisturb` is
	// the canonical signal on macOS 12+. The exact key shifted across
	// versions; "userPref" is the most reliable read across recent
	// ones.
	if out, err := exec.Command("defaults", "read",
		"com.apple.controlcenter", "NSStatusItem Visible FocusModes").Output(); err == nil {
		if strings.TrimSpace(string(out)) == "1" {
			warnings = append(warnings,
				"Focus / Do Not Disturb appears active. Toasts will go to Notification Center "+
					"(swipe in from the right edge to see them) but won't pop as banners. "+
					"Toggle off in Control Center → Focus.")
		}
	}

	// Script Editor permission: macOS shows osascript-originated
	// notifications under Script Editor's identity. If Script Editor
	// is set to "Off" or "Banners off" in System Settings →
	// Notifications, audr's toasts silently disappear. We can't
	// programmatically flip the setting (requires user interaction
	// + UI automation permission), but we can detect + tell the
	// user where to look.
	//
	// The system stores notification prefs at
	// ~/Library/Preferences/com.apple.ncprefs.plist as a binary
	// plist with per-bundle-id flags. Parsing it is brittle — instead
	// we check for the well-known Script Editor bundle id presence
	// in the listed apps via `defaults read`. Best-effort: a present
	// entry confirms the user has SEEN macOS prompt for Script
	// Editor's permission at least once; absence means we should
	// nudge them to expect a prompt.
	if _, err := exec.LookPath("defaults"); err == nil {
		out, err := exec.Command("defaults", "read",
			"com.apple.ncprefs.plist", "apps").Output()
		if err == nil && !strings.Contains(string(out), "com.apple.ScriptEditor2") {
			warnings = append(warnings,
				"Script Editor has no notification entry in System Settings yet. "+
					"audr uses osascript under the hood, so toasts are attributed to "+
					"Script Editor. The first run should prompt — if you don't see "+
					"the prompt, open System Settings → Notifications and ensure "+
					"Script Editor is allowed to send notifications.")
		}
	}

	// Suggest terminal-notifier as the cleaner long-term path.
	if _, err := exec.LookPath("terminal-notifier"); err != nil {
		warnings = append(warnings,
			"For click-to-open support on macOS (currently Linux-only), install "+
				"`terminal-notifier` via `brew install terminal-notifier`. audr will "+
				"prefer it when present in a future release.")
	}

	return warnings
}
