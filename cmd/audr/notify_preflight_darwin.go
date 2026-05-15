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
//   - terminal-notifier missing on PATH: toasts still fire via
//     osascript fallback, but click-to-open is disabled. The body
//     copy gains a "run audr open" suffix so the user has a fallback.
//   - When falling back to osascript: macOS attributes the
//     notification to Script Editor — NOT to audr. If the user has
//     never granted Script Editor notification permission, macOS
//     silently swallows the toast. The fix is to allow Script
//     Editor in System Settings → Notifications.
//   - Focus / Do Not Disturb modes suppress popups; notifications
//     queue in Notification Center (right-edge swipe) but never pop.
//
// Empty slice = environment looks fine. Caller prints the list as
// per-item warnings before firing the test toast.
func preflightNotifications() []string {
	var warnings []string
	tnAvailable := terminalNotifierPresent()

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

	// Script Editor permission only matters on the osascript fallback
	// path — terminal-notifier brings its own identity. Skip this
	// diagnostic when terminal-notifier is in use.
	if !tnAvailable {
		// macOS shows osascript-originated notifications under Script
		// Editor's identity. If Script Editor is "Off" or "Banners
		// off" in System Settings → Notifications, audr's toasts
		// silently disappear. We can't programmatically flip the
		// setting (requires user interaction + UI automation
		// permission), but we can detect + tell the user where to
		// look.
		//
		// The system stores notification prefs at
		// ~/Library/Preferences/com.apple.ncprefs.plist as a binary
		// plist with per-bundle-id flags. Parsing it is brittle —
		// instead we check for the well-known Script Editor bundle
		// id presence in the listed apps via `defaults read`.
		// Best-effort: a present entry confirms macOS has prompted
		// for Script Editor's permission at least once; absence means
		// we should nudge the user to expect a prompt.
		if _, err := exec.LookPath("defaults"); err == nil {
			out, err := exec.Command("defaults", "read",
				"com.apple.ncprefs.plist", "apps").Output()
			if err == nil && !strings.Contains(string(out), "com.apple.ScriptEditor2") {
				warnings = append(warnings,
					"Script Editor has no notification entry in System Settings yet. "+
						"audr is falling back to osascript (terminal-notifier not on PATH), "+
						"so toasts are attributed to Script Editor. The first run should "+
						"prompt — if you don't see the prompt, open System Settings → "+
						"Notifications and ensure Script Editor is allowed to send "+
						"notifications.")
			}
		}
	}

	// Surface the terminal-notifier suggestion when it's missing.
	// Now actually meaningful: the macOS toaster prefers it for
	// click-to-open routing; absent it, clicks go nowhere.
	if !tnAvailable {
		warnings = append(warnings,
			"Click-to-open notifications need `terminal-notifier`. Install via "+
				"`brew install terminal-notifier`. Without it, toasts still fire but "+
				"clicking them opens Script Editor instead of the audr dashboard.")
	}

	return warnings
}

// terminalNotifierPresent reports whether terminal-notifier is on the
// daemon's PATH. Mirrors the check inside internal/notify's
// darwinToaster constructor so the preflight surface and the runtime
// behavior stay in sync.
func terminalNotifierPresent() bool {
	_, err := exec.LookPath("terminal-notifier")
	return err == nil
}
