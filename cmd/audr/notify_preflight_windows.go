//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/registry"
)

// preflightNotifications surfaces user-visible warnings about Windows
// notification environment state that would make a toast appear to
// succeed silently. Observed (and documented) silent-failure modes:
//
//   - Quiet Hours / Focus Assist suppresses popups. Notifications
//     queue in Action Center but never pop. Toggle via Settings →
//     System → Focus.
//
//   - Toast notifications disabled system-wide via the master switch
//     under Settings → System → Notifications.
//
//   - Per-application notifications disabled. Without an
//     AppUserModelID-registered Start Menu shortcut audr doesn't have
//     its own per-app entry; beeep's PowerShell-driven backend
//     attributes toasts to PowerShell or Windows.UI.Notifications,
//     and the user can have THAT identity blocked while everything
//     else allows.
//
// Empty slice = environment looks fine. Caller prints the list as
// per-item warnings before firing the test toast.
//
// All probes are read-only registry queries via the standard
// `golang.org/x/sys/windows/registry` package. No PowerShell shell-outs,
// no admin required.
func preflightNotifications() []string {
	var warnings []string

	if msg := checkSystemNotificationsEnabled(); msg != "" {
		warnings = append(warnings, msg)
	}
	if msg := checkToastsApplicationNotification(); msg != "" {
		warnings = append(warnings, msg)
	}
	if msg := checkQuietHours(); msg != "" {
		warnings = append(warnings, msg)
	}
	if msg := checkAppUserModelIDPresent(); msg != "" {
		warnings = append(warnings, msg)
	}

	return warnings
}

// checkSystemNotificationsEnabled reads the master notifications
// toggle under HKCU. Path:
//
//	HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications
//	     value: ToastEnabled (DWORD, 1=enabled, 0=disabled)
//
// Default behavior: when the value is missing, Windows treats
// notifications as enabled — return nil. Only flag the explicit
// disabled state.
func checkSystemNotificationsEnabled() string {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\PushNotifications`,
		registry.QUERY_VALUE)
	if err != nil {
		return "" // key absent → Windows defaults enabled
	}
	defer k.Close()

	v, _, err := k.GetIntegerValue("ToastEnabled")
	if err != nil {
		return ""
	}
	if v == 0 {
		return "System notifications are disabled. Settings → System → Notifications → 'Notifications' must be On for audr's toasts to fire."
	}
	return ""
}

// checkToastsApplicationNotification probes the user-scope master
// toast switch:
//
//	HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications
//	     value: NoToastApplicationNotification (DWORD, 1=blocked)
//
// This is the group-policy-side toggle that overrides
// PushNotifications\ToastEnabled. Some corporate-managed laptops
// will have this set — audr's toasts fire successfully from the API
// surface but never reach the desktop. Without surfacing it the user
// is stuck guessing why their `--test` toast didn't appear.
func checkToastsApplicationNotification() string {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications`,
		registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()

	v, _, err := k.GetIntegerValue("NoToastApplicationNotification")
	if err != nil {
		return ""
	}
	if v == 1 {
		return "Group Policy 'NoToastApplicationNotification' is blocking application toasts. On a personal machine: delete the HKCU\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications value. On a managed machine: contact your IT admin — the policy is enforced from Active Directory / Intune."
	}
	return ""
}

// checkQuietHours probes Focus Assist (formerly Quiet Hours).
//
//	HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings
//	     value: NOC_GLOBAL_SETTING_TOASTS_ENABLED (DWORD, 0=disabled in current focus)
//
// Focus Assist is a mode rather than a single bit. The most reliable
// indicator across versions is the toasts-enabled flag in the
// notifications-settings subtree. A 0 means the user is currently in
// a focus mode that's suppressing toasts.
func checkQuietHours() string {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Notifications\Settings`,
		registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()

	v, _, err := k.GetIntegerValue("NOC_GLOBAL_SETTING_TOASTS_ENABLED")
	if err != nil {
		return ""
	}
	if v == 0 {
		return "Focus Assist / Quiet Hours is currently active and suppressing toasts. Toggle off via Settings → System → Focus, or via the Action Center → Focus tile."
	}
	return ""
}

// checkAppUserModelIDPresent confirms audr has a Start Menu shortcut
// carrying the AppUserModelID that lets Windows route notification
// clicks back to a launchable target. The shortcut lives at:
//
//	%APPDATA%\Microsoft\Windows\Start Menu\Programs\Audr.lnk
//
// When `audr daemon install` registers the AppUserModelID in a
// follow-up slice (Lane A continuation), the shortcut lands there.
// Until then the shortcut won't exist — Windows toasts still fire via
// beeep but clicks route to the PowerShell launcher (which does
// nothing useful for audr's "open the dashboard" intent).
//
// Surfacing this as a warning prepares users for the deferred state:
// they understand why clicking doesn't work and that an install-time
// fix will land later, not that something is broken.
//
// On installs where the AppUserModelID work HAS landed, the shortcut
// exists and this probe returns empty.
func checkAppUserModelIDPresent() string {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		// Without %APPDATA% we can't probe — and audr has bigger
		// problems than notification routing. Skip silently; the
		// other registry probes already covered the toast surface.
		return ""
	}
	shortcut := appData + `\Microsoft\Windows\Start Menu\Programs\Audr.lnk`
	if _, err := os.Stat(shortcut); err == nil {
		return ""
	}
	return fmt.Sprintf(
		"AppUserModelID Start Menu shortcut not registered at %q. Toasts will fire but clicking them won't open the dashboard. This shortcut is created automatically by a future `audr daemon install` slice; until then, run `audr open` after a notification to investigate.",
		shortcut,
	)
}
