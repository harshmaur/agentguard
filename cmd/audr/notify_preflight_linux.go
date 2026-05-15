//go:build linux

package main

import (
	"os"
	"os/exec"
	"strings"
)

// preflightNotifications returns user-visible warnings about Linux
// notification environment state that would make a toast appear to
// succeed (beeep / dbus returns no error) but never display as a
// banner. These were the actual failure modes observed in the wild:
//
//   - notify-send / libnotify-bin missing → dbus returns success
//     but no daemon delivers the notification to the user
//   - org.gnome.desktop.notifications show-banners=false → banners
//     suppressed system-wide, notifications go silently to the tray
//   - DND / Focus mode equivalents (per-DE)
//
// Empty slice = environment looks fine. Caller prints the list as
// "audr: notification preflight detected potential issues:" + bullets.
func preflightNotifications() []string {
	var warnings []string

	// notify-send presence is a strong proxy for "the OS has a
	// notification client installed." Its absence doesn't break
	// godbus calls but every desktop should have it.
	if _, err := exec.LookPath("notify-send"); err != nil {
		warnings = append(warnings,
			"`notify-send` not found on PATH. Install libnotify-bin: `sudo apt install libnotify-bin`")
	}

	// DBUS session bus must be reachable. Without it, godbus calls
	// fail loudly — but if DBUS_SESSION_BUS_ADDRESS isn't even set
	// the user's systemd-user environment may have stripped it.
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		warnings = append(warnings,
			"DBUS_SESSION_BUS_ADDRESS env var is empty. The daemon may not see your user session bus.")
	}

	// GNOME-specific: show-banners=false silently drops popups.
	// Notifications still go to the tray drawer (click clock in top
	// bar) but never pop up. Cheap probe: read the gsettings key.
	// We use `gsettings get` rather than dbus-Settings because the
	// binary is more uniformly present.
	if _, err := exec.LookPath("gsettings"); err == nil {
		out, err := exec.Command("gsettings", "get",
			"org.gnome.desktop.notifications", "show-banners").Output()
		if err == nil && strings.TrimSpace(string(out)) == "false" {
			warnings = append(warnings,
				"GNOME `show-banners` is OFF — banners will go silently to the tray drawer. "+
					"To re-enable popups: `gsettings set org.gnome.desktop.notifications show-banners true`")
		}
	}

	return warnings
}
