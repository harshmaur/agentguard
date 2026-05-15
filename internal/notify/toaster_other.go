//go:build !linux && !darwin

package notify

// defaultToaster picks the platform default toaster. Linux uses dbus
// (toaster_linux.go); macOS uses terminal-notifier-or-osascript
// (toaster_darwin.go); this file covers Windows (beeep fallback,
// pre-WinRT) plus *BSD / Solaris / etc. that audr doesn't actively
// target.
//
// Windows click-to-open lands when toaster_windows.go ships in v1.1
// with AppUserModelID registration at install time. Until then,
// beeep's PowerShell-driven BurntToast path is the best we get —
// it displays the toast but does not route clicks.
func defaultToaster(_ OnClick) Toaster {
	return beeepToaster{}
}
