//go:build darwin

package notify

import (
	"fmt"
	"os/exec"
)

// darwinToaster fires notifications on macOS. Two backends:
//
//  1. `terminal-notifier` (preferred): supports click-to-execute,
//     so we register `-execute "audr open"` and the user's click
//     opens the live dashboard URL via the CLI's existing state-file
//     read path. This deliberately mirrors how the Linux toaster
//     resolves the URL fresh at click time — restart-survival is the
//     same in both cases because `audr open` reads the daemon's
//     state file each time it runs.
//
//  2. `osascript display notification` fallback: works on a stock
//     macOS install with no third-party tooling, but the click never
//     routes anywhere useful (it opens Script Editor at best). The
//     Notifier consults SupportsClickAction() and appends the
//     "run audr open" hint to the body when this backend is active,
//     so the user still has a working manual path.
//
// We do NOT bundle audr as a .app — that contradicts the single-static-
// binary trust thesis (and forces notarization onto the release
// pipeline). The cost is a brew install for users who want clickable
// toasts; the install.sh / README prints the suggestion at install
// time and the preflight diagnostic surfaces it on demand.
type darwinToaster struct {
	// terminalNotifierPath is the resolved exec.LookPath of
	// terminal-notifier at construction time. Empty string means
	// "fall through to osascript." Resolved once; we do NOT
	// re-probe per-toast because brew-install/uninstall during a
	// daemon's lifetime is rare and the cost of a stale path is
	// "one failed toast" — the next toast loops back through the
	// osascript path on error.
	terminalNotifierPath string

	// onClick is held but only meaningful for the terminal-notifier
	// path. osascript notifications cannot route clicks back to a
	// Go callback, so onClick is dropped in the fallback.
	onClick OnClick
}

// newDarwinToaster constructs the macOS toaster. Always succeeds —
// even on a macOS box with neither terminal-notifier nor a working
// osascript, the toaster constructs and Toast() will surface the
// per-call error to the caller (which records to pending-notify.json
// via the Notifier).
func newDarwinToaster(onClick OnClick) *darwinToaster {
	tn, _ := exec.LookPath("terminal-notifier")
	return &darwinToaster{
		terminalNotifierPath: tn,
		onClick:              onClick,
	}
}

// Toast fires the notification. Routes through terminal-notifier when
// available (with click-to-execute wired to `audr open`), otherwise
// falls through to osascript without click action.
func (dt *darwinToaster) Toast(title, body string) error {
	if dt.terminalNotifierPath != "" {
		return dt.toastViaTerminalNotifier(title, body)
	}
	return dt.toastViaOsascript(title, body)
}

func (dt *darwinToaster) toastViaTerminalNotifier(title, body string) error {
	// terminal-notifier flags:
	//   -title    notification title (shows above body)
	//   -message  notification body
	//   -execute  shell command to run when user clicks the notification
	//   -sender   bundle identifier used for the notification's
	//             on-screen identity; "com.apple.Terminal" is a safe
	//             default that doesn't require us to register our own
	//             bundle and works without notarization concerns.
	//             We pass our own identifier when one exists; otherwise
	//             omit -sender entirely.
	//
	// We don't pass -group: the Notifier owns per-fingerprint dedup
	// already; -group would only matter if we wanted re-fires of the
	// same fingerprint to replace prior toasts in-place, which is the
	// opposite of what cooldown guarantees.
	args := []string{
		"-title", title,
		"-message", body,
		"-execute", "audr open",
	}
	cmd := exec.Command(dt.terminalNotifierPath, args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("notify: terminal-notifier: %w", err)
	}
	return nil
}

func (dt *darwinToaster) toastViaOsascript(title, body string) error {
	// AppleScript's display-notification cannot carry a click action.
	// We accept this and lean on the Notifier's body-suffix logic to
	// give the user a manual path ("run audr open to investigate").
	//
	// Escape any embedded double-quotes in body/title to keep the
	// AppleScript string literal valid. macOS Focus Mode / DND
	// suppresses the toast silently — osascript still returns 0 in
	// that case, so we cannot detect the suppression from here.
	// notify_preflight_darwin.go handles the diagnostic surface.
	script := fmt.Sprintf(
		`display notification %q with title %q`,
		body, title,
	)
	cmd := exec.Command("osascript", "-e", script)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("notify: osascript: %w", err)
	}
	return nil
}

// SupportsClickAction reports true when terminal-notifier is on PATH
// and onClick is non-nil. False otherwise — the Notifier appends the
// `run "audr open"` hint to the body so the user has a fallback.
// Implements ClickableToaster.
//
// Note: onClick itself is not invoked by the macOS toaster — clicks
// route through `audr open` (a shell-out from terminal-notifier),
// which reads the live state file. We still require a non-nil
// onClick to report true because the daemon-build path that disables
// click-routing entirely passes nil OnClick, and the user-visible
// body should reflect that.
func (dt *darwinToaster) SupportsClickAction() bool {
	return dt.terminalNotifierPath != "" && dt.onClick != nil
}

// TerminalNotifierAvailable reports whether terminal-notifier was
// detected on PATH at construction. Exposed for the preflight
// diagnostic in cmd/audr/notify_preflight_darwin.go.
func (dt *darwinToaster) TerminalNotifierAvailable() bool {
	return dt.terminalNotifierPath != ""
}

// defaultToaster on macOS: always returns the darwinToaster. The
// terminal-notifier-vs-osascript decision happens inside Toast()
// based on what was detected at construction.
func defaultToaster(onClick OnClick) Toaster {
	return newDarwinToaster(onClick)
}

// Compile-time assertion that darwinToaster satisfies ClickableToaster.
// Doesn't need to satisfy LifecycleToaster — no goroutine needed; the
// click handler lives inside terminal-notifier's own process.
var _ ClickableToaster = (*darwinToaster)(nil)
var _ Toaster = (*darwinToaster)(nil)
