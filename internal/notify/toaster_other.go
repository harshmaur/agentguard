//go:build !linux

package notify

// defaultToaster picks the platform default toaster. On non-Linux
// platforms today this is the beeep-backed toaster, which has no
// click-action support — onClick is dropped.
//
// macOS click-to-open lands when we either bundle audr as a .app or
// detect terminal-notifier on PATH and route through it. Windows
// click-to-open needs AppUserModelID registration. Both are
// follow-up slices.
func defaultToaster(_ OnClick) Toaster {
	return beeepToaster{}
}
