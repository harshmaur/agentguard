//go:build !linux

package watch

// macOS / Windows stub. Phase 3 detects remote filesystems on Linux
// only; macOS would need a similar statfs (f_fstypename string field)
// and Windows would need GetVolumeInformation + IsNetworkDrive. Both
// land in v1.1.
//
// Returning FSLocal here means the watcher behaves as if all paths
// are local (fsnotify on, no banner). That's the right safe default:
// on macOS dev laptops the home dir is almost always APFS; on
// Windows it's NTFS. The minority case of a $HOME on SMB or
// fileserver-mounted disk doesn't yet trigger the banner.

type stubDetector struct{}

func DefaultRemoteFSDetector() RemoteFSDetector { return stubDetector{} }

func (stubDetector) Detect(_ string) (RemoteFSKind, error) {
	return FSLocal, nil
}
