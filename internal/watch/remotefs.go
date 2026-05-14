package watch

// RemoteFSKind enumerates the filesystem types we treat specially.
// "local" = native disk; everything else triggers poll-only mode +
// a dashboard banner per /plan-eng-review.
type RemoteFSKind string

const (
	FSLocal RemoteFSKind = "local"
	FSNFS   RemoteFSKind = "nfs"
	FSSMB   RemoteFSKind = "smb"
	FSSshfs RemoteFSKind = "sshfs"  // fuse-mounted sshfs
	FSWSL   RemoteFSKind = "wsl"    // 9p-mounted /mnt/c from WSL host
	FS9P    RemoteFSKind = "9p"     // generic 9p
	FSFuse  RemoteFSKind = "fuse"   // catchall FUSE — may be remote or local
)

// RemoteFSDetector probes a filesystem path and reports its kind.
// Implementations are per-OS (see remotefs_linux.go / _darwin.go /
// _windows.go) and behind a //go:build tag so cross-platform builds
// don't pull in OS-specific stat syscalls.
type RemoteFSDetector interface {
	Detect(path string) (RemoteFSKind, error)
}

// IsRemote reports whether the kind warrants poll-only fallback +
// dashboard banner per the design doc.
func (k RemoteFSKind) IsRemote() bool {
	switch k {
	case FSNFS, FSSMB, FSSshfs, FSWSL, FS9P, FSFuse:
		return true
	default:
		return false
	}
}
