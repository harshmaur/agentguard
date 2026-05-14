//go:build linux

package watch

import (
	"fmt"
	"syscall"
)

// Linux filesystem magic numbers we recognize. Reference:
// /usr/include/linux/magic.h. We match the ones that show up in real
// dev-machine setups; an unknown magic falls back to FSLocal so the
// daemon doesn't refuse to scan rare-but-local filesystems (btrfs,
// zfs, etc., are all "local enough" for fsnotify).
const (
	magicNFS    = 0x6969
	magicCIFS   = 0xff534d42 // SMB1/CIFS
	magicSMB2   = 0xfe534d42 // SMB2
	magicSshfs  = 0x65735546 // FUSE — sshfs is the most common FUSE mount
	magic9p     = 0x01021997 // 9P — WSL /mnt/<drive> uses this
)

type linuxDetector struct{}

// DefaultRemoteFSDetector returns the per-OS detector.
func DefaultRemoteFSDetector() RemoteFSDetector { return linuxDetector{} }

// Detect runs syscall.Statfs and maps the f_type field to a
// RemoteFSKind. Errors from Statfs (e.g., path doesn't exist) bubble
// up rather than getting silently mapped to FSLocal — the caller
// (watcher startup) wants to know.
func (linuxDetector) Detect(path string) (RemoteFSKind, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return FSLocal, fmt.Errorf("statfs %s: %w", path, err)
	}
	switch uint64(st.Type) { // st.Type is int64 on amd64, int32 on 32-bit
	case magicNFS:
		return FSNFS, nil
	case magicCIFS, magicSMB2:
		return FSSMB, nil
	case magic9p:
		return FSWSL, nil // 9p in practice means a WSL host mount
	case magicSshfs:
		// FUSE could be sshfs OR a local FUSE mount (e.g., ntfs-3g).
		// Without inspecting /proc/self/mountinfo we can't be sure.
		// Mark it FSFuse so the dashboard banner is honest, and let
		// the user know what we saw.
		return FSFuse, nil
	default:
		return FSLocal, nil
	}
}
