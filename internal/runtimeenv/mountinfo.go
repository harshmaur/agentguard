package runtimeenv

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Mount describes how one of audr's scan roots relates to the host
// filesystem. The interesting bit for container runs is HostBound: a true
// value means the path was bind-mounted from outside the container (e.g.
// `docker run -v $HOME:/host`) and the report is genuinely about host files
// even though audr ran inside a container.
type Mount struct {
	Path      string `json:"path"`             // path as passed to `audr scan`
	MountPoint string `json:"mount_point,omitempty"` // matched mountinfo mount point (may be a prefix of Path)
	Source    string `json:"source,omitempty"` // device or bind-source from mountinfo
	FSType    string `json:"fs_type,omitempty"`
	HostBound bool   `json:"host_bound"`       // true = looks bind-mounted from outside
}

// ClassifyRoots maps each scan root onto its mountinfo entry, classifying
// bind mounts that look like they came from a host filesystem. On non-Linux
// systems (or when /proc/self/mountinfo is unreadable) every root is
// returned with HostBound=false and the other fields empty.
func ClassifyRoots(roots []string) []Mount {
	entries := readMountInfo()
	out := make([]Mount, 0, len(roots))
	for _, r := range roots {
		abs, err := filepath.Abs(r)
		if err != nil {
			abs = r
		}
		m := classifyOne(abs, entries)
		m.Path = r
		out = append(out, m)
	}
	return out
}

type mountInfoEntry struct {
	MountPoint string
	Source     string
	FSType     string
	OptFields  []string // optional fields between dash separators in /proc/self/mountinfo
}

func classifyOne(abs string, entries []mountInfoEntry) Mount {
	// Walk entries longest-mount-point first so /host/foo wins over /host.
	for _, e := range entries {
		if abs == e.MountPoint || strings.HasPrefix(abs, e.MountPoint+"/") {
			m := Mount{
				MountPoint: e.MountPoint,
				Source:     e.Source,
				FSType:     e.FSType,
			}
			m.HostBound = looksHostBound(e)
			return m
		}
	}
	return Mount{}
}

// looksHostBound applies the heuristics that distinguish a bind mount from a
// container-local fs. We treat anything mounted on a real device or with a
// source path that isn't under /var/lib/{docker,containers}/overlay (the
// typical container-local layer location) as host-bound. False positives
// here are preferable to false negatives — overstating "this came from the
// host" is the safer reading for an audit report.
func looksHostBound(e mountInfoEntry) bool {
	src := strings.TrimSpace(e.Source)
	fs := strings.ToLower(strings.TrimSpace(e.FSType))

	// overlay / overlay2 / aufs are the classic container-local fs. If the
	// mount point is at "/" with one of these types, we're looking at the
	// container's own writable layer — not host-bound.
	switch fs {
	case "overlay", "overlay2", "aufs":
		return false
	case "tmpfs", "proc", "sysfs", "cgroup", "cgroup2", "devpts", "mqueue", "nsfs":
		return false
	}

	// A non-empty source that is NOT under typical container-storage prefixes
	// is a strong "this came from outside" signal.
	if src == "" {
		return false
	}
	for _, prefix := range []string{
		"/var/lib/docker/",
		"/var/lib/containers/",
		"/var/lib/containerd/",
		"overlay",
		"none",
	} {
		if strings.HasPrefix(src, prefix) {
			return false
		}
	}
	return true
}

func readMountInfo() []mountInfoEntry {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	entries := parseMountInfo(string(data))
	// Longest mount point first so prefix matches resolve to the most-
	// specific overlay (a bind mount of /host/foo wins over /host).
	sort.SliceStable(entries, func(i, j int) bool {
		return len(entries[i].MountPoint) > len(entries[j].MountPoint)
	})
	return entries
}

// parseMountInfo is the lenient /proc/self/mountinfo reader. Format:
//
//   mount_id parent_id major:minor root mount_point options - fs_type source super_options
//
// We only need fields [4]=mount_point, [-3]=fs_type, [-2]=source. The
// "optional fields" between mount_point and the literal "-" can contain a
// variable number of tokens.
func parseMountInfo(text string) []mountInfoEntry {
	var out []mountInfoEntry
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		// Find the dash separator that splits the variable-length optional
		// fields from the post-separator tail.
		dash := -1
		for i, f := range fields {
			if f == "-" {
				dash = i
				break
			}
		}
		if dash < 0 || dash+3 > len(fields) {
			continue
		}
		entry := mountInfoEntry{
			MountPoint: unescapeOctal(fields[4]),
			FSType:     fields[dash+1],
			Source:     unescapeOctal(fields[dash+2]),
		}
		if dash > 6 {
			entry.OptFields = fields[6:dash]
		}
		out = append(out, entry)
	}
	return out
}

// unescapeOctal handles the \040 \011 \012 \134 escapes that the kernel
// uses for whitespace and backslash in mount paths. Anything else passes
// through unchanged.
func unescapeOctal(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			v := (int(s[i+1]-'0') << 6) | (int(s[i+2]-'0') << 3) | int(s[i+3]-'0')
			if v >= 0 && v < 128 {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
