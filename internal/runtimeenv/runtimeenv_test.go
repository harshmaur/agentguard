package runtimeenv

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

func TestDetectFillsOSAndArch(t *testing.T) {
	info := Detect(context.Background())
	if info.OS != runtime.GOOS {
		t.Fatalf("OS = %q, want %q", info.OS, runtime.GOOS)
	}
	if info.Arch != runtime.GOARCH {
		t.Fatalf("Arch = %q, want %q", info.Arch, runtime.GOARCH)
	}
	if info.Kind == "" {
		t.Fatalf("Kind must be non-empty (got empty)")
	}
}

func TestKindFromVendor(t *testing.T) {
	cases := []struct {
		vendor string
		role   string
		want   Kind
	}{
		{"docker", "guest", KindContainer},
		{"podman", "guest", KindContainer},
		{"kubernetes", "guest", KindContainer},
		{"kvm", "guest", KindVM},
		{"vmware", "guest", KindVM},
		{"hyperv", "guest", KindVM},
		{"wsl", "guest", KindWSL},
		{"", "", KindBareMetal},
		// "host" role means we're the hypervisor host, not a guest.
		{"kvm", "host", KindBareMetal},
		{"made-up-runtime", "guest", KindUnknown},
	}
	for _, tc := range cases {
		if got := kindFromVendor(tc.vendor, tc.role); got != tc.want {
			t.Errorf("kindFromVendor(%q, %q) = %q, want %q", tc.vendor, tc.role, got, tc.want)
		}
	}
}

func TestParseMountInfo_BindMountDetected(t *testing.T) {
	// Two synthetic /proc/self/mountinfo lines:
	//   - overlay root: the container's own writable layer.
	//   - bind of /host: classic `docker run -v $HOME:/host` shape.
	in := `25 0 254:1 / / rw,relatime shared:1 - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/foo
1234 25 0:42 /Users/dev /host rw,relatime - ext4 /dev/disk1s1 rw
`
	entries := parseMountInfo(in)
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if entries[0].MountPoint != "/" || entries[0].FSType != "overlay" {
		t.Errorf("root entry = %+v", entries[0])
	}
	if entries[1].MountPoint != "/host" || entries[1].FSType != "ext4" || entries[1].Source != "/dev/disk1s1" {
		t.Errorf("bind entry = %+v", entries[1])
	}
}

func TestClassifyOne_HostBoundBindMount(t *testing.T) {
	entries := []mountInfoEntry{
		{MountPoint: "/host", FSType: "ext4", Source: "/dev/disk1s1"},
		{MountPoint: "/", FSType: "overlay", Source: "overlay"},
	}
	m := classifyOne("/host/repo", entries)
	if !m.HostBound {
		t.Fatalf("expected HostBound=true for /host/repo, got %+v", m)
	}
	if m.FSType != "ext4" {
		t.Errorf("FSType = %q, want ext4", m.FSType)
	}
}

func TestClassifyOne_ContainerLocalOverlay(t *testing.T) {
	entries := []mountInfoEntry{
		{MountPoint: "/", FSType: "overlay", Source: "overlay"},
	}
	m := classifyOne("/workspace", entries)
	if m.HostBound {
		t.Fatalf("expected HostBound=false for /workspace inside overlay root, got %+v", m)
	}
}

func TestClassifyOne_NoMountInfo(t *testing.T) {
	m := classifyOne("/anywhere", nil)
	if m.HostBound || m.FSType != "" {
		t.Fatalf("expected zero Mount when no mountinfo, got %+v", m)
	}
}

func TestUnescapeOctal(t *testing.T) {
	cases := map[string]string{
		`/plain`:                  `/plain`,
		`/path\040with\040space`:  `/path with space`,
		`/tab\011here`:            "/tab\there",
		`/back\134slash`:          `/back\slash`,
	}
	for in, want := range cases {
		if got := unescapeOctal(in); got != want {
			t.Errorf("unescapeOctal(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassifyRoots_PassesThroughPath(t *testing.T) {
	got := ClassifyRoots([]string{"."})
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Path != "." {
		t.Errorf("Path = %q, want '.'", got[0].Path)
	}
}

func TestDetectIncludesEvidenceWhenPresent(t *testing.T) {
	// We can't reliably synthesize a container env in the test process, so
	// just assert the Evidence slice is empty-or-strings and that the
	// detection function doesn't panic.
	info := Detect(context.Background())
	for _, e := range info.Evidence {
		if strings.TrimSpace(e) == "" {
			t.Errorf("empty evidence entry in %+v", info.Evidence)
		}
	}
}
