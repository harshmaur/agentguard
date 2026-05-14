package ospkg

import (
	"context"
	"testing"
)

// fakeRunner returns canned stdout for a given (name, args[0]).
// Tests register expected commands and what to return.
type fakeRunner struct {
	out map[string][]byte
}

func newFakeRunner() *fakeRunner { return &fakeRunner{out: map[string][]byte{}} }

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name
	if len(args) > 0 {
		key = name + " " + args[0]
	}
	if v, ok := f.out[key]; ok {
		return v, nil
	}
	return nil, nil
}

func TestParseDpkgQueryRealOutput(t *testing.T) {
	// Verbatim from a Debian 12 install. Note epoch versions and a
	// deinstall-state row (empty version, must be skipped).
	body := []byte(`adduser	3.137ubuntu1
apt	2.7.10
base-files	12.5+deb12u3
libc6	2.36-9+deb12u4
removed-pkg
libssl3	3.0.13-1~deb12u1
`)
	pkgs := parseDpkgQuery(body)
	if len(pkgs) != 5 {
		t.Fatalf("got %d packages, want 5 (deinstall row must be skipped); pkgs=%v", len(pkgs), pkgs)
	}
	want := []Package{
		{ManagerDpkg, "adduser", "3.137ubuntu1"},
		{ManagerDpkg, "apt", "2.7.10"},
		{ManagerDpkg, "base-files", "12.5+deb12u3"},
		{ManagerDpkg, "libc6", "2.36-9+deb12u4"},
		{ManagerDpkg, "libssl3", "3.0.13-1~deb12u1"},
	}
	for i, w := range want {
		if pkgs[i] != w {
			t.Errorf("pkg[%d] = %+v, want %+v", i, pkgs[i], w)
		}
	}
}

func TestParseRpmQueryStripsNoneEpoch(t *testing.T) {
	body := []byte(`openssl	(none):3.0.7-22.el9
glibc	(none):2.34-83.el9
NetworkManager	1:1.42.2-14.el9
broken
`)
	pkgs := parseRpmQuery(body)
	if len(pkgs) != 3 {
		t.Fatalf("got %d packages, want 3", len(pkgs))
	}
	if pkgs[0].Version != "3.0.7-22.el9" {
		t.Errorf("openssl version = %q, want 3.0.7-22.el9 (stripped (none):)", pkgs[0].Version)
	}
	if pkgs[2].Version != "1:1.42.2-14.el9" {
		t.Errorf("NetworkManager version = %q, want 1:1.42.2-14.el9 (epoch kept)", pkgs[2].Version)
	}
}

func TestParseApkInfoSplitsNameVersionRelease(t *testing.T) {
	body := []byte(`musl-1.2.4-r2
libcrypto3-3.1.4-r0
busybox-1.36.1-r5
ca-certificates-bundle-20240705-r0
zlib-1.3.1-r0
`)
	pkgs := parseApkInfo(body)
	if len(pkgs) != 5 {
		t.Fatalf("got %d packages, want 5; pkgs=%v", len(pkgs), pkgs)
	}
	want := []Package{
		{ManagerApk, "musl", "1.2.4-r2"},
		{ManagerApk, "libcrypto3", "3.1.4-r0"},
		{ManagerApk, "busybox", "1.36.1-r5"},
		{ManagerApk, "ca-certificates-bundle", "20240705-r0"}, // hyphen in name
		{ManagerApk, "zlib", "1.3.1-r0"},
	}
	for i, w := range want {
		if pkgs[i] != w {
			t.Errorf("pkg[%d] = %+v, want %+v", i, pkgs[i], w)
		}
	}
}

func TestSplitApkLineFallbacks(t *testing.T) {
	// No -r release suffix: keep whole tail as version.
	name, version := splitApkLine("dev-tool-1.2.3")
	if name != "dev-tool" || version != "1.2.3" {
		t.Errorf("dev-tool-1.2.3 → name=%q version=%q, want dev-tool/1.2.3", name, version)
	}
	// No version → empty result (so the row is dropped upstream).
	name, version = splitApkLine("not-a-package")
	if name != "" || version != "" {
		t.Errorf("not-a-package: name=%q version=%q, want empty/empty", name, version)
	}
}

func TestEnumerateDispatchesByManager(t *testing.T) {
	cases := []struct {
		manager  Manager
		key      string
		out      string
		wantName string
	}{
		{ManagerDpkg, "dpkg-query -W", "openssl\t3.0.7-1\n", "openssl"},
		{ManagerRpm, "rpm -qa", "openssl\t(none):3.0.7-22.el9\n", "openssl"},
		{ManagerApk, "apk info", "openssl-3.1.4-r0\n", "openssl"},
	}
	for _, tt := range cases {
		t.Run(string(tt.manager), func(t *testing.T) {
			r := newFakeRunner()
			r.out[tt.key] = []byte(tt.out)

			var pkgs []Package
			var err error
			switch tt.manager {
			case ManagerDpkg:
				pkgs, err = enumerateDpkg(context.Background(), r)
			case ManagerRpm:
				pkgs, err = enumerateRpm(context.Background(), r)
			case ManagerApk:
				pkgs, err = enumerateApk(context.Background(), r)
			}
			if err != nil {
				t.Fatalf("enumerate: %v", err)
			}
			if len(pkgs) != 1 {
				t.Fatalf("len(pkgs) = %d, want 1", len(pkgs))
			}
			if pkgs[0].Name != tt.wantName {
				t.Errorf("name = %q, want %q", pkgs[0].Name, tt.wantName)
			}
			if pkgs[0].Manager != tt.manager {
				t.Errorf("manager = %q, want %q", pkgs[0].Manager, tt.manager)
			}
		})
	}
}
