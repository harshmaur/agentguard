package ospkg

import (
	"testing"
)

func TestManagerForRecognizedDistros(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		idLike  string
		wantMgr Manager
		wantID  DistroID
		wantOK  bool
	}{
		{"debian", "debian", "", ManagerDpkg, DistroDebian, true},
		{"ubuntu", "ubuntu", "debian", ManagerDpkg, DistroUbuntu, true},
		{"linuxmint via id_like", "linuxmint", "ubuntu debian", ManagerDpkg, DistroUbuntu, true},
		{"rhel", "rhel", "", ManagerRpm, DistroRHEL, true},
		{"rocky", "rocky", "rhel centos fedora", ManagerRpm, DistroRocky, true},
		{"alma", "almalinux", "rhel centos fedora", ManagerRpm, DistroAlma, true},
		{"centos", "centos", "", ManagerRpm, DistroCentOS, true},
		{"fedora", "fedora", "", ManagerRpm, DistroFedora, true},
		{"alpine", "alpine", "", ManagerApk, DistroAlpine, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, distroID, ok := managerFor(tt.id, tt.idLike)
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
			if mgr != tt.wantMgr {
				t.Errorf("manager = %q, want %q", mgr, tt.wantMgr)
			}
			if distroID != tt.wantID {
				t.Errorf("distro ID = %q, want %q", distroID, tt.wantID)
			}
		})
	}
}

func TestManagerForUnknownDistros(t *testing.T) {
	// OSV-Scanner doesn't cover these well — Phase 4 keeps them
	// "unavailable" rather than producing noisy/empty findings.
	for _, id := range []string{"arch", "manjaro", "opensuse-tumbleweed", "gentoo", "void"} {
		t.Run(id, func(t *testing.T) {
			_, _, ok := managerFor(id, "")
			if ok {
				t.Errorf("managerFor(%q) = ok; want false (OSV coverage gap)", id)
			}
		})
	}
}
