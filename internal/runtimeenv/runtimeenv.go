// Package runtimeenv detects whether audr is running on bare metal, inside a
// container, inside a VM, or inside WSL — and which scanned roots are
// bind-mounted from a host vs. native to the runtime.
//
// The report surfaces this so a reader can answer "is this scan about the
// developer machine or about a throwaway container filesystem?" without
// guessing. Detection is informational only: nothing here ever produces a
// finding or changes scan behavior.
//
// Primary signal comes from github.com/shirou/gopsutil/v4/host, which mirrors
// systemd-detect-virt's logic across Linux/macOS/Windows. We supplement that
// with our own evidence collector — every signal that fired is captured by
// name so the report can show the receipts, not just the verdict.
package runtimeenv

import (
	"context"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/host"
)

// Kind labels the broad runtime category. "unknown" is reserved for cases
// where every signal came back empty — rare, but possible on restricted
// systems where /proc is mounted noproc or the calling user has no read
// access to cgroup files.
type Kind string

const (
	KindBareMetal Kind = "bare-metal"
	KindContainer Kind = "container"
	KindVM        Kind = "vm"
	KindWSL       Kind = "wsl"
	KindUnknown   Kind = "unknown"
)

// Info is the detection result. Vendor and Role may be empty when the kind
// is bare-metal or unknown; callers should treat empty strings as "no
// information" rather than "false".
type Info struct {
	Kind     Kind     `json:"kind"`
	Vendor   string   `json:"vendor,omitempty"` // docker, podman, kubernetes, kvm, vmware, vbox, hyperv, apple-vm, wsl
	Role     string   `json:"role,omitempty"`   // guest / host
	OS       string   `json:"os"`               // runtime.GOOS at scan time
	Arch     string   `json:"arch"`             // runtime.GOARCH
	Evidence []string `json:"evidence,omitempty"`
}

// Detect runs all available signals and returns a single consolidated Info.
// The context is honored for the gopsutil host probe; everything else is
// synchronous file/env reads with their own short hard timeouts.
func Detect(ctx context.Context) Info {
	info := Info{
		Kind: KindBareMetal,
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}

	// gopsutil first — it gives us the cleanest vendor name when it works,
	// and its detection covers more edge cases than our own.
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if hi, err := host.InfoWithContext(probeCtx); err == nil {
		if hi.VirtualizationSystem != "" {
			info.Vendor = hi.VirtualizationSystem
			info.Role = hi.VirtualizationRole
			info.Evidence = append(info.Evidence, "gopsutil:"+hi.VirtualizationSystem+"/"+hi.VirtualizationRole)
			info.Kind = kindFromVendor(hi.VirtualizationSystem, hi.VirtualizationRole)
		}
	}

	// Layer our own evidence collector. We don't override gopsutil's vendor
	// — its mapping is well-tested — but if gopsutil came back empty and one
	// of our signals fires, we promote the strongest one to vendor + kind.
	for _, ev := range collectEvidence() {
		info.Evidence = append(info.Evidence, ev.signal)
		if info.Vendor == "" && ev.vendor != "" {
			info.Vendor = ev.vendor
			info.Kind = ev.kind
			info.Role = "guest"
		}
	}

	return info
}

// kindFromVendor maps a gopsutil VirtualizationSystem string onto our Kind
// enum. The vendor strings come from systemd-detect-virt conventions: see
// https://www.freedesktop.org/software/systemd/man/latest/systemd-detect-virt.html
func kindFromVendor(vendor, role string) Kind {
	if role == "host" {
		// "host" with a non-empty vendor means we're the host of a hypervisor
		// — still bare-metal from our perspective.
		return KindBareMetal
	}
	switch strings.ToLower(vendor) {
	case "docker", "podman", "lxc", "lxc-libvirt", "openvz", "rkt", "systemd-nspawn", "containerd", "cri-o", "kubernetes":
		return KindContainer
	case "kvm", "qemu", "vmware", "vbox", "virtualbox", "xen", "hyperv", "microsoft", "uml", "parallels", "bhyve", "powervm", "apple-vm":
		return KindVM
	case "wsl":
		return KindWSL
	case "":
		return KindBareMetal
	}
	return KindUnknown
}

type signal struct {
	signal string
	vendor string
	kind   Kind
}

func collectEvidence() []signal {
	var out []signal

	// Filesystem markers — cheap reads, ignore errors (file absent == signal
	// didn't fire).
	if _, err := os.Stat("/.dockerenv"); err == nil {
		out = append(out, signal{signal: "file:/.dockerenv", vendor: "docker", kind: KindContainer})
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		out = append(out, signal{signal: "file:/run/.containerenv", vendor: "podman", kind: KindContainer})
	}

	// Env vars. KUBERNETES_SERVICE_HOST is set inside every pod that has a
	// service account, regardless of which runtime is underneath.
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		out = append(out, signal{signal: "env:KUBERNETES_SERVICE_HOST", vendor: "kubernetes", kind: KindContainer})
	}
	// systemd sets `container=...` for nspawn, podman, docker, lxc, etc.
	if v := os.Getenv("container"); v != "" {
		out = append(out, signal{signal: "env:container=" + v, vendor: v, kind: KindContainer})
	}
	if os.Getenv("WSL_DISTRO_NAME") != "" || os.Getenv("WSL_INTEROP") != "" {
		out = append(out, signal{signal: "env:WSL_DISTRO_NAME", vendor: "wsl", kind: KindWSL})
	}

	// Linux-specific file reads. Implemented in runtimeenv_linux.go and
	// stubbed out elsewhere.
	out = append(out, collectLinuxSignals()...)

	return out
}
