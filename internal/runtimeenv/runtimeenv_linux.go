//go:build linux

package runtimeenv

import (
	"os"
	"strings"
)

func collectLinuxSignals() []signal {
	var out []signal

	// /proc/1/cgroup — init's cgroup path leaks the container runtime on
	// cgroup v1 systems. Docker uses /docker/<id>, k8s uses /kubepods/...,
	// LXC uses /lxc/, etc. cgroup v2 collapses to a single hierarchy with
	// less specific names but still surfaces /.slice paths that hint at the
	// runtime.
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		text := string(data)
		switch {
		case strings.Contains(text, "/docker/"):
			out = append(out, signal{signal: "cgroup:/docker/", vendor: "docker", kind: KindContainer})
		case strings.Contains(text, "/kubepods"):
			out = append(out, signal{signal: "cgroup:/kubepods", vendor: "kubernetes", kind: KindContainer})
		case strings.Contains(text, "/lxc/"):
			out = append(out, signal{signal: "cgroup:/lxc/", vendor: "lxc", kind: KindContainer})
		case strings.Contains(text, "containerd"):
			out = append(out, signal{signal: "cgroup:containerd", vendor: "containerd", kind: KindContainer})
		case strings.Contains(text, "/system.slice/docker-"):
			out = append(out, signal{signal: "cgroup:/system.slice/docker-", vendor: "docker", kind: KindContainer})
		}
	}

	// /proc/cpuinfo — the `hypervisor` flag on x86 is the canonical "we are
	// in a VM" signal. ARM hosts surface this differently and we leave that
	// to gopsutil.
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		text := string(data)
		// flags line on x86 surfaces "hypervisor" when running under any
		// hypervisor that exposes the CPUID bit (KVM, VMware, Hyper-V, Xen).
		if strings.Contains(text, " hypervisor") || strings.Contains(text, "\thypervisor") {
			out = append(out, signal{signal: "cpuinfo:hypervisor", vendor: "", kind: KindVM})
		}
	}

	// /proc/sys/kernel/osrelease contains "microsoft" on WSL1 and WSL2.
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		lower := strings.ToLower(string(data))
		if strings.Contains(lower, "microsoft") || strings.Contains(lower, "wsl") {
			out = append(out, signal{signal: "osrelease:microsoft/wsl", vendor: "wsl", kind: KindWSL})
		}
	}

	return out
}
