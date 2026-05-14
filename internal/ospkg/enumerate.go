package ospkg

import (
	"context"
	"fmt"
)

// enumerate dispatches to the per-manager enumerator based on the
// detected distro's manager. Returns the installed package list ready
// for SBOM construction.
func enumerate(ctx context.Context, info DistroInfo) ([]Package, error) {
	switch info.Manager {
	case ManagerDpkg:
		return enumerateDpkg(ctx, defaultRunner)
	case ManagerRpm:
		return enumerateRpm(ctx, defaultRunner)
	case ManagerApk:
		return enumerateApk(ctx, defaultRunner)
	default:
		return nil, fmt.Errorf("ospkg: no enumerator for manager %q", info.Manager)
	}
}
