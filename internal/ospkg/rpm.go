package ospkg

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"
)

// enumerateRpm runs:
//
//   rpm -qa --qf '%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\n'
//
// and parses the tab-separated output. The query format encodes the
// epoch:version-release tuple that RPM uses for ordering — OSV reads
// this back via the deb-style version comparator and matches against
// the advisory database.
//
// Edge cases handled:
//   - Packages with no epoch: rpm prints "(none):version-release";
//     we strip "(none):" so the version starts at the numeric part.
//   - Packages with no Release: shouldn't happen on a healthy rpmdb;
//     if it does, we keep the bare Version.
//   - Corrupt rpmdb: rpm -qa may hang indefinitely (well-known
//     issue). The orchestrator wraps EnumerateAndScan with a
//     context deadline; if rpm exceeds it, ctx cancels the
//     subprocess.
func enumerateRpm(ctx context.Context, runner CommandRunner) ([]Package, error) {
	out, err := runner.Run(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\n")
	if err != nil {
		return nil, fmt.Errorf("rpm -qa: %w", err)
	}
	return parseRpmQuery(out), nil
}

func parseRpmQuery(raw []byte) []Package {
	var pkgs []Package
	scan := bufio.NewScanner(bytes.NewReader(raw))
	scan.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scan.Scan() {
		line := scan.Text()
		i := strings.IndexByte(line, '\t')
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		version := strings.TrimSpace(line[i+1:])
		if name == "" || version == "" {
			continue
		}
		// "(none):version-release" → "version-release"
		if strings.HasPrefix(version, "(none):") {
			version = strings.TrimPrefix(version, "(none):")
		}
		// "0:version-release" is the same as no-epoch as far as OSV
		// is concerned; leaving it as "0:" is also valid PURL form,
		// so we don't strip it. RPM upstreams generally don't query
		// for it that way anyway.
		pkgs = append(pkgs, Package{Manager: ManagerRpm, Name: name, Version: version})
	}
	return pkgs
}
