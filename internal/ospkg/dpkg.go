package ospkg

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"
)

// enumerateDpkg runs `dpkg-query -W -f='${Package}\t${Version}\n'`
// and parses the tab-separated output.
//
// Format spec from dpkg-query(1):
//   ${Package}\t${Version}\n
//
// Real output:
//   adduser\t3.137ubuntu1
//   apt\t2.7.10
//   ...
//
// Edge cases handled:
//   - Packages with epoch versions: "1:2.7.10" → kept as-is (OSV
//     understands deb epochs in the version field).
//   - Packages with multi-arch tags: dpkg-query without :all/:amd64
//     prints the bare name unless the user explicitly asks; we don't
//     pass the arch qualifier, so names stay short.
//   - Partial-state rows: dpkg sometimes lists packages in
//     deinstall-but-not-purged state with an empty Version; we skip
//     them (a deinstalled package has no installed code to scan).
func enumerateDpkg(ctx context.Context, runner CommandRunner) ([]Package, error) {
	out, err := runner.Run(ctx, "dpkg-query", "-W", "-f=${Package}\t${Version}\n")
	if err != nil {
		return nil, fmt.Errorf("dpkg-query: %w", err)
	}
	return parseDpkgQuery(out), nil
}

func parseDpkgQuery(raw []byte) []Package {
	var pkgs []Package
	scan := bufio.NewScanner(bytes.NewReader(raw))
	// dpkg lists are large (~2k pkgs on a default desktop install);
	// bump the buffer so any single line doesn't trip the scanner.
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
		pkgs = append(pkgs, Package{Manager: ManagerDpkg, Name: name, Version: version})
	}
	return pkgs
}
