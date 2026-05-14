package ospkg

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"
)

// enumerateApk runs `apk info -v` and parses the line-oriented output.
//
// `apk info -v` prints one package per line as:
//
//   <name>-<version>-r<rel>
//
// where the version can contain dots and the release is the apk-specific
// rebuild counter prefixed with -r. We split on the last "-r" boundary
// to separate name+version from the release; then split name and
// version on the LAST "-" since apk allows hyphens in package names
// (e.g., "libcrypto1.1-3.0.7-r1").
//
// Edge cases:
//   - Some packages have no -r release suffix (rare; we handle by
//     leaving the whole tail as the version).
//   - apk version comparison is dpkg-style; OSV ingests this directly.
func enumerateApk(ctx context.Context, runner CommandRunner) ([]Package, error) {
	out, err := runner.Run(ctx, "apk", "info", "-v")
	if err != nil {
		return nil, fmt.Errorf("apk info -v: %w", err)
	}
	return parseApkInfo(out), nil
}

func parseApkInfo(raw []byte) []Package {
	var pkgs []Package
	scan := bufio.NewScanner(bytes.NewReader(raw))
	scan.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" {
			continue
		}
		name, version := splitApkLine(line)
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, Package{Manager: ManagerApk, Name: name, Version: version})
	}
	return pkgs
}

// splitApkLine parses one "<name>-<version>-r<rel>" line. We anchor
// on the LAST "-r" (followed by digits) — that's the release marker.
// Everything before it is "<name>-<version>"; we then find the LAST
// "-" before the release to split name from version.
//
// Falls back to splitting on the last "-" if no -r release is
// present (Alpine virtual packages or hand-installed builds).
func splitApkLine(line string) (name, version string) {
	// Find last "-r<digits>" — that's the release marker.
	relStart := -1
	for i := len(line) - 1; i >= 1; i-- {
		if line[i-1] == '-' && line[i] == 'r' && i+1 < len(line) && isDigit(line[i+1]) {
			relStart = i - 1
			break
		}
	}
	body := line
	relSuffix := ""
	if relStart > 0 {
		body = line[:relStart]
		relSuffix = line[relStart:]
	}
	// Split name from version on the LAST "-" in body. Apk names can
	// contain hyphens; versions cannot start with a letter.
	splitAt := -1
	for i := len(body) - 1; i >= 1; i-- {
		if body[i-1] == '-' && isDigit(body[i]) {
			splitAt = i - 1
			break
		}
	}
	if splitAt < 0 {
		return "", ""
	}
	name = body[:splitAt]
	version = body[splitAt+1:] + relSuffix
	return name, version
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
