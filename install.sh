#!/usr/bin/env sh
# Audr install script.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/harshmaur/audr/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/harshmaur/audr/main/install.sh | sh -s -- --version v0.2.4
#
# Steps:
#   1. Detect OS + arch.
#   2. Download the matching signed release tarball from GitHub Releases.
#   3. Verify the SHA-256 against the published SHA256SUMS.
#   4. (If cosign is installed) verify the tarball signature against the
#      sigstore transparency log.
#   5. Extract the binary to ${INSTALL_DIR:-$HOME/.local/bin}.
#
# After install you can re-verify any downloaded tarball with
# `audr verify <tarball>`, and confirm what is compiled into the
# binary on a given machine with `audr self-audit`.

set -eu

REPO="harshmaur/audr"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${VERSION:-latest}"

# --- arg parsing ---
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --help|-h)
      sed -n '2,18p' "$0"
      exit 0
      ;;
    *) echo "unknown flag: $1" >&2; exit 1 ;;
  esac
done

# --- detect platform ---
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
  darwin) os="darwin" ;;
  linux)  os="linux" ;;
  *)
    echo "audr: unsupported OS: $os" >&2
    echo "audr: macOS and Linux are supported in v1; Windows is on the v2 roadmap." >&2
    exit 1
    ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *)
    echo "audr: unsupported arch: $arch" >&2
    exit 1
    ;;
esac

# --- resolve version ---
if [ "$VERSION" = "latest" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
  if [ -z "$VERSION" ]; then
    echo "audr: failed to resolve latest version (rate limited?)" >&2
    exit 1
  fi
fi

artifact="audr-${VERSION}-${os}-${arch}.tar.gz"
base="https://github.com/${REPO}/releases/download/${VERSION}"
echo "audr: installing ${VERSION} for ${os}/${arch}..."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# --- download artifact + sig + cert + checksums ---
curl -fsSL -o "${tmp}/${artifact}"           "${base}/${artifact}"
curl -fsSL -o "${tmp}/${artifact}.sig"       "${base}/${artifact}.sig"
curl -fsSL -o "${tmp}/${artifact}.crt"       "${base}/${artifact}.crt"
curl -fsSL -o "${tmp}/SHA256SUMS"            "${base}/SHA256SUMS"

# --- checksum verify ---
echo "audr: verifying SHA-256..."
expected="$(grep -F " ${artifact}" "${tmp}/SHA256SUMS" | awk '{print $1}')"
if [ -z "$expected" ]; then
  echo "audr: artifact ${artifact} not found in SHA256SUMS" >&2
  exit 1
fi
actual="$(shasum -a 256 "${tmp}/${artifact}" | awk '{print $1}')"
if [ "$expected" != "$actual" ]; then
  echo "audr: CHECKSUM MISMATCH (expected ${expected}, got ${actual}) — refusing to install" >&2
  exit 1
fi
echo "audr: SHA-256 OK"

# --- cosign verify (best effort) ---
if command -v cosign >/dev/null 2>&1; then
  echo "audr: verifying cosign signature..."
  if cosign verify-blob \
      --certificate "${tmp}/${artifact}.crt" \
      --signature   "${tmp}/${artifact}.sig" \
      --certificate-identity-regexp 'https://github.com/harshmaur/audr/.+' \
      --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
      "${tmp}/${artifact}" 2>/dev/null; then
    echo "audr: cosign signature verified"
  else
    echo "audr: WARNING — cosign signature did not verify. Inspect manually before trusting this binary." >&2
  fi
else
  echo "audr: cosign not found on PATH — skipping signature verify."
  echo "audr: After install, run 'audr verify <binary>' to verify against the transparency log."
fi

# --- extract + install ---
mkdir -p "$INSTALL_DIR"
tar -xzf "${tmp}/${artifact}" -C "$tmp"
binary="${tmp}/audr-${VERSION}-${os}-${arch}"
chmod +x "$binary"
mv "$binary" "${INSTALL_DIR}/audr"

echo "audr: installed ${VERSION} → ${INSTALL_DIR}/audr"
case ":$PATH:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo "audr: NOTE — ${INSTALL_DIR} is not on PATH."
    echo "audr:        Add it to your shell rc:  export PATH=\"${INSTALL_DIR}:\$PATH\""
    ;;
esac
echo "audr: try it now:  audr scan ~"
