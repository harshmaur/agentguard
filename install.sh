#!/usr/bin/env sh
# AgentGuard install script.
#
# Usage:
#   curl -fsSL https://agentguard.dev/install.sh | sh
#   curl -fsSL https://agentguard.dev/install.sh | sh -s -- --version v0.1.0
#
# This script:
#   1. Detects OS + arch.
#   2. Downloads the matching signed release tarball from GitHub Releases.
#   3. Verifies the SHA-256 against the published SHA256SUMS.
#   4. (If cosign is installed) verifies the tarball signature against the
#      sigstore transparency log.
#   5. Extracts the binary to ${INSTALL_DIR:-$HOME/.local/bin}.
#
# Why no cosign required: a fresh machine often won't have cosign. The
# embedded `agentguard verify` tool can do the same check after install.
# See "verify before installing" in README.md for the manual path CISO
# security teams should follow.

set -eu

REPO="harshmaur/agentguard"
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
    echo "agentguard: unsupported OS: $os" >&2
    echo "agentguard: macOS and Linux are supported in v1; Windows is on the v2 roadmap." >&2
    exit 1
    ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *)
    echo "agentguard: unsupported arch: $arch" >&2
    exit 1
    ;;
esac

# --- resolve version ---
if [ "$VERSION" = "latest" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
  if [ -z "$VERSION" ]; then
    echo "agentguard: failed to resolve latest version (rate limited?)" >&2
    exit 1
  fi
fi

artifact="agentguard-${VERSION}-${os}-${arch}.tar.gz"
base="https://github.com/${REPO}/releases/download/${VERSION}"
echo "agentguard: installing ${VERSION} for ${os}/${arch}..."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# --- download artifact + sig + cert + checksums ---
curl -fsSL -o "${tmp}/${artifact}"           "${base}/${artifact}"
curl -fsSL -o "${tmp}/${artifact}.sig"       "${base}/${artifact}.sig"
curl -fsSL -o "${tmp}/${artifact}.crt"       "${base}/${artifact}.crt"
curl -fsSL -o "${tmp}/SHA256SUMS"            "${base}/SHA256SUMS"

# --- checksum verify ---
echo "agentguard: verifying SHA-256..."
expected="$(grep -F " ${artifact}" "${tmp}/SHA256SUMS" | awk '{print $1}')"
if [ -z "$expected" ]; then
  echo "agentguard: artifact ${artifact} not found in SHA256SUMS" >&2
  exit 1
fi
actual="$(shasum -a 256 "${tmp}/${artifact}" | awk '{print $1}')"
if [ "$expected" != "$actual" ]; then
  echo "agentguard: CHECKSUM MISMATCH (expected ${expected}, got ${actual}) — refusing to install" >&2
  exit 1
fi
echo "agentguard: SHA-256 OK"

# --- cosign verify (best effort) ---
if command -v cosign >/dev/null 2>&1; then
  echo "agentguard: verifying cosign signature..."
  if cosign verify-blob \
      --certificate "${tmp}/${artifact}.crt" \
      --signature   "${tmp}/${artifact}.sig" \
      --certificate-identity-regexp 'https://github.com/harshmaur/agentguard/.+' \
      --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
      "${tmp}/${artifact}" 2>/dev/null; then
    echo "agentguard: cosign signature verified"
  else
    echo "agentguard: WARNING — cosign signature did not verify. Inspect manually before trusting this binary." >&2
  fi
else
  echo "agentguard: cosign not found on PATH — skipping signature verify."
  echo "agentguard: After install, run 'agentguard verify <binary>' to verify against the transparency log."
fi

# --- extract + install ---
mkdir -p "$INSTALL_DIR"
tar -xzf "${tmp}/${artifact}" -C "$tmp"
binary="${tmp}/agentguard-${VERSION}-${os}-${arch}"
chmod +x "$binary"
mv "$binary" "${INSTALL_DIR}/agentguard"

echo "agentguard: installed ${VERSION} → ${INSTALL_DIR}/agentguard"
case ":$PATH:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo "agentguard: NOTE — ${INSTALL_DIR} is not on PATH."
    echo "agentguard:        Add it to your shell rc:  export PATH=\"${INSTALL_DIR}:\$PATH\""
    ;;
esac
echo "agentguard: try it now:  agentguard scan ~"
