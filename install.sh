#!/bin/sh
# install.sh — download and install the IAM CLI from GitHub Releases.
#
# Usage:
#   curl --proto '=https' --tlsv1.2 -sSfL \
#     https://raw.githubusercontent.com/Abraxas-365/iamkit/main/install.sh | sh
#
# Options (env vars):
#   INSTALL_DIR   — where to put the binary (default: /usr/local/bin)
#   VERSION       — tag to install (default: latest)

set -eu

REPO="Abraxas-365/iamkit"
BINARY="iam"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# --- detect OS & arch ---------------------------------------------------------
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64)  ARCH="amd64" ;;
  aarch64|arm64)  ARCH="arm64" ;;
  *)  echo "Error: unsupported architecture $ARCH" >&2; exit 1 ;;
esac

case "$OS" in
  linux|darwin) ;;
  *)  echo "Error: unsupported OS $OS" >&2; exit 1 ;;
esac

# --- resolve version ----------------------------------------------------------
if [ -z "${VERSION:-}" ]; then
  VERSION="$(curl -sSfL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')"
fi

if [ -z "$VERSION" ]; then
  echo "Error: could not determine latest version. Set VERSION=vX.Y.Z" >&2
  exit 1
fi

# --- download & extract -------------------------------------------------------
TARBALL="iam_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading ${BINARY} ${VERSION} (${OS}/${ARCH})…"
curl --proto '=https' --tlsv1.2 -sSfL "$URL" -o "${TMPDIR}/${TARBALL}"
tar -xzf "${TMPDIR}/${TARBALL}" -C "$TMPDIR"

# --- install ------------------------------------------------------------------
if [ -w "$INSTALL_DIR" ]; then
  mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  echo "Installing to ${INSTALL_DIR} (requires sudo)…"
  sudo mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

chmod +x "${INSTALL_DIR}/${BINARY}"
echo "✓ ${BINARY} ${VERSION} installed to ${INSTALL_DIR}/${BINARY}"
