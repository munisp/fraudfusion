#!/usr/bin/env bash
# Installs Go toolchain (no root required). Usage: ./install-go.sh [version] [prefix]
set -euo pipefail
VERSION="${1:-1.22.12}"
PREFIX="${2:-$HOME/.local/go-toolchain}"
ARCH="$(uname -m)"; case "$ARCH" in x86_64) ARCH=amd64;; aarch64) ARCH=arm64;; esac
URLS=("https://go.dev/dl/go${VERSION}.linux-${ARCH}.tar.gz"
      "https://dl.google.com/go/go${VERSION}.linux-${ARCH}.tar.gz"
      "https://golang.google.cn/dl/go${VERSION}.linux-${ARCH}.tar.gz")
TMP="$(mktemp -d)"; cd "$TMP"
for u in "${URLS[@]}"; do curl -fsSL --retry 3 --max-time 300 -o go.tgz "$u" && break; done
mkdir -p "$PREFIX" && tar -C "$PREFIX" -xzf go.tgz
echo "export PATH=$PREFIX/go/bin:\$PATH  # add to your shell profile"
"$PREFIX/go/bin/go" version
