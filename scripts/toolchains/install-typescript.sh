#!/usr/bin/env bash
# Installs the TypeScript compiler globally via npm. Usage: ./install-typescript.sh [version]
set -euo pipefail
VERSION="${1:-5.5}"
npm install -g "typescript@${VERSION}"
tsc --version
