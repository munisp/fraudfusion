#!/usr/bin/env bash
# Installs Rust stable via rustup (minimal profile). Usage: ./install-rust.sh
set -euo pipefail
curl -fsSL --retry 5 --max-time 300 https://sh.rustup.rs -o /tmp/rustup.sh
sh /tmp/rustup.sh -y --default-toolchain stable --profile minimal
export PATH="$HOME/.cargo/bin:$PATH"
rustc --version && cargo --version
