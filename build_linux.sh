#!/usr/bin/env bash
# ==============================================================================
# Elise - Linux Multi-Architecture Build Script for Linux / macOS
# Targets: Linux amd64 (x86_64-unknown-linux-musl) and arm64 (aarch64-unknown-linux-musl)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${SCRIPT_DIR}/dist"
mkdir -p "${DIST_DIR}"

echo "=== Elise Linux Multi-Architecture Builder ==="

rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

if ! command -v cross &> /dev/null; then
    echo "Installing cross..."
    cargo install cross --git https://github.com/cross-rs/cross
fi

echo ">>> Building Elise for Linux amd64..."
cross build --release --target x86_64-unknown-linux-musl
cp "${SCRIPT_DIR}/target/x86_64-unknown-linux-musl/release/elise" "${DIST_DIR}/elise-linux-amd64"
chmod +x "${DIST_DIR}/elise-linux-amd64"

echo ">>> Building Elise for Linux arm64..."
cross build --release --target aarch64-unknown-linux-musl
cp "${SCRIPT_DIR}/target/aarch64-unknown-linux-musl/release/elise" "${DIST_DIR}/elise-linux-arm64"
chmod +x "${DIST_DIR}/elise-linux-arm64"

echo "=== Build Complete! Binaries generated in ${DIST_DIR} ==="
ls -lh "${DIST_DIR}"
