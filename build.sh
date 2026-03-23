#!/bin/bash
set -e

PROJECT_NAME="netid"

echo "=== Building ${PROJECT_NAME} ==="

mkdir -p bin

# Build for macOS ARM64 using cross
echo "Building for aarch64-apple-darwin..."
docker run --rm \
    -v "$(pwd)":/build \
    -w /build \
    rustembedded/cross:aarch64-apple-darwin \
    cargo build --release --target aarch64-apple-darwin

cp target/aarch64-apple-darwin/release/${PROJECT_NAME} bin/${PROJECT_NAME}
chmod +x bin/${PROJECT_NAME}

echo ""
echo "=== Build complete ==="
ls -la bin/
