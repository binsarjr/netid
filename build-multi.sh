#!/bin/bash
set -e

PROJECT_NAME="netid"

echo "=== Building ${PROJECT_NAME} for all platforms ==="

mkdir -p bin

# Use cross to build for multiple targets
TARGETS=(
    "x86_64-unknown-linux-gnu"
    "aarch64-unknown-linux-gnu"
    "x86_64-unknown-linux-musl"
    "aarch64-unknown-linux-musl"
)

for TARGET in "${TARGETS[@]}"; do
    echo "Building for ${TARGET}..."

    case "$TARGET" in
        x86_64-unknown-linux-gnu)
            OUTPUT="${PROJECT_NAME}-linux-amd64"
            ;;
        aarch64-unknown-linux-gnu)
            OUTPUT="${PROJECT_NAME}-linux-arm64"
            ;;
        x86_64-unknown-linux-musl)
            OUTPUT="${PROJECT_NAME}-linux-musl-amd64"
            ;;
        aarch64-unknown-linux-musl)
            OUTPUT="${PROJECT_NAME}-linux-musl-arm64"
            ;;
    esac

    docker run --rm -v "$(pwd)":/build -w /build \
        rust:latest \
        sh -c "cargo install cross && cross build --release --target ${TARGET}"

    cp "target/${TARGET}/release/${PROJECT_NAME}" "bin/${OUTPUT}"
    chmod +x "bin/${OUTPUT}"
    echo "  -> bin/${OUTPUT}"
done

echo ""
echo "=== Build complete ==="
ls -la bin/
