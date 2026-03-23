#!/bin/bash
set -e

IMAGE_NAME="netid-runner"

# Build if needed (only once)
if ! docker image inspect ${IMAGE_NAME} > /dev/null 2>&1; then
    echo "Building Docker image (once)..."
    docker build -t ${IMAGE_NAME} .
fi

# Run with all arguments passed through
docker run --rm ${IMAGE_NAME} "$@"
