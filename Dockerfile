FROM rust:latest AS builder

WORKDIR /build

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock* ./

# Create dummy source for dependency compilation
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release && rm -rf src target/release/deps/*.so target/release/.fingerprint

# Copy actual source
COPY src ./src

# Build the actual binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /build/target/release/netid /app/netid

ENTRYPOINT ["/app/netid"]
