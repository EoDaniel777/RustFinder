# Multi-stage build for RustFinder
FROM rust:1.75-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false rustfinder

# Copy binary from builder stage
COPY --from=builder /app/target/release/rustfinder /usr/local/bin/rustfinder

# Set permissions
RUN chmod +x /usr/local/bin/rustfinder

# Create config directory
RUN mkdir -p /home/rustfinder/.config/rustfinder && \
    chown -R rustfinder:rustfinder /home/rustfinder

# Switch to non-root user
USER rustfinder
WORKDIR /home/rustfinder

# Set environment variables
ENV RUST_LOG=info
ENV RUSTFINDER_CONFIG_DIR=/home/rustfinder/.config/rustfinder

# Default command
ENTRYPOINT ["rustfinder"]
CMD ["--help"]

# Labels
LABEL maintainer="Daniel Alisom"
LABEL description="Fast passive subdomain enumeration tool"
LABEL version="1.0.0"