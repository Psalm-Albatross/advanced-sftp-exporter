# Multi-stage build for advanced-sftp-exporter
# Stage 1: Builder
FROM golang:1.25.5-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git make

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s" \
    -o advanced-sftp-exporter .

# Stage 2: Runtime (minimal image)
FROM alpine:3.20

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user for security
RUN addgroup -g 1000 exporter && \
    adduser -D -u 1000 -G exporter exporter

# Copy binary from builder
COPY --from=builder /app/advanced-sftp-exporter /usr/local/bin/

# Create necessary directories
RUN mkdir -p /var/log && \
    mkdir -p /etc/advanced-sftp-exporter && \
    mkdir -p /data && \
    chown -R exporter:exporter /data /etc/advanced-sftp-exporter

# Set user
USER exporter

# Expose metrics port
EXPOSE 1210

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:1210/health || exit 1

# Default entrypoint
ENTRYPOINT ["/usr/local/bin/advanced-sftp-exporter"]

# Default parameters (override with environment variables or command-line args)
CMD ["-web.listen-address=:1210", \
     "-auth-log=/var/log/auth.log", \
     "-home-base=/home"]
