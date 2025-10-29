# Multi-stage build for Go network exporter
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY *.go ./

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' -o network-exporter .

# Final stage - minimal runtime image
FROM alpine:3.18

# Install runtime dependencies and security updates
RUN apk add --no-cache \
    iputils \
    mtr \
    ca-certificates \
    tzdata \
    wget \
    && rm -rf /var/cache/apk/*

# Create app directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/network-exporter .

# Copy configuration files if they exist
COPY web_config.yml* ./

# Make binary executable and set capabilities for ICMP
RUN chmod +x ./network-exporter && \
    setcap cap_net_raw+ep ./network-exporter

# Create non-root user AFTER setting capabilities
RUN addgroup -g 1001 -S netexporter && \
    adduser -u 1001 -S netexporter -G netexporter

# Create config directory
RUN mkdir -p /etc/network_exporter && \
    chown -R netexporter:netexporter /app /etc/network_exporter

# Expose port
EXPOSE 9115

# Set environment variables
ENV PORT=9115
ENV DEBUG=false

# Health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9115/health || exit 1

# Switch to non-root user
USER netexporter

# Run the binary
CMD ["./network-exporter"]