# Multi-stage Dockerfile for Terraform Registry Backend

# Stage 1: Build the Go application
FROM golang:alpine@sha256:f85330846cde1e57ca9ec309382da3b8e6ae3ab943d2739500e08c86393a21b1 AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata
RUN update-ca-certificates || true

# Use default Go module proxy and sum DB (remove dev workarounds)
# ENV GOPROXY=proxy.golang.org
# ENV GOSUMDB=sum.golang.org

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
ARG VERSION=dev
ARG BUILD_DATE=unknown
ARG TARGETARCH=amd64
RUN CLEAN_VERSION="${VERSION#v}" && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-w -s -X main.Version=${CLEAN_VERSION} -X main.BuildDate=${BUILD_DATE}" \
    -o terraform-registry \
    ./cmd/server

# Stage 2: Create minimal production image
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 registry && \
    adduser -D -u 1000 -G registry registry

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/terraform-registry /app/terraform-registry

# Copy example config
COPY config.example.yaml /app/config.example.yaml

# Copy Swagger documentation from builder
COPY --from=builder /build/docs /app/docs

# Create directories
RUN mkdir -p /app/storage /app/scanners && \
    chown -R registry:registry /app

# Switch to non-root user
USER registry

# Expose ports
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Set entrypoint
ENTRYPOINT ["/app/terraform-registry"]

# Default command
CMD ["serve"]

