# Multi-stage Dockerfile for Terraform Registry Backend

# Stage 1: Build the Go application
FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder

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
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# Apply the latest Alpine security patches on top of the digest-pinned base (the
# pin freezes the package set, so a rebuild otherwise keeps shipping the base
# layer's OS CVEs), then install runtime dependencies.
RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates tzdata

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
    CMD wget --no-verbose --tries=1 -O /dev/null http://localhost:8080/health || exit 1

# Set entrypoint
ENTRYPOINT ["/app/terraform-registry"]

# Default command
CMD ["serve"]

