# Multi-stage Dockerfile for Terraform Registry Backend

# Stage 1: Build the Go application
FROM golang:alpine AS builder

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

# Tidy dependencies
RUN go mod tidy

# Install swag CLI and generate Swagger documentation (JSON only; embedded at build time)
RUN go install github.com/swaggo/swag/cmd/swag@latest && \
    swag init -g cmd/server/main.go --outputTypes json

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o terraform-registry \
    ./cmd/server

# Stage 2: Create minimal production image
FROM alpine:3.19

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
RUN mkdir -p /app/storage && \
    chown -R registry:registry /app

# Switch to non-root user
USER registry

# Expose ports
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider --no-check-certificate https://localhost:8080/health || exit 1

# Set entrypoint
ENTRYPOINT ["/app/terraform-registry"]

# Default command
CMD ["serve"]

