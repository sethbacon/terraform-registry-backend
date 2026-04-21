SWAG=swag
VERSION ?= dev
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: swag backend-test test-compose-up test-compose-down build build-fips docker-fips

swag:
	@echo "Generating Swagger JSON..."
	cd backend && $(SWAG) init -g cmd/server/main.go --outputTypes json

backend-test:
	@echo "Running Go unit tests..."
	cd backend && go test ./... -v

build:
	@echo "Building backend (standard crypto)..."
	cd backend && CGO_ENABLED=0 go build \
		-ldflags="-w -s -X main.Version=$(VERSION) -X main.BuildDate=$(BUILD_DATE)" \
		-o terraform-registry ./cmd/server

build-fips:
	@echo "Building backend (FIPS / BoringCrypto)..."
	cd backend && CGO_ENABLED=0 GOEXPERIMENT=boringcrypto go build \
		-ldflags="-w -s -X main.Version=$(VERSION) -X main.BuildDate=$(BUILD_DATE) -X main.CryptoMode=fips" \
		-o terraform-registry-fips ./cmd/server

docker-fips:
	@echo "Building FIPS Docker image..."
	docker build -f backend/Dockerfile.fips -t terraform-registry-backend:fips backend/

airgap-bundle:
	@echo "Building air-gap bundle..."
	./scripts/airgap-bundle.sh --output ./airgap-bundle

test-compose-up:
	@echo "Starting test compose..."
	docker compose -f deployments/docker-compose.test.yml up -d --build

test-compose-down:
	@echo "Stopping test compose..."
	docker compose -f deployments/docker-compose.test.yml down --volumes
