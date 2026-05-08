SWAG=swag
VERSION ?= dev
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: swag openapi3 backend-test test-compose-up test-compose-down build build-fips docker-fips

swag:
	@echo "Generating Swagger JSON..."
	cd backend && $(SWAG) init -g cmd/server/main.go --outputTypes json
	@$(MAKE) openapi3

# openapi3 converts the swag-generated Swagger 2.0 spec to OpenAPI 3.0.
# Downstream consumers (frontend codegen, terraform-provider-registry oapi-codegen)
# require OpenAPI 3 — emitting it from this repo means each consumer doesn't
# have to run its own conversion step.
openapi3:
	@echo "Converting Swagger 2.0 -> OpenAPI 3.0..."
	@npx --yes swagger2openapi backend/docs/swagger.json -o backend/docs/openapi3.json -p

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
