SWAG=swag
VERSION ?= dev
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: swag openapi3 backend-test test-compose-up test-compose-down build build-fips docker-fips

swag:
	@echo "Generating Swagger JSON..."
	cd backend && $(SWAG) init -g cmd/server/main.go --outputTypes json
	@$(MAKE) openapi3

# openapi3 converts the swag-generated Swagger 2.0 spec to OpenAPI 3.0.
#
# This must stay byte-identical to CI's "Swagger generation" step, because the
# swagger-docs-sync job regenerates the spec and commits ITS output to the PR
# branch -- so any transformation here that CI does not also perform is
# reverted, and a contributor who follows the documented workflow gets a large
# diff that CI then throws away. That is what #947 was: they disagreed for
# months and the artifact CI produced always won.
#
# NO PATH-PARAMETER HOISTING (#947). This target used to promote
# operation-level path parameters to path level, on the stated grounds that
# "OpenAPI 3 tools such as oapi-codegen require them at path level" and that
# the downstream consumers needed it. Neither consumer did:
#
#   - terraform-provider-registry generates MODELS ONLY
#     (internal/client/spec/oapi-codegen.yaml sets `client: false`), and
#     oapi-codegen reads path parameters only when generating a client or a
#     server. Its committed spec snapshot has 76 templated paths and ZERO
#     path-level parameters, and its codegen has always worked.
#   - terraform-registry-frontend has no typegen from openapi3.json at all.
#     Its one spec consumer, frontend/scripts/contract-check.ts, reads
#     swagger.json (OpenAPI 2) and parses the path templates itself.
#
# So the published spec never met a requirement that nothing had. The hoisting
# was removed rather than adopted into CI because adding it would mean a large
# one-time diff to satisfy no consumer.
#
# IF YOU ARE ADDING A CONSUMER THAT GENERATES A CLIENT OR SERVER from this
# spec, it WILL need path-level parameters -- restore the hoisting here and add
# it to CI's step in the same change, or the two will diverge again.
# swagger_ci_parity_test.go fails if only one of them grows a post-process.
openapi3:
	@echo "Converting Swagger 2.0 -> OpenAPI 3.0..."
	@test -x node_modules/.bin/swagger2openapi || (echo "swagger2openapi not installed — run 'npm install' first" && exit 1)
	@node_modules/.bin/swagger2openapi backend/docs/swagger.json -o backend/docs/openapi3.json -p

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
