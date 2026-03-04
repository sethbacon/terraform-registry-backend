SWAG=swag

.PHONY: swag backend-test test-compose-up test-compose-down

swag:
	@echo "Generating Swagger JSON..."
	cd backend && $(SWAG) init -g cmd/server/main.go --outputTypes json

backend-test:
	@echo "Running Go unit tests..."
	cd backend && go test ./... -v

test-compose-up:
	@echo "Starting test compose..."
	docker compose -f deployments/docker-compose.test.yml up -d --build

test-compose-down:
	@echo "Stopping test compose..."
	docker compose -f deployments/docker-compose.test.yml down --volumes
