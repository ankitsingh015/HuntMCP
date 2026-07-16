.PHONY: all build run test clean dev db-up db-down help

APP_NAME := huntmcp-server
BUILD_DIR := ./bin

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

all: build ## Build the server

build: ## Build the Go binary
	go build -o $(BUILD_DIR)/$(APP_NAME) ./cmd/server

run: ## Run the server locally (requires PostgreSQL)
	DATABASE_URL="postgres://huntmcp:huntmcp@localhost:5432/huntmcp?sslmode=disable" \
	go run ./cmd/server

test: ## Run all tests
	go test ./... -v -count=1

clean: ## Clean build artifacts
	rm -rf $(BUILD_DIR)

dev: ## Start dev environment with Docker Compose
	docker compose up --build -d postgres api embedder

db-up: ## Start PostgreSQL only
	docker compose up -d postgres

db-down: ## Stop PostgreSQL
	docker compose down

migrate: ## Run database migrations
	DATABASE_URL="postgres://huntmcp:huntmcp@localhost:5432/huntmcp?sslmode=disable" \
	go run ./cmd/server &
	sleep 2
	kill %1 2>/dev/null || true

lint: ## Run golangci-lint
	golangci-lint run ./...

vendor: ## Download dependencies
	go mod tidy
	go mod vendor

# Embedder commands
embedder-run: ## Run embedder microservice locally
	cd embedder && python3 server.py

embedder-test: ## Test embedder endpoint
	curl -s -X POST http://localhost:9102/embed \
		-H "Content-Type: application/json" \
		-d '{"texts": ["test embedding"]}' | python3 -m json.tool

# Docker commands
docker-build: ## Build production Docker image
	docker build -t huntmcp-api:latest .

docker-run: ## Run production Docker image
	docker run --rm -p 8080:8080 \
		-e DATABASE_URL="postgres://huntmcp:huntmcp@host.docker.internal:5432/huntmcp?sslmode=disable" \
		huntmcp-api:latest
