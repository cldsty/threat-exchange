# Developer tasks. Run `make help` for the list.
# Windows users without make can run the commands from README.md directly.

GO            ?= go
BINARY        := bin/threat-exchange
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOLANGCI_LINT ?= golangci-lint
FUZZTIME      ?= 30s
TEST_DB_URL   ?= postgres://threats:threats-dev-password@127.0.0.1:5432/threats?sslmode=disable

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: generate
generate: ## Regenerate code from api/openapi.yaml (oapi-codegen)
	$(GO) generate ./...

.PHONY: check-generate
check-generate: generate ## Fail if generated code is out of date
	git diff --exit-code -- internal/api

.PHONY: fmt
fmt: ## Format code
	gofmt -w .

.PHONY: vet
vet: ## Run go vet (including integration-tagged files)
	$(GO) vet ./...
	$(GO) vet -tags integration ./...

.PHONY: lint
lint: ## Run golangci-lint (see .golangci.yml)
	$(GOLANGCI_LINT) run ./...

.PHONY: test
test: ## Run unit tests with the race detector
	$(GO) test -race -count=1 ./...

.PHONY: test-integration
test-integration: ## Run unit + integration tests (needs PostgreSQL, see db-up)
	TEST_DB_URL="$(TEST_DB_URL)" $(GO) test -race -count=1 -tags integration ./...

.PHONY: cover
cover: ## Integration test coverage report (coverage.html)
	TEST_DB_URL="$(TEST_DB_URL)" $(GO) test -count=1 -tags integration -coverpkg=./internal/... -coverprofile=coverage.out ./...
	grep -v 'api.gen.go' coverage.out > coverage.nogen.out
	$(GO) tool cover -func=coverage.nogen.out | tail -1
	$(GO) tool cover -html=coverage.nogen.out -o coverage.html

.PHONY: fuzz
fuzz: ## Fuzz the parsers of untrusted input (FUZZTIME=30s per target)
	$(GO) test -run=NONE -fuzz=FuzzParseIfMatch -fuzztime=$(FUZZTIME) ./internal/transport/httpapi
	$(GO) test -run=NONE -fuzz=FuzzClientIP -fuzztime=$(FUZZTIME) ./internal/transport/httpapi
	$(GO) test -run=NONE -fuzz=FuzzNameAndDescription -fuzztime=$(FUZZTIME) ./internal/domain/threat

.PHONY: build
build: ## Build the binary into bin/
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o $(BINARY) ./cmd/threat-exchange

.PHONY: db-up
db-up: ## Start only PostgreSQL and generate its certificates (for integration tests)
	docker compose up -d --wait db

.PHONY: up
up: ## Build and start the whole stack (db, migrations, service)
	VERSION=$(VERSION) docker compose up --build -d --wait

.PHONY: down
down: ## Stop the stack (keeps the database volume)
	docker compose down

.PHONY: logs
logs: ## Follow service logs
	docker compose logs -f threat-exchange

.PHONY: keygen
keygen: ## Generate an API key: make keygen ID=partner-a ROLE=writer
	$(GO) run ./cmd/threat-exchange keygen -id $(ID) -role $(or $(ROLE),reader)

.PHONY: certs
certs: ## Generate development certificates into deploy/certs
	$(GO) run ./cmd/threat-exchange devcerts -dir deploy/certs -hosts localhost,127.0.0.1,::1,threat-exchange

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf bin coverage.out coverage.nogen.out coverage.html
