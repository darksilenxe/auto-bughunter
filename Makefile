# Auto BugHunter — top-level make targets.
#
# These wrap the language-specific tooling so that contributors and CI
# get a single, consistent entry point. Most targets are thin shims over
# `go ...` and `npm ...` and respect any environment variables those
# tools accept (e.g. GOFLAGS, NPM_CONFIG_*).

BACKEND_DIR := backend
FRONTEND_DIR := frontend

.PHONY: help
help:
	@echo "Auto BugHunter — make targets"
	@echo ""
	@echo "  make build         Build backend + frontend"
	@echo "  make test          Run unit tests for backend + frontend"
	@echo "  make test-backend  Run backend Go tests with race detector"
	@echo "  make test-frontend Run frontend (vitest) tests"
	@echo "  make integration   Run integration tests (currently the same"
	@echo "                     race-enabled Go test suite — see CONTRIBUTING.md)"
	@echo "  make lint          Run available linters (go vet + golangci-lint if installed)"
	@echo "  make fmt           Format backend Go code"
	@echo "  make tidy          go mod tidy on the backend module"
	@echo "  make clean         Remove built artefacts"

.PHONY: build
build: build-backend build-frontend

.PHONY: build-backend
build-backend:
	cd $(BACKEND_DIR) && go build ./...

.PHONY: build-frontend
build-frontend:
	cd $(FRONTEND_DIR) && npm install --no-audit --no-fund && npm run build

.PHONY: test
test: test-backend test-frontend

.PHONY: test-backend
test-backend:
	cd $(BACKEND_DIR) && go test -race -count=1 ./...

.PHONY: test-frontend
test-frontend:
	cd $(FRONTEND_DIR) && npm install --no-audit --no-fund && npm test --silent

# Integration tests: today the project does not have a separate integration
# suite (most cross-package interactions are covered by the API package
# tests). This target is a stable hook for CI and local workflows so a
# future suite can be added without changing how it is invoked.
.PHONY: integration
integration:
	cd $(BACKEND_DIR) && go test -race -count=1 -tags=integration ./...

.PHONY: lint
lint:
	cd $(BACKEND_DIR) && go vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "Running golangci-lint…"; \
		cd $(BACKEND_DIR) && golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed — skipping (install: https://golangci-lint.run/)."; \
	fi

.PHONY: fmt
fmt:
	cd $(BACKEND_DIR) && gofmt -w .

.PHONY: tidy
tidy:
	cd $(BACKEND_DIR) && go mod tidy

.PHONY: clean
clean:
	cd $(BACKEND_DIR) && go clean ./...
	rm -rf $(FRONTEND_DIR)/dist $(FRONTEND_DIR)/node_modules/.vite
