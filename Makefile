.PHONY: help build test lint run clean release

# Build settings
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo "dev")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_HASH ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GO_VERSION ?= go1.25.5
LDFLAGS := -X 'main.Version=$(VERSION)' -X 'main.BuildDate=$(BUILD_DATE)' -X 'main.BuildHash=$(BUILD_HASH)' -X 'main.GoVersion=$(GO_VERSION)'

# Output directory
BIN_DIR := bin
OUTPUT := $(BIN_DIR)/advanced-sftp-exporter

help:
	@echo "advanced-sftp-exporter build targets:"
	@echo ""
	@echo "  make build          Build binary for current platform"
	@echo "  make build-all      Build binaries for all platforms"
	@echo "  make test           Run unit tests with coverage"
	@echo "  make lint           Run golangci-lint checks"
	@echo "  make clean          Remove build artifacts"
	@echo "  make run            Build and run locally"
	@echo "  make watch          Watch for changes and rebuild"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION=$(VERSION)"
	@echo "  BUILD_DATE=$(BUILD_DATE)"
	@echo "  BUILD_HASH=$(BUILD_HASH)"

build: clean
	@echo "Building $(VERSION) for $$(uname -s)-$$(uname -m)..."
	@mkdir -p $(BIN_DIR)
	@go build -ldflags "$(LDFLAGS)" -o $(OUTPUT) *.go
	@echo "✓ Binary: $(OUTPUT)"

build-all: clean
	@echo "Building $(VERSION) for all platforms..."
	@mkdir -p $(BIN_DIR)
	@bash scripts/build.sh
	@echo "✓ All binaries built to $(BIN_DIR)/"

test:
	@echo "Running tests with coverage..."
	@go test -v -race -coverprofile=coverage.out ./...
	@echo ""
	@go tool cover -func=coverage.out | tail -1

test-verbose:
	@go test -v -race -coverprofile=coverage.out ./... -args -test.v

lint:
	@echo "Running golangci-lint..."
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	@golangci-lint run --config=.golangci.yml ./...

fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@goimports -w *.go
	@goimports -w internal/*/...
	@goimports -w tests/...

run: build
	@echo "Running exporter..."
	@$(OUTPUT) -help | grep -E "web.listen|version|help" || true
	@$(OUTPUT) -version

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BIN_DIR)
	@rm -f coverage.out coverage.html

check: lint test
	@echo "✓ All checks passed"

release: check build-all
	@echo "✓ Release ready in $(BIN_DIR)/"
	@ls -lh $(BIN_DIR)/

watch:
	@which inotifywait > /dev/null || (echo "Installing inotify-tools..." && brew install inotify-tools)
	@while inotifywait -e modify -r . --exclude 'bin|\.git'; do \
		clear; \
		make lint test build; \
	done

cover-html: test
	@go tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report: coverage.html"

version:
	@echo "Version: $(VERSION)"
	@echo "Build Date: $(BUILD_DATE)"
	@echo "Build Hash: $(BUILD_HASH)"
	@echo "Go Version: $(GO_VERSION)"

info:
	@echo "Go version: $$(go version)"
	@echo "Git version: $$(git --version)"
	@echo "Current branch: $$(git rev-parse --abbrev-ref HEAD)"
	@echo "Uncommitted changes: $$(git status --porcelain | wc -l)"
