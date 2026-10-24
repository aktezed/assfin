BINARY_NAME=assfin
GO=go
GOFLAGS=-v

.PHONY: all build clean test lint fmt install help

all: clean fmt test build

## build: Build the assfin binary
build:
	@echo "Building $(BINARY_NAME)..."
	$(GO) build $(GOFLAGS) -o bin/$(BINARY_NAME) ./cmd/assfin

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf bin/ $(BINARY_NAME) coverage.out coverage.html .assfin-config.yaml

## test: Run all tests
test:
	@echo "Running tests..."
	$(GO) test -v ./...

## fmt: Format and vet code
fmt:
	$(GO) fmt ./...
	$(GO) vet ./...

## install: Install binary to $GOPATH/bin
install:
	$(GO) install ./cmd/assfin

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
