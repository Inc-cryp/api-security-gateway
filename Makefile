GO      ?= go
BIN     ?= bin/gatewayd
PKG     ?= ./...
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build run test test-cover e2e vet fmt fmt-check deps-check tidy clean help

all: fmt-check vet test build

## build: compile the gateway into $(BIN)
build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/gatewayd

## run: start the gateway with config.yaml
run: build
	$(BIN) -config config.yaml

## test: run the test suite with the race detector
test:
	$(GO) test -race -count=1 $(PKG)

## test-cover: run the tests and print a coverage summary
test-cover:
	$(GO) test -race -count=1 -coverprofile=coverage.out $(PKG)
	$(GO) tool cover -func=coverage.out | tail -1

## e2e: run the end-to-end smoke test against the built binary
e2e: build
	@command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }
	python3 test/e2e/gateway_e2e.py

## vet: run go vet
vet:
	$(GO) vet $(PKG)

## fmt: format every Go file
fmt:
	$(GO) fmt $(PKG)

## fmt-check: fail if any file is not gofmt-clean
fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then \
		echo "these files need gofmt:"; \
		echo "$$out"; \
		exit 1; \
	fi

## deps-check: fail if the module grew a dependency (it must stay stdlib-only)
deps-check:
	@if [ -f go.sum ]; then \
		echo "go.sum exists: this module is meant to have no dependencies"; \
		exit 1; \
	fi
	@if grep -qE '^[[:space:]]*require[[:space:]]' go.mod; then \
		echo "go.mod declares a requirement: this module is meant to have no dependencies"; \
		grep -nE '^[[:space:]]*require[[:space:]]' go.mod; \
		exit 1; \
	fi
	@echo "no external dependencies"

## tidy: keep go.mod accurate
tidy:
	$(GO) mod tidy

## clean: remove build output
clean:
	rm -rf bin coverage.out

## help: list the available targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
