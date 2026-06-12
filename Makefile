BINARY  := notenv
PKG     := ./cmd/notenv
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build install test vet fmt lint snapshot clean

## build: compile the binary into ./notenv
build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

## install: install the binary into $(go env GOPATH)/bin
install:
	go install -ldflags "$(LDFLAGS)" $(PKG)

## test: run the test suite (race detector on)
test:
	go test -race ./...

## vet: run go vet
vet:
	go vet ./...

## fmt: format all sources
fmt:
	gofmt -w .

## lint: check formatting, vet, cyclomatic complexity, and ineffectual assignments (no changes)
lint:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then echo "needs gofmt:"; echo "$$unformatted"; exit 1; fi
	go vet ./...
	go tool gocyclo -over 15 .
	go tool ineffassign ./...

## snapshot: build a local release into ./dist without publishing (needs goreleaser)
snapshot:
	goreleaser release --snapshot --clean

## clean: remove build artifacts
clean:
	rm -rf dist $(BINARY)
