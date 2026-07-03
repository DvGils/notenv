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
# -tags fastkdf lowers the scrypt work factor so the suite is not dominated by
# 2^19 KDF cost; production keeps 2^19 (guarded by TestProductionScryptWorkFactor,
# which builds only without the tag). CI runs that guard in a separate untagged step.
test:
	go test -tags fastkdf -race ./...

## vet: run go vet
vet:
	go vet ./...

## fmt: format all sources
fmt:
	gofmt -w .

## lint: run golangci-lint (gofmt, vet, gocyclo, ineffassign, gosec and more; see .golangci.yml)
lint:
	golangci-lint run

## snapshot: build a local release into ./dist without publishing (needs goreleaser)
snapshot:
	goreleaser release --snapshot --clean

## clean: remove build artifacts
clean:
	rm -rf dist $(BINARY)
