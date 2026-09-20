.PHONY: build build-cli test test-unit test-sdk vet fmt test-e2e test-integration test-all

build:
	go build -o bin/iamkit ./cmd/iamkit

build-cli:
	go build -o bin/iam ./cmd/iam

test: test-unit test-sdk

test-unit:
	go test ./internal/... ./cmd/...

test-sdk:
	cd sdk && go test ./...

vet:
	go vet ./...
	cd sdk && go vet ./...

fmt:
	gofmt -w cmd internal tests sdk

test-e2e:
	IAMKIT_TEST_E2E=1 go test -count=1 -timeout=10m -v ./tests/e2e

# HTTP journeys and schema constraints run together in disposable testcontainers.
test-integration: test-e2e

test-all: test test-e2e
