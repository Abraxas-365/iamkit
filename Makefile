.PHONY: build build-cli test test-unit test-sdk vet fmt test-e2e test-integration test-all test-languages test-browser openapi api-client

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

# api/openapi.json from the routes and handlers (TestSpecIsCurrent keeps it
# current; the e2e suite validates every exchange against it), then the
# TypeScript client's types.
openapi:
	go run ./cmd/openapi
	cd clients/typescript && npm run generate

api-client:
	cd clients/typescript && npm ci && npm run generate && npm test && npm run build
	cd clients/js && npm ci && npm run typecheck && npm test && npm run build
	cd clients/react && npm ci && npm run typecheck && npm test && npm run build

test-e2e:
	IAMKIT_TEST_E2E=1 go test -count=1 -timeout=10m -v ./tests/e2e

# HTTP journeys and schema constraints run together in disposable testcontainers.
test-integration: test-e2e

test-all: test test-e2e test-browser

# The console, hosted pages and org-admin portal in headless Chromium against
# IAMKit built from this checkout, on PostgreSQL + Mailpit testcontainers.
test-browser:
	cd tests/browser && npm ci && npx playwright install chromium && GOWORK=off npx playwright test

# Hosted pages in every language at 320 px (needs Docker and Playwright:
# NODE_PATH pointing at a node_modules with playwright + chromium).
LANG_DIR ?= /tmp/iamkit-languages
test-languages:
	rm -rf $(LANG_DIR) && mkdir -p $(LANG_DIR)/shots
	IAMKIT_TEST_E2E=1 IAMKIT_LANGUAGE_SNAPSHOTS=$(LANG_DIR) go test -count=1 -run TestHostedEveryLanguage ./tests/e2e
	node scripts/check_hosted_languages.js $(LANG_DIR) $(LANG_DIR)/shots
