# Local parity for CI: `make ci` runs the lint, test, and race commands.
# CI pins golangci-lint v2.12.2 (same binary Eshu uses); install it once:
#   go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
GO ?= go
GOLANGCI_LINT ?= golangci-lint
COVERAGE_FLOOR ?= 66.1

.PHONY: ci lint vet test race build fmt tidy cap cover clean

ci: lint test race

lint: vet
	$(GOLANGCI_LINT) run ./...
	$(GOLANGCI_LINT) fmt --diff ./...
	$(GO) mod tidy -diff
	git diff --exit-code -- go.mod go.sum
	over=$$(find . -name '*.go' -not -path './vendor/*' -exec wc -l {} + | awk '$$1 > 500 && $$2 != "total" {print}'); \
	if [ -n "$$over" ]; then echo "$$over"; echo "FAIL: .go files over 500 lines"; exit 1; fi
	git diff --check

vet:
	$(GO) vet ./...

build:
	$(GO) build ./...

test: build
	$(GO) test ./... -count=1

race:
	$(GO) test ./... -race -count=1 -covermode=atomic -coverprofile=coverage.out
	$(GO) tool cover -func=coverage.out | tail -n 30
	total=$$($(GO) tool cover -func=coverage.out | awk '/^total:/ {gsub(/%/, "", $$3); print $$3}'); \
	echo "total=$$total floor=$(COVERAGE_FLOOR)"; \
	awk -v t="$$total" -v f="$(COVERAGE_FLOOR)" 'BEGIN { if (t + 0 < f + 0) { print "FAIL: coverage below floor"; exit 1 } }'

cover:
	$(GO) tool cover -html=coverage.out

fmt:
	$(GOLANGCI_LINT) fmt ./...

tidy:
	$(GO) mod tidy

cap:
	over=$$(find . -name '*.go' -not -path './vendor/*' -exec wc -l {} + | awk '$$1 > 500 && $$2 != "total" {print}'); \
	if [ -n "$$over" ]; then echo "$$over"; echo "FAIL: .go files over 500 lines"; exit 1; fi

clean:
	rm -f coverage.out gosec.sarif
