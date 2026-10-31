BIN ?= bin/ksbx
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null)

.PHONY: build dev-bundle test check fmt lint vuln clean

build:
	go build -ldflags "-X github.com/KLORQ/sandboxes-cli/internal/version.Commit=$(COMMIT)" -o $(BIN) ./cmd/ksbx

# Local workspace bundle; releases must use tagged module dependencies.
dev-bundle:
	go build -ldflags "-X github.com/KLORQ/sandboxes-cli/internal/version.Commit=$(COMMIT)" -o dist/ksbx ./cmd/ksbx
	cd ../sandboxes-daemon && go build -o ../sandboxes-cli/dist/sandboxesd ./cmd/sandboxesd

test:
	go test -race -count=1 ./...

check:
	test -z "$$(gofmt -l .)"
	go vet ./...

fmt:
	gofmt -w .

lint:
	golangci-lint config verify
	golangci-lint run ./...

vuln:
	govulncheck ./...

clean:
	rm -rf bin
