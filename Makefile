BIN ?= bin/sbx

.PHONY: build test check fmt lint vuln clean

build:
	go build -o $(BIN) ./cmd/sbx

test:
	go test -race -count=1 ./...

check:
	test -z "$$(gofmt -l .)"
	go vet ./...

fmt:
	gofmt -w .

lint:
	golangci-lint run ./...

vuln:
	govulncheck ./...

clean:
	rm -rf bin
