.PHONY: check fmt vet lint test coverage fuzz

check: fmt vet lint test

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -l .; exit 1)

vet:
	go vet ./...

lint:
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

test:
	go test -race -cover ./...

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

fuzz:
	go test ./honeypot -fuzz=FuzzMatcher -fuzztime=30s
