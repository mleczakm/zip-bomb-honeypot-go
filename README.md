# zip-bomb-honeypot-go

[![CI](https://github.com/mleczakm/zip-bomb-honeypot-go/actions/workflows/ci.yml/badge.svg)](https://github.com/mleczakm/zip-bomb-honeypot-go/actions/workflows/ci.yml)

A small Go `net/http` middleware that recognizes common vulnerability-scanner
probes and replies with a harmless ZIP decoy. It is inspired by
[mleczakm/zip-bomb-honeypot](https://github.com/mleczakm/zip-bomb-honeypot).

The original project uses overlapping ZIP records to create an archive that can
expand dramatically when extracted. This Go implementation deliberately does
not generate or serve a ZIP bomb. Its ordinary one-file archive has a strict
uncompressed-content limit of 512 bytes.

## Install

~~~sh
go get github.com/mleczakm/zip-bomb-honeypot-go
~~~

## Usage

Wrap your existing handler and optionally record matching requests:

~~~go
package main

import (
	"log"
	"net/http"

	"github.com/mleczakm/zip-bomb-honeypot-go/honeypot"
)

func main() {
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	handler := honeypot.New(app, func(r *http.Request) {
		log.Printf("scanner probe: method=%s path=%q remote=%s",
			r.Method, r.URL.Path, r.RemoteAddr)
	})
	log.Fatal(http.ListenAndServe(":8080", handler))
}
~~~

Requests that match a known probe receive `200 OK` with a small ZIP attachment.
Other requests continue to the wrapped handler. `HEAD` requests receive the
same headers without a body. Pass `nil` for the callback if you do not need
probe notifications; pass `nil` for the next handler to use `http.NotFoundHandler`.

## Matched paths

The matcher covers common probes for environment files and credentials, Git/SVN
metadata, WordPress and phpMyAdmin, PHP tooling, actuator/debug endpoints, and
SQL or backup files. Matching is case-insensitive. See
[`honeypot/matcher.go`](honeypot/matcher.go) for the current list.

Use this middleware only on an HTTP service you operate. The callback receives
the original request; avoid logging secrets from query strings or other
untrusted request data.

## Development

~~~sh
make check       # formatting, vet, static analysis, tests, and race detector
make coverage   # HTML coverage report
make fuzz        # run the matcher fuzzer for 30 seconds
~~~

The test suite includes table-driven unit tests, HTTP handler integration
tests, ZIP format and size checks, a Go fuzz target, and a matcher benchmark.
CI runs tests across supported Go versions and checks formatting, vet, lint,
race safety, and known dependency vulnerabilities.

## License

MIT. See [LICENSE](LICENSE).
