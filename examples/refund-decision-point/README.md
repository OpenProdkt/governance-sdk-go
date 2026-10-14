# Refund decision point (Go)

A small refund service built on the OpenProdkt Go SDK. It covers:

- an immediate allow, and a deny that never runs the refund
- a bounded synchronous wait that returns pending without executing
- an approval webhook that resumes the refund exactly once and ignores duplicate deliveries
- an async status poll (`Poll`) that keeps the refund pending, resumes it once on approval, and discards it on rejection
- a rejected approval that discards the pending refund

The tests use an `httptest` fake of `POST /v1/evaluate` and `GET /v1/approvals/{id}`, so no control plane is needed.

## Run

From this directory:

```bash
go test -p 1 -count=1 ./...
```

In this repository, `go.mod` replaces `github.com/OpenProdkt/governance-sdk-go` with `../..`, so the example tests the SDK in the same checkout. In the public SDK mirror, the replace directive is removed and the example is pinned to the published module version.
