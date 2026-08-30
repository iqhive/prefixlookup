# Centralised quality suite

This is the repo-wide hardening lot. It hits the public APIs the way an outside caller would, rather than poking at internals.

What's in here:

- brute-force oracle checks across the implementations
- cross-implementation consistency, plus a few external competitors
- IPv4, IPv6, mapped IPv4, default routes, overwrites, deletes
- parent / supernet / subnet / exact-match / enumeration contracts
- managed-generation batching, async publish, and race tests
- that the benchmark work-distribution helpers aren't lying
- the fuzz corpus we imported from the internal hardening suite

Per-package invariant tests still live next to the packages they belong to.

```sh
go test ./tests
go test -race ./tests
go test ./tests -fuzz FuzzImplementationsAgree
```
