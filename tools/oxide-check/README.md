# oxide-check

A dev-only harness that cross-checks monergo against
[monero-oxide](https://github.com/monero-oxide/monero-oxide), an independent Rust
implementation of Monero. It is pinned to commit `a6b46701fb9b331006d7f2f2278bf51f123b1447`.
It is not part of the Go module, and the Go build never needs it.

It reads `{"txs":[{"hex": "...", "rings": [[["key","mask"], ...], ...]}]}` on stdin. For
each transaction it reports:
- whether monero-oxide parses it and re-serializes the same bytes;
- the transaction hash, signature hash and weight;
- whether every CLSAG and the range proof verify.

## Build

```sh
cd tools/oxide-check
cargo build --release
```

`Cargo.lock` pins `hex-literal` 0.4.1, `zeroize` 1.8.1 and `zeroize_derive` 1.4.2, so the
harness builds with Rust 1.81. Newer releases of these crates need edition 2024.

## Use

Go tests that use it (`internal/oxidecheck`) find the binary at
`tools/oxide-check/target/release/oxide-check`, or at `$MONERGO_OXIDE_CHECK`. They are
skipped when it is missing:

```sh
go test ./verify -run Oxide -v
```
