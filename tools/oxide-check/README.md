# oxide-check

A dev-only harness that cross-checks monergo against
[monero-oxide](https://github.com/monero-oxide/monero-oxide), an independent Rust
implementation of Monero. It is pinned to commit `a6b46701fb9b331006d7f2f2278bf51f123b1447`.
It is not part of the Go module, and the Go build never needs it.

It reads a JSON request on stdin with two lists.

`txs` holds `{"hex", "rings"}` entries. For each transaction it reports:
- whether monero-oxide parses it and re-serializes the same bytes;
- the transaction hash, signature hash and weight;
- whether every CLSAG and the range proof verify.

`scans` holds `{"tx_hex", "miner_tx_hex", "spend_pub", "view_sec", "subaddresses"}` entries.
For each one it reports the outputs that monero-wallet's `Scanner` assigns to that view pair:
index, subaddress, amount and payment ID. This independently checks output keys, view tags,
tx and additional keys, amount encryption and payment-ID encryption.

## Build

```sh
cd tools/oxide-check
cargo build --release
```

`rust-toolchain.toml` pins Rust 1.89.0, which `monero-wallet` requires. rustup installs it
on first build, alongside your default toolchain.

## Use

Go tests that use it (`internal/oxidecheck`) find the binary at
`tools/oxide-check/target/release/oxide-check`, or at `$MONERGO_OXIDE_CHECK`. They are
skipped when it is missing:

```sh
go test ./verify -run Oxide -v
```
