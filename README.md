# monergo

Pure-Go (`CGO_ENABLED=0`) library for Monero keys, addresses and transaction signing
(RingCT type 6: CLSAG + Bulletproofs+, view tags), built for stateless signers such as a
HashiCorp Vault plugin. You give it a JSON request and get a signed transaction back as hex.
The signer never touches the network.

> **Unaudited. Do not use with real funds until independently audited.**

## Status

See [docs/PLAN.md](docs/PLAN.md) for milestones and evidence.

- **Primitives, addresses, seeds, serialization and verification:** tested against upstream
  vectors, `monero-wallet-rpc` output and real mainnet/stagenet transactions.
- **Provers and builder:** every CLSAG, BP+ and full transaction we produce passes our
  verifier and [monero-oxide](https://github.com/monero-oxide/monero-oxide) (an independent
  Rust implementation), with matching hash and weight.
- **End to end against the official daemon:** on a private regtest chain, the official
  `monerod` v0.18.5.4 accepts and mines transactions monergo signs (8 shapes, including
  subaddresses, integrated addresses, 16 outputs, a 19-input sweep). The official wallet
  confirms what arrived, and a double spend is rejected. No funds are involved; CI runs it on
  every push ([docs/regtest-e2e.md](docs/regtest-e2e.md)).
- **Public test network:** a testnet or stagenet run with free faucet coins is prepared but
  **not yet run** ([docs/testnet-e2e.md](docs/testnet-e2e.md)).
- **Hard forks:** only v16 transactions can be built. FCMP++ (v17) is not supported, and
  the signer refuses any other hard-fork version.

## Production readiness

Done:
- **Engineering hardening.** Constant-time secret handling, input and fee validation,
  self-verification of every signed transaction, and early weight limits.
- **Independent cross-checks.** monero-oxide's verifier and wallet scanner accept everything
  monergo builds.
- **Fuzzing and linting.** Every parser and the signer are fuzzed; golangci-lint and
  govulncheck run in CI.
- **Supply chain.** CI actions are pinned to commit SHAs, Dependabot is configured, and
  tagged releases build reproducible binaries with checksums.
- **Documentation.** The threat model is in [SECURITY.md](SECURITY.md): what the signer
  guarantees, and what the calling policy must handle.

Still required before real funds:
1. A public testnet or stagenet run, [docs/testnet-e2e.md](docs/testnet-e2e.md). Faucet
   coins are free.
2. An independent security audit.
3. A small mainnet canary transaction.

## Usage

```go
import "github.com/sina-haseli/monergo/builder"

keys := builder.PrivateKeys{Spend: spendKey, View: viewKey} // keys.SecretKey, hex in JSON
txHex, txHash, err := builder.Sign(keys, builder.TransferRequest{
	Network: protocol.Stagenet,
	Inputs: []builder.Input{{
		TxPubKey: ..., AdditionalTxPubKeys: ..., OutputIndex: 1, OutputKey: ...,
		Amount: 5_000_000_000_000, Subaddress: keys.SubaddressIndex{},
		Ring: ring16, RealIndex: 7, // from get_outs; see package decoy
	}},
	Destinations:        []builder.Destination{{Address: "5...", Amount: 1_000_000_000_000}},
	FeePerByte:          20000, // get_fee_estimate
	FeeQuantizationMask: 10000,
	MaxFee:              100_000_000,
})
```

Before signing, `builder.Sign` checks the request:
- **Ownership.** For every input it re-derives the one-time key from the private keys and
  recomputes the amount commitment. A mismatch is an error.
- **Rings.** It rejects wrong ring sizes, rings not sorted by global index, and duplicate
  key images.
- **Amounts and fee.** It rejects amount overflow, zero amounts, insufficient funds, and a
  fee above `MaxFee`.

The construction follows `wallet2` / `construct_tx_with_tx_key`: change and dummy 0-amount
outputs, encrypted (or dummy) payment IDs, additional tx keys for subaddresses, shuffled
outputs, inputs sorted by key image, and the same `tx_extra` layout. Each signed
transaction is verified (`package verify`) before it is returned.

Other entry points:
- `scan.KeyImages(keys, outputs)` returns key images.
- `address.FromAccount` and `address.Parse` derive and decode addresses.
- `seed.Decode` and `seed.Encode` handle 25-word seeds.
- `decoy.Select` picks decoys with wallet2's gamma distribution.
- `cmd/xmr-sign` is a CLI that reads JSON on stdin and writes JSON on stdout.

## Packages

| Package | Purpose |
|---|---|
| `primitives` | Keccak-256, scalar helpers, `Hs`, `Hp`, point decoding, subgroup check |
| `keys` | key types, key derivation, one-time keys, subaddresses, key images, view tags |
| `address` (`/base58`) | Monero base58, standard / integrated / subaddress |
| `seed` | 25-word English mnemonic |
| `protocol` | networks, hard-fork rules, consensus limits |
| `ringct`, `ringct/clsag`, `ringct/bpplus` | commitments, ECDH, CLSAG and Bulletproofs+ prove/verify |
| `tx` | transaction types, byte-exact serialization, hashes, `tx_extra`, weight |
| `verify` | RingCT verification of a transaction given its rings |
| `scan` | output ownership, one-time secret keys, key images |
| `builder` | `Sign(keys, request)`, `InputSigner` (CLSAG today, FCMP++ later) |
| `decoy` | gamma decoy selection over a daemon's output distribution |
| `cmd/xmr-sign`, `tools/xmr-prepare` | offline signing CLI; request assembly from wallet-rpc and daemon |

## Design notes

- **Faithful ports.** Every cryptographic function is a port of the Monero C++ reference at
  commit `3fd0f88`. Each one carries a comment naming the upstream file and function.
- **Dependencies.** Only `filippo.io/edwards25519` and `golang.org/x/crypto/sha3`
  (`x/sys` comes in indirectly). Monero uses the original Keccak, not SHA3-256.
- **Constant time.** Operations on secret scalars use constant-time edwards25519 APIs,
  including the Bulletproofs+ prover's multi-scalar multiplications (upstream uses
  variable-time ones there). Secret buffers are zeroed after use where practical, but Go's
  garbage collector may copy memory. Run the signer in an isolated process.
- **Benchmarks.** i5-12400, `CGO_ENABLED=0`:
  - `Sign` 1-in/2-out: 32 ms
  - `Sign` 4-in/16-out: 223 ms
  - CLSAG (16) sign: 2.1 ms; verify: 2.0 ms
  - BP+ (2 outputs) prove: 23 ms; verify: 2.5 ms

## Testing

```sh
CGO_ENABLED=0 go test ./...
go test -run '^$' -fuzz FuzzSign -fuzztime 1m ./builder
(cd tools/oxide-check && cargo build --release) && go test -run Oxide -v ./verify ./builder
MONERGO_MONEROD=/path/monerod MONERGO_WALLET_RPC=/path/monero-wallet-rpc go test -v ./internal/e2e
```

Fixtures and their provenance are listed in
[internal/testvectors/README.md](internal/testvectors/README.md).

## Releasing

1. Move the `[Unreleased]` entries in `CHANGELOG.md` under `## [X.Y.Z] - YYYY-MM-DD`.
2. Tag and push: `git tag -s vX.Y.Z && git push origin vX.Y.Z`.
3. `.github/workflows/release.yml` runs the full CI (including the oxide cross-check and the
   regtest end-to-end test), builds `xmr-sign` and `xmr-prepare` for five platforms twice
   and checks that both builds are byte-identical, writes `SHA256SUMS`, attests build
   provenance, and opens a **draft** release with the changelog section as notes.
4. Review the draft and publish it. Users can check a binary with
   `gh attestation verify <file> --repo sina-haseli/monergo`.

## License

BSD 3-Clause. Contains code ported from the Monero Project; see [LICENSE](LICENSE) and
[NOTICE](NOTICE).
