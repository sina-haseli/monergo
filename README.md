# monergo

Pure-Go (`CGO_ENABLED=0`) library for Monero keys, addresses and transaction signing
(RingCT, CLSAG, Bulletproofs+). Built for stateless signers such as a HashiCorp Vault
plugin: JSON payload in, signed transaction hex out, no network access.

> **Unaudited. Do not use with real funds until independently audited.**

## Status

Work in progress. See [docs/PLAN.md](docs/PLAN.md) for the milestones and their status.

| Package | Purpose |
|---|---|
| `primitives` | Keccak-256, scalar helpers, `Hs`, `Hp`, point decoding |
| `keys` | key types, key derivation, one-time keys, key images, view tags |
| `address` | Monero base58, standard / integrated / subaddress |
| `seed` | 25-word mnemonic |
| `protocol` | networks, hard-fork rules, consensus constants |
| `ringct`, `ringct/clsag`, `ringct/bpplus` | commitments, ECDH, CLSAG, Bulletproofs+ |
| `tx` | transaction types, serialization, hashes, weight |
| `scan` | output ownership, key images |
| `builder` | `Sign(keys, request)` |
| `decoy` | optional decoy selection helper |
| `cmd/xmr-sign` | CLI for manual testing |

## Design notes

- Every cryptographic function is a port of the Monero C++ reference. Each one carries a
  comment naming its upstream file, function and pinned commit, and is tested against
  upstream vectors.
- Only two dependencies: `filippo.io/edwards25519` and `golang.org/x/crypto/sha3`. Monero
  uses the original Keccak, not SHA3-256.
- Operations on secret scalars use edwards25519's constant-time APIs. Secret buffers are
  zeroed after use where practical, but Go's garbage collector may copy memory, so run the
  signer in an isolated process.

## License

BSD 3-Clause. Contains code ported from the Monero Project; see [LICENSE](LICENSE) and
[NOTICE](NOTICE).
