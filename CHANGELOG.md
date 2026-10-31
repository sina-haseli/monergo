# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Before 1.0.0 the public API may change in minor
releases.

## [Unreleased]

First version. **Unaudited.**

### Added

- `primitives`:
  - Keccak-256, `Hs`, `Hp` (`biased_hash_to_ec`, `ge_fromfe_frombytes_vartime`).
  - Point decoding with Monero's acceptance rules and a prime-order subgroup check.
  - Constant-time decoding of secret scalars.
- `keys`:
  - Key derivation, one-time keys, subaddress keys, key images and view tags.
  - Account recovery from a seed key.
  - Hex JSON encoding; secret keys never print.
- `address`: Monero base58; standard, integrated and subaddress addresses for mainnet,
  testnet and stagenet.
- `seed`: 25-word English mnemonic.
- `protocol`: networks, v16 hard-fork rules and consensus limits.
- `tx`: byte-exact v2 serialization (RCT types 0, 5, 6), hashes, `tx_extra` and weight.
- `ringct`, `ringct/clsag`, `ringct/bpplus`:
  - Commitments and v2 amount encryption.
  - CLSAG sign and verify.
  - Bulletproofs+ prove and batch verify.
- `verify`: RingCT verification of a transaction, given its rings.
- `scan`: output ownership, one-time secret keys, key images.
- `builder`: stateless `Sign(keys, TransferRequest)` with wallet2-equivalent construction,
  and the `InputSigner` interface.
- `decoy`: wallet2 gamma decoy selection.
- `cmd/xmr-sign` (offline signing CLI) and `tools/xmr-prepare` (assembles a request from
  wallet-rpc and a daemon).
