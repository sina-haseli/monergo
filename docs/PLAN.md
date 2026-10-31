# monergo — Implementation Plan

Status: **draft, awaiting approval**. Nothing below is implemented yet.

> Unaudited. Do not use with real funds until independently audited.

## 0. Ground truth checked on 2026-10-31

### Upstream references

| Reference | Pinned revision |
|---|---|
| monero-project/monero `master` | `3fd0f88c20f559839cafb20911cb13cb45eba7bd` |
| monero-oxide/monero-oxide `main` | `a6b46701fb9b331006d7f2f2278bf51f123b1447` |
| monero-oxide/monero-wallet-util `main` | pinned when M3 starts |

Every Monero path in the brief still exists at the pinned commit: `src/crypto/crypto.cpp`,
`src/crypto/crypto-ops.c`, `src/ringct/rctOps.cpp`, `src/ringct/rctSigs.cpp`,
`src/ringct/bulletproofs_plus.cc`, `src/cryptonote_basic/cryptonote_format_utils.cpp`,
`src/common/base58.cpp`, `src/device/device_default.cpp`, `src/wallet/wallet2.cpp` and
`tests/crypto/tests.txt`. The plan also uses these files:

- `src/cryptonote_core/cryptonote_tx_utils.cpp`: `construct_tx_with_tx_key`, output and extra
  construction.
- `src/mnemonics/electrum-words.cpp` and `src/mnemonics/english.h`: the 25-word seed.
- `src/hardforks/hardforks.cpp` and `src/cryptonote_config.h`: HF heights and `HF_VERSION_*`.
- `tests/crypto/main.cpp`: the semantics of each vector type in `tests.txt`.

### Things that have moved or changed

1. **`hash_to_ec` was renamed to `biased_hash_to_ec`.** `crypto.cpp` now contains both:
   - `biased_hash_to_ec`: `keccak` → `ge_fromfe_frombytes_vartime` → `ge_mul8`. This is the
     current mainnet `Hp`, and `generate_key_image` still uses it. The source comment says "key
     image derivation used before FCMP++/Carrot".
   - `unbiased_hash_to_ec`: a 64-byte **BLAKE2b** hash → two `ge_fromfe_frombytes_vartime`
     calls → sum. This is FCMP++-only.

   `derive_key_image_generator(pub, biased)` switches between the two. We implement the biased
   path now. The unbiased path needs BLAKE2b (see open question Q1).
2. **monero-oxide has no seed crate.** The 25-word seed and Polyseed now live in
   **`monero-oxide/monero-wallet-util`** (`seed/`, `polyseed/`). That repo becomes the second
   reference for M3.
3. **FCMP++ / Carrot status.** Beta stressnet v3.1 forked testnet at block 3102800 on
   2026-10-05 (seraphis-migration/monero release `v0.19.0.0-beta.3.1`). I found **no announced
   mainnet date**. Current mainnet is HF v16, with BP+ and view tags since v15 and CLSAG since
   v13.

### Vector types in `tests/crypto/tests.txt`

The file is 8.7 MB, or 4.9 MB gzipped. Plan for each type:

| Type | Count | Plan |
|---|---|---|
| `hash_to_scalar`, `check_scalar`, `check_key` | 256 / 337 / 372 | **M1** |
| `secret_key_to_public_key`, `generate_key_derivation` | 272 / 272 | **M1** |
| `derive_public_key`, `derive_secret_key` | 272 / 256 | **M1** |
| `hash_to_point` (`ge_fromfe_frombytes_vartime` on raw bytes), `biased_hash_to_ec` | 371 / 256 | **M1** |
| `generate_key_image`, `derive_view_tag`, `check_ge_p3_identity` | 256 / 70 / 6 | **M1** |
| `derive_key_image_generator` | 200 | **M1** for `biased=true`; `biased=false` needs BLAKE2b (Q1) |
| `random_scalar`, `generate_keys` | 245 / 256 | Skipped: these depend on the harness's deterministic RNG (Q2) |
| `generate_signature`, `check_signature`, `generate_ring_signature`, `check_ring_signature` | 256 / 512 / 256 / 1024 | Skipped: pre-RingCT signatures, which the signer does not need (Q2) |
| `point_to_wei_x_y` | 200 | Skipped: FCMP++ only |

The parser **fails on any unknown type**. Each skipped type is listed explicitly with its
reason, so a new upstream type cannot be silently ignored.

## 1. Package layout (revised)

Changes from the brief, with reasons:

- **New `/primitives`.** Keccak, scalar helpers, `Hs`, `Hp` and point decoding are used by
  `keys`, `ringct`, `scan`, `tx` and the BP+ generators. In `/keys` they would create import
  tangles, so `/keys` becomes the user-facing key types and derivations built on
  `/primitives`. (monero-oxide splits it the same way.)
- **New `/protocol`.** This is the single place for hard-fork rules: network bytes, HF version
  thresholds, ring size, BP+ max outputs, fee and weight constants. `address`, `tx` and
  `builder` read from it; nothing else hard-codes a consensus number.
- **`/ringct` gets subpackages** `clsag` and `bpplus`. Each one is large and independently
  testable.
- **`/internal/varint`.** Varints are needed below `tx`: the output index in `Hs`, the BP+
  generator seeds, and the subaddress table.

```
/primitives        Keccak256, ScReduce32, ScCheck, Hs, HashToPoint (ge_fromfe_frombytes_vartime),
                   BiasedHashToEC, DecodePoint (check_key semantics), constant-time helpers
/keys              PrivateKeys / PublicKeys, derivation 8·a·R, derive_public/secret_key,
                   key image, view tag, subaddress secret m
/address           Monero base58, standard / integrated / subaddress encode/decode
/seed              25-word mnemonic (English first); BIP39 bridge is deferred (Q5)
/protocol          Network (mainnet/testnet/stagenet), HF table, consensus + fee constants
/ringct            Pedersen commitments, zeroCommit, ECDH v2 amount encoding, commitment mask
/ringct/clsag      CLSAG prove/verify
/ringct/bpplus     Bulletproofs+ generators, prove/verify (single + batch verify)
/tx                types, binary (de)serialization, prefix hash, tx hash, signature hash
                   (get_pre_mlsag_hash), extra fields, weight + clawback
/scan              output ownership, one-time secret key, key images, subaddress lookup table
/builder           Sign(), TransferRequest, validation, InputSigner interface (CLSAG impl)
/decoy             optional gamma decoy selection over caller-supplied distribution data
/internal/varint
/internal/testvectors   tests.txt parser + committed fixtures (with provenance README)
/cmd/xmr-sign      stdin JSON → stdout {tx_hex, tx_hash}
/tools/oxide-check dev-only Rust harness that cross-verifies our proofs (outside the Go module; Q3)
```

Dependency direction: `internal/varint` → `primitives` → `keys`, `ringct/*` → `tx` →
`scan`, `address` → `builder` → `cmd`. `protocol` is a leaf that any package may import.

## 2. Cross-cutting rules

- **Porting.** Every ported function carries a header comment naming its source:
  `// Ported from monero src/crypto/crypto.cpp: crypto_ops::generate_key_derivation @3fd0f88`.
  Where `filippo.io/edwards25519` already provides the identical operation, we call it instead
  of porting ref10 line by line. Examples: `sc_reduce32` as `SetUniformBytes` on a
  zero-padded 64-byte buffer, and `ge_scalarmult_base` as `ScalarBaseMult`. The comment still
  names the upstream function, and test vectors prove the equivalence.
  `ge_fromfe_frombytes_vartime` has no equivalent there, so it is ported from
  `crypto-ops.c` onto `filippo.io/edwards25519/field`.
- **Point decoding is consensus-critical.** Monero's `ge_frombytes_vartime` and
  edwards25519's `Point.SetBytes` may disagree on non-canonical encodings. `DecodePoint` must
  match `check_key` on all 372 vectors before anything builds on it. Where they differ, we
  add explicit checks and document why.
- **Constant time.**
  - Secret scalars only go through `ScalarMult`, `ScalarBaseMult` and `MultiScalarMult`.
  - `VarTime*` is allowed only on public data (verification, and `Hp` of public keys).
  - Scalars are compared with `Scalar.Equal`, and secret bytes with
    `crypto/subtle.ConstantTimeCompare`.
  - Secret buffers are zeroed with a `defer` helper. Go's GC may still copy them, which the
    README states.
- **Randomness.** `crypto/rand` in production. Internal functions take an `io.Reader`, so tests
  can inject a deterministic stream and compare against fixtures.
- **Dependencies.** Only `filippo.io/edwards25519` and `golang.org/x/crypto/sha3`, plus the
  standard library. `go.mod` targets `go 1.24` (local toolchain: 1.25.7). CI fails if
  `CGO_ENABLED=0 go build ./...` fails or if `go.mod` gains a module.
- **Fixtures.** Every committed fixture gets a line in `internal/testvectors/README.md` with
  its source, upstream commit or block height, retrieval command and SHA-256. Tests never
  touch the network.
- **TDD.** Each primitive starts with its vectors and a failing test, then the implementation.
- **Commits.** Conventional, one logical change each (`feat(primitives): add biased_hash_to_ec`).
- **Licensing.** BSD-3-Clause `LICENSE`. Ported files keep
  `Copyright (c) 2014-2026, The Monero Project` above our own line. `NOTICE` credits
  monero-project (BSD-3) and monero-oxide / monero-wallet-util (MIT; used for cross-checking,
  with MIT notices added if any code is ever ported from them).

## 3. Milestones

Each milestone ends with green `go test ./...`, the pasted test output and a short report.
None is marked done without the output.

### M0 — Scaffold
`go.mod`, `LICENSE`, `NOTICE`, README with the unaudited warning, `.gitignore`, empty package
docs and a minimal CI workflow (`go vet`, `go test`, `CGO_ENABLED=0`). This lets every later
milestone run in CI from day one.

### M1 — Primitives
1. `internal/testvectors`: parser for `tests.txt` (gzipped, pinned to `3fd0f88`), with typed
   accessors per vector type and an explicit skip list.
2. `primitives`:
   - `Keccak256` (legacy Keccak, `sha3.NewLegacyKeccak256`)
   - `ScReduce32`, `ScCheck`, `Hs` (`hash_to_scalar`)
   - `DecodePoint` (`check_key`)
   - `HashToPoint` (`ge_fromfe_frombytes_vartime`), `BiasedHashToEC`
3. `keys`:
   - `SecretToPublic`, `GenerateKeyDerivation` (`8·a·R`), `DerivationToScalar` (varint index)
   - `DerivePublicKey`, `DeriveSecretKey`
   - `GenerateKeyImage`, `DeriveViewTag` (`"view_tag"` salt, keccak, first byte)
   - `DeriveKeyImageGenerator(biased=true)`

Done when every in-scope vector type above passes 100%, plus `check_ge_p3_identity`.

### M2 — Addresses
- Monero base58 with 8-byte blocks, a final partial block and the 4-byte keccak checksum.
- Standard, integrated (8-byte payment ID) and subaddress addresses:
  - `m = Hs("SubAddr\0" ‖ k_v ‖ major_le32 ‖ minor_le32)`
  - `D = K_s + m·G`, `C = k_v·D`; index (0,0) is the main address
- Network bytes for mainnet, testnet and stagenet come from `protocol`.

Fixtures:
- A fixed seed restored in `monero-wallet-cli --offline` on each network.
- The main address, subaddresses (0,1..5), (1,0..2), and one integrated address per network.
- The exact CLI commands, recorded in the fixture README.
- An extra cross-check against `base58.cpp` unit-test strings and monero-oxide's address tests.

The wallet binary is needed for this (Q4).

### M3 — Seed
- 25-word English mnemonic: 3 words per 4 bytes, and a checksum word chosen by CRC32 of the
  3-character prefixes (`electrum-words.cpp`).
- Encode and decode with checksum validation; reject unknown words and a bad checksum.
- `seed → spend key → view key = Hs(spend)`.

Fixture: the M2 wallet's `seed` output, round-tripped both ways. Other languages and Polyseed
come later. The BIP39 / SLIP-0010 bridge is deferred (Q5).

### M4 — Serialization
- `tx` types for version 2 transactions: `txin_gen`, `txin_to_key`, and `txout_to_key` /
  `txout_to_tagged_key`.
- `rct_signatures`: base plus prunable, for RCT types 5 (CLSAG) and 6 (BulletproofPlus) first.
- Parse version 1 / older RCT types only as far as needed to reject them cleanly.
- `extra` parser: tx pubkey `0x01`, nonce `0x02` (payment ID / encrypted payment ID),
  additional pubkeys `0x04`, padding. Unknown fields are kept as bytes.
- Hashes:
  - Prefix hash.
  - Tx hash: the three-part hash of prefix, rct base and rct prunable.
  - `get_pre_mlsag_hash` signature hash.

Fixtures: about 10 real mainnet and stagenet transactions as raw hex, with block heights and
`monerod get_transactions` expected hashes:

- 1-in/2-out, 2-in/2-out, 16-out, a subaddress send with additional keys, a coinbase, and an
  integrated-address send.
- Re-serialization must be byte-identical.
- Fetched once (Q6).

### M5 — Verification
- `ringct`: `zeroCommit`, `commit(a, mask)` with `H`, and the balance check
  `Σ pseudoOuts = Σ outPk + fee·H`.
- `ringct/clsag`: `CLSAG_Ver` (`rctSigs.cpp`). The domain separators (`CLSAG_agg_0`,
  `CLSAG_agg_1`, `CLSAG_round`) are copied verbatim.
- `ringct/bpplus`:
  - Generators (`bulletproofs_plus.cc`: `get_exponent`, `"bulletproof_plus"` transcript seed).
  - Transcript and weighted-inner-product verification.
  - Single and batch verification.

Fixtures: the M4 transactions plus each input's ring members (output key and commitment, from
`get_outs`, committed). Every CLSAG and BP+ in those transactions must verify. Tampered
copies (one flipped bit in each field) must fail. No prover code lands before this is green.

### M6 — Provers
- `CLSAG_Gen` and the `proveRctCLSAGSimple` flow.
- `bulletproof_plus_PROVE` for 1–16 outputs, padded to a power of two the way upstream does.
- Every proof we produce must pass our own verifier, in property tests over random inputs.
- Cross-check: `tools/oxide-check` (Rust, monero-oxide at the pinned commit) reads our
  proof-plus-statement JSON and verifies it. Run locally and in an optional CI job (Q3).
  Byte-identical proofs are impossible because of randomness, so the check is "the
  independent verifier accepts".

### M7 — Builder
- `TransferRequest` JSON as in the brief, plus:
  - `max_fee` (required cap)
  - `fee_quantization_mask` (from `get_fee_estimate`)
  - Optional `payment_id` for integrated destinations
- Validation before signing:
  - For each input, recompute the derivation, one-time key (with the subaddress `m`) and
    commitment `= amount·H + mask·G`. The v2 deterministic mask is
    `Hs("commitment_mask" ‖ Hs(derivation ‖ index))`, and coinbase outputs use `zeroCommit`.
  - The real member at `real_index` equals the output key and commitment.
  - Ring size matches `protocol` for the network's current HF (16 today).
  - Global indices are strictly increasing.
  - Reject duplicate key images and `uint64` overflow on input and output sums.
  - Reject a fee above `max_fee`, and destination amounts of 0.
- Construction follows `construct_tx_with_tx_key` and `wallet2`:
  - **Tx key.** Random `r`.
  - **Additional keys.** Follows the upstream `need_additional_txkeys` rule: at least one
    subaddress destination plus either a standard-address destination or a second subaddress
    destination. With exactly one subaddress destination, the tx pubkey is `R = r·D`. Change is
    excluded from both counts, as upstream does.
  - **Outputs.** One-time keys, view tags, `ecdhInfo` (8-byte amount XOR), commitments.
  - **Change** to the change subaddress index, with output order shuffled as in wallet2.
  - **`extra`** matches wallet2's layout and ordering, including the dummy encrypted payment ID
    for 2-output sends. Fingerprint parity with the reference wallet is a goal.
  - **Inputs.** Sorted by key image as consensus requires. The comparison direction is taken
    from `blockchain.cpp`'s sorted-key-image check, not guessed. Key offsets are converted to
    relative form.
  - **Fee.** Iterate weight → fee until stable. Weight includes the BP+ clawback
    (`get_transaction_weight`). Fee = `weight · fee_per_byte`, rounded up by the quantization
    mask.
  - **Pseudo-outs.** Random masks, with the last one set so the sum balances.
- `InputSigner` interface: `Sign(msg, input, pseudoMask) → MembershipProof`. CLSAG is the
  only implementation. `Sign()` selects it through `protocol`'s HF rules, so FCMP++ can add an
  implementation without breaking the public API.
- `scan.KeyImages(keys, outputs)` and address helpers are exposed.
- Tests:
  - A built tx parses back, re-serializes byte-identically and passes our verifiers plus
    `oxide-check`.
  - Every rejection rule has a test.

### M8 — Stagenet end-to-end
- `cmd/xmr-sign` builds a tx from a JSON payload assembled from a stagenet wallet's outputs
  (a helper script gathers the rings via `get_outs`).
- Submit with `send_raw_transaction`; it must be accepted and mined.
- Capture the payload, tx hash and block height in `docs/stagenet-e2e.md`, with the exact
  steps. Needs funded stagenet keys and a node (Q7).

### M9 — Hardening
- `go test -fuzz` targets: base58, address decode, seed decode, tx parse (round-trip
  property), extra parse, and the `TransferRequest` JSON.
- golangci-lint config: govet, staticcheck, errcheck, gosec, and a rule forbidding
  `math/rand`.
- GitHub Actions matrix (Linux, macOS, Windows × Go 1.24 / stable, `CGO_ENABLED=0`).
- Benchmarks for `Sign` (1-in/2-out and 4-in/16-out), CLSAG and BP+.
- `decoy` (gamma, `wallet2::gamma_picker`) also lands here if not earlier. It is a port of
  the distribution, not the RNG, so it is tested statistically.

## 4. Risks

| Risk | Mitigation |
|---|---|
| `check_key` / point-decoding mismatch with edwards25519 | Gate M1 on all 372 vectors; add explicit canonicality checks if needed |
| Wallet-fingerprint divergence (extra order, output shuffle, fee rounding) | Port the wallet2 code paths literally; compare structure against real wallet txs in M7 tests |
| Upstream changes before FCMP++ (renames like `biased_hash_to_ec`) | Pin commits; re-check the pins at each milestone start |
| GC copies of secrets | Best-effort zeroing, documented; recommend running the signer in an isolated process |
| FCMP++ activation changes the tx format | HF rules isolated in `protocol`; `InputSigner` interface; the builder refuses to sign for an HF version it does not know |

## 5. Open questions — need your decision

- **Q1.** `unbiased_hash_to_ec` (FCMP++ key-image generator) uses BLAKE2b. It is available as
  `golang.org/x/crypto/blake2b`: same module as `sha3`, a new package, no new module. Allow it
  now for the 100 `biased=false` vectors, or defer until FCMP++ work? *Recommendation: defer.*
- **Q2.** Skip the RNG-dependent and pre-RingCT vector types listed in §0? Porting the
  harness's deterministic RNG would let `random_scalar` and `generate_keys` run too.
  *Recommendation: skip for now.*
- **Q3.** For M6/M7 cross-checks, OK to add a dev-only Rust harness under `tools/oxide-check`
  (needs `cargo`; not part of the Go module)? The alternative is relying only on stagenet
  `monerod` in M8. *Recommendation: add the harness.*
- **Q4.** For the M2/M3 fixtures, may I download the official Monero CLI release, verify its
  hashes against the signed `hashes.txt`, and run it `--offline`? Or would you rather generate
  the outputs yourself?
- **Q5.** The "SLIP-0010 / BIP39 bridge" has no single Monero standard: Trezor, Ledger and
  others derive differently. Which scheme should it be compatible with, or do we drop it from
  v1? *Recommendation: drop from v1.*
- **Q6.** For M4/M5, OK to fetch the raw transactions and ring members once from a public node,
  or will you point me at your own node?
- **Q7.** For M8, you will need funded stagenet keys (a faucet) and a stagenet node. Who
  provides them?
- **Q8.** Spendable input scope for v1: outputs from RCT types 4–6 (deterministic v2 masks) and
  coinbase (`zeroCommit`). Outputs from older RCT types (encrypted masks, pre-2019) would be
  rejected. *Recommendation: yes.*
- **Q9.** Commit `tests.txt` gzipped in full (4.9 MB, simplest provenance) or a filtered subset
  of only the types we run (smaller, but a derived file)? *Recommendation: the full gzipped
  file.*
