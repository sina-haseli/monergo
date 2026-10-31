# Security

> **monergo is unaudited. Do not use it with real funds until it has been independently
> audited.**

## Reporting a vulnerability

Report privately through GitHub's "Report a vulnerability" (Security → Advisories) on this
repository. Do not open a public issue. Include a reproducer if you can. We aim to
acknowledge reports within 72 hours.

## Supported versions

Only the latest release receives fixes. Transactions can be built only for Monero hard fork
v16 (`protocol.CurrentHardFork`). Signing requests for any other version are refused,
including the FCMP++ fork once it activates.

## Threat model

monergo is meant to run as a **stateless signer**, for example a HashiCorp Vault plugin. It
holds the private keys, receives a `builder.TransferRequest` from a caller, and returns a
signed transaction. It never opens a network connection.

### What the signer guarantees

Every guarantee below is enforced in `builder` and covered by tests.

1. **It signs only outputs it owns.** For every input it re-derives the one-time key from the
   private keys and the tx public key(s), and checks that it opens the output key. It then
   recomputes the commitment from the stated amount and the derived mask (`G + a·H` for
   coinbase outputs) and checks it against the ring member. Any mismatch is
   `ErrInputNotOwned`.
2. **Amounts balance.** Inputs equal destinations plus change plus fee. All sums are
   overflow-checked, and the Bulletproof+ proves every output is in range.
3. **Change cannot be redirected.** Change goes to a subaddress derived from the keys. The
   caller chooses the index but cannot supply the change address.
4. **The fee is capped.** The fee is computed from the transaction weight and the caller's
   per-byte rate, and is never above `MaxFee` (`ErrFeeTooHigh`).
5. **The output is valid.** Every signed transaction is re-parsed and checked by
   `verify.Transaction` (balance, Bulletproofs+, every CLSAG, input rules) before it is
   returned.
6. **Secrets stay secret.** Scalar multiplications with secret scalars and secret scalar
   decoding are constant time, and so is the Bulletproof+ prover's multi-scalar
   multiplication. Secret buffers are wiped where practical. `keys.SecretKey` never prints
   its value.

### What the caller must handle

- **Authorization.** Anyone who can submit a request can spend: destinations and amounts are
  taken as given. Put authorization (policy, limits, allow-lists, approvals) in front of the
  signer.
- **Ring members (privacy, not funds).** Decoys and their commitments come from the caller.
  A malicious or careless caller can choose decoys that reveal which input is real, for
  example outputs it knows are spent or outputs it created. This costs privacy, not funds.
  Ring members that do not exist on chain make the network reject the transaction. Fetch
  rings from your own node and use `package decoy`, or an equivalent, for selection.
- **Fake inputs.** A caller can fabricate an "output" to your address with any amount, since
  anyone can create outputs to an address. The signer will sign it, and the network rejects
  the transaction, because the ring member does not match the chain. No funds move.
- **Fee rate.** `FeePerByte` comes from a daemon, which may be hostile. `MaxFee` bounds the
  damage, so set it.
- **Key images.** The returned key images, and the inputs themselves, show the caller which
  outputs were spent.
- **Hard forks.** The signer cannot know the chain's current hard fork. After a fork that
  changes the transaction format, its transactions are rejected until monergo is updated.
- **Process isolation.** Go's garbage collector may copy key material. Run the signer in its
  own process, with swap disabled or encrypted, and do not log requests that contain keys.

## Assurance so far

- **Upstream vectors.** Every cryptographic function is a port of monero-project/monero at
  `3fd0f88`, checked against upstream vectors (`tests/crypto/tests.txt`, base58 unit tests).
- **Reference wallet.** Address and seed results match the official `monero-wallet-rpc`
  v0.18.5.4.
- **Real chain data.** Real mainnet and stagenet transactions round-trip byte for byte, and
  their CLSAGs and Bulletproofs+ verify.
- **Independent implementation.** Every proof and transaction monergo builds is accepted by
  monero-oxide, an independent Rust implementation, with matching hash and weight.
  monero-oxide's wallet scanner finds the intended outputs, amounts, subaddresses and
  payment IDs.
- **Fuzzing.** Every parser and the whole signer are fuzzed in CI.

Not yet done:
- an independent audit;
- a stagenet end-to-end run (`docs/stagenet-e2e.md`);
- a small mainnet canary.
