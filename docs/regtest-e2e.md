# Regtest end-to-end test

`internal/e2e` tests monergo against the official Monero daemon and wallet on a private
regtest chain. Coins are mined locally in seconds, so it needs **no funds, no faucet and
no network access**. CI runs it on every push (job `e2e-regtest`).

> Unaudited. Regtest proves consensus acceptance, not safety for real funds.

## What it checks

The test starts `monerod --regtest --offline --fixed-difficulty 1`, which is at hard fork
v16 from block 1, and two `monero-wallet-rpc` wallets, alice and bob. It mines 300 blocks to
alice, then runs these steps in order:

| Step | Shape |
|---|---|
| standard address | 1 coinbase input → bob's primary address + change |
| subaddress | → bob's subaddress (tx key `r·D`) |
| integrated address | → bob's integrated address (encrypted payment ID) |
| mixed destinations | → primary + 2 subaddresses (additional tx keys) |
| 16 outputs | → 15 subaddresses + change |
| spend received outputs | bob spends 3+ outputs received at several subaddresses |
| sweep | bob spends all 19 outputs with zero change (dummy output) |
| double spend | a different tx reusing the sweep's key images |

For each transfer:
- `xmr-prepare`'s logic (`internal/prepare`) gathers inputs, gamma-picked decoys, rings and
  the fee from the wallet and the daemon;
- monergo signs it with the keys exported from the wallet;
- `send_raw_transaction` must return `OK`, and the tx must be mined;
- the recipient's official wallet must show exactly the intended amount per subaddress
  (and the payment ID);
- the sender's official wallet must show the spend with the same fee and the right
  change.

The double spend must be rejected with `double_spend: true`.

## Run it

Download the official CLI (v0.18.5.4 or newer) from <https://getmonero.org/downloads/> and
check it against `hashes.txt`, signed by binaryFate
(`81AC 591F E9C4 B65C 5806 AFC3 F0AF 4D46 2A0B DF92`). Then:

```sh
MONERGO_MONEROD=/path/to/monerod \
MONERGO_WALLET_RPC=/path/to/monero-wallet-rpc \
go test -count=1 -v ./internal/e2e
```

It takes about 30 seconds. Without the two variables the test is skipped. Optional:
- `MONERGO_E2E_LOGDIR=dir` keeps the daemon and wallet logs;
- `MONERGO_E2E_DAEMON_LOG=2` raises monerod's log level.

## Notes

- **Wallet network.** Release builds of `monero-wallet-rpc` have no `--regtest` flag.
  Regtest uses mainnet address prefixes, so the wallets run in mainnet mode with
  `--allow-mismatched-daemon-version`, which accepts regtest's hard-fork table.
- **Dandelion++.** monerod keeps a locally submitted transaction out of its block templates
  while the transaction is in the Dandelion++ stem phase. An offline daemon has no peers to
  stem to, so the transaction waits for the embargo timer (about 39 s on average). The test
  keeps mining a block every 2 s until the transaction is included.
