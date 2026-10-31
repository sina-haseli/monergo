# Test vector provenance

Every committed fixture is listed here. Tests never touch the network.

| File | Source | Retrieved | SHA-256 |
|---|---|---|---|
| `data/tests.txt.gz` | `monero-project/monero@3fd0f88c20f559839cafb20911cb13cb45eba7bd:tests/crypto/tests.txt`, gzipped with `gzip -9 -n` | 2026-10-31 | uncompressed `98cf75c9c4bb48dc10d6e93b4b54767cfa32e66955c5ac4b8349eb627a603c18` (checked at load time) |

| `data/base58_unit_tests.json` | Test tables from `monero-project/monero@3fd0f88:tests/unit_tests/base58.cpp`, extracted by `tools/fixtures/extract_base58_tests.py` | 2026-10-31 | source `75c446818fc1c4be2906722de3b86cc152f2e80e4b33dcf660d1c9055be268b7` |
| `data/wallet_fixtures.json` | Official `monero-wallet-rpc` **v0.18.5.4** (`monero-win-x64-v0.18.5.4.zip`, sha256 `1ccac3b4…a042`, matching `hashes.txt` signed by binaryFate `81AC 591F E9C4 B65C 5806 AFC3 F0AF 4D46 2A0B DF92`), run `--offline` by `tools/fixtures/gen_wallet_fixtures.py` | 2026-10-31 | `5ee7a08f838cbcde900347d893b59d98f103c25ac5baf7c211e6c9759a73cb79` |

The wallet fixtures restore the three public seeds from `tests/functional_tests/transfer.py`
on each network. They record the private spend and view keys, the mnemonic, subaddresses
(0,0..5) and (1,0..2), and one integrated address with payment ID `1234567890abcdef`. The
mainnet primary address of the first seed matches the one asserted in upstream
`tests/functional_tests/wallet.py`. **These seeds are public. Never send funds to them.**

Retrieval of `tests.txt`:

```sh
curl -sL https://raw.githubusercontent.com/monero-project/monero/3fd0f88c20f559839cafb20911cb13cb45eba7bd/tests/crypto/tests.txt \
  | gzip -9 -n > internal/testvectors/data/tests.txt.gz
```

The semantics of each line type are defined by `tests/crypto/main.cpp` and
`tests/crypto/crypto.cpp` at the same commit. `Implemented` and `Skipped` in
`testvectors.go` account for every type in the file. `TestEveryTypeIsAccountedFor`
fails if upstream adds one.
