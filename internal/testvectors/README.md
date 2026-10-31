# Test vector provenance

Every committed fixture is listed here. Tests never touch the network.

| File | Source | Retrieved | SHA-256 |
|---|---|---|---|
| `data/tests.txt.gz` | `monero-project/monero@3fd0f88c20f559839cafb20911cb13cb45eba7bd:tests/crypto/tests.txt`, gzipped with `gzip -9 -n` | 2026-10-31 | uncompressed `98cf75c9c4bb48dc10d6e93b4b54767cfa32e66955c5ac4b8349eb627a603c18` (checked at load time) |

Retrieval:

```sh
curl -sL https://raw.githubusercontent.com/monero-project/monero/3fd0f88c20f559839cafb20911cb13cb45eba7bd/tests/crypto/tests.txt \
  | gzip -9 -n > internal/testvectors/data/tests.txt.gz
```

The semantics of each line type are defined by `tests/crypto/main.cpp` and
`tests/crypto/crypto.cpp` at the same commit. `Implemented` and `Skipped` in
`testvectors.go` account for every type in the file. `TestEveryTypeIsAccountedFor`
fails if upstream adds one.
