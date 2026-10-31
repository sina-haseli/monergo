# Stagenet end-to-end test (M8)

This procedure builds a transaction with monergo, submits it to stagenet, and confirms
that the network accepts and mines it.

> Unaudited. Use stagenet only. Stagenet coins have no value.

**Status: not yet run.** It needs a funded stagenet wallet. The daemon side of
`xmr-prepare` has been exercised against `stagenet.xmr-tw.org` with a real stagenet output.
That run covered decoy selection over the live output distribution, `/get_outs`, unlock
checks and the real-member check. Signing and submission still need your funds. Record the
result in the table at the end.

## Pieces

| Component | Network? | Sees keys? |
|---|---|---|
| `monero-wallet-rpc --stagenet` (official) | yes | yes (your wallet) |
| `tools/xmr-prepare`: inputs, decoys, rings, fee | yes | **no** |
| `cmd/xmr-sign`: builds and signs | **no** | yes |
| `monerod` `/send_raw_transaction` | yes | no |

## 1. Build

```sh
CGO_ENABLED=0 go build -o xmr-sign ./cmd/xmr-sign
CGO_ENABLED=0 go build -o xmr-prepare ./tools/xmr-prepare
```

You also need the official CLI, v0.18.5.4 or newer, from <https://getmonero.org/downloads/>.
Verify `hashes.txt` against binaryFate's key, fingerprint
`81AC 591F E9C4 B65C 5806 AFC3 F0AF 4D46 2A0B DF92`.

## 2. A stagenet daemon

Use a local `monerod --stagenet` (most private) or a public node:

```sh
DAEMON=http://stagenet.xmr-tw.org:38081   # or http://127.0.0.1:38081
```

## 3. A funded stagenet wallet

```sh
monero-wallet-cli --stagenet --daemon-address ${DAEMON#http://} --generate-new-wallet e2e
# note the primary address (starts with 5), then fund it from a stagenet faucet
# wait for 10 confirmations; check with: balance
```

## 4. Open the wallet over RPC (localhost only)

```sh
monero-wallet-rpc --stagenet --daemon-address ${DAEMON#http://} --wallet-file e2e \
  --password '' --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38083 --disable-rpc-login
WALLET=http://127.0.0.1:38083
```

Export the private keys to a file that only you can read. `xmr-sign` reads them with
`-keys`:

```sh
SPEND=$(curl -s $WALLET/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"query_key","params":{"key_type":"spend_key"}}' | jq -r .result.key)
VIEW=$(curl -s $WALLET/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"query_key","params":{"key_type":"view_key"}}' | jq -r .result.key)
umask 077; printf '{"Spend":"%s","View":"%s"}\n' "$SPEND" "$VIEW" > keys.json
unset SPEND VIEW
```

## 5. Prepare, sign, submit

Send 0.1 XMR (1e11 atomic units) to a second stagenet address you control, such as a
subaddress of another wallet:

```sh
./xmr-prepare -wallet $WALLET -daemon $DAEMON -network stagenet \
  -to 5... -amount 100000000000 -max-fee 1000000000 > payload.json

./xmr-sign -keys keys.json < payload.json > signed.json
jq '{tx_hash, fee, weight, key_images}' signed.json

curl -s $DAEMON/send_raw_transaction \
  -d "{\"tx_as_hex\":\"$(jq -r .tx_hex signed.json)\",\"do_not_relay\":false}" | jq
```

Expected: `"status": "OK"`, `"not_relayed": false`, and every rejection flag
(`double_spend`, `fee_too_low`, `invalid_input`, `invalid_output`, `sanity_check_failed`,
...) `false`.

## 6. Confirm it is mined

```sh
TX=$(jq -r .tx_hash signed.json)
curl -s $DAEMON/get_transactions -d "{\"txs_hashes\":[\"$TX\"]}" | jq '.txs[0] | {in_pool, block_height}'
```

Repeat until `in_pool` is `false` and `block_height` is set (one block is about 2 minutes).
Then, in `monero-wallet-cli`:
- the sender wallet shows the transfer and the change after `refresh`;
- the recipient wallet shows the incoming amount.

Clean up: `shred -u keys.json` (or delete it securely).

## Result

| Date | Tx hash | Block height | Fee | Inputs/outputs | Notes |
|---|---|---|---|---|---|
| _pending_ | | | | | |
