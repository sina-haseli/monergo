#!/usr/bin/env python3
"""Fetch real transactions and their ring members once, for offline tests.

Usage:
  python3 -I tools/fixtures/fetch_chain_fixtures.py > internal/testvectors/data/chain_fixtures.json

Each transaction is fetched from a primary node and its hex is cross-checked against a
second, independent node. The tests then recompute every tx hash from the hex, so a
node cannot substitute data without detection. Ring members (output key and commitment
for every global index referenced by an input) come from /get_outs; M5 verifies them
by checking every CLSAG.
"""
import json
import sys
import urllib.request

NODES = {
    "mainnet": ["https://xmr-node.cakewallet.com:18081", "http://node.sethforprivacy.com:18089"],
    "stagenet": ["http://stagenet.xmr-tw.org:38081", "http://node2.monerodevs.org:38089"],
}

# Shapes to find: name -> (network, predicate on decoded json, start height, scan direction)
def rct_type(j):
    return j.get("rct_signatures", {}).get("type")


def has_additional_keys(j):
    extra = bytes(j.get("extra", []))
    i = 0
    while i < len(extra):
        tag = extra[i]
        if tag == 0x04:
            return True
        if tag == 0x01:
            i += 33
        elif tag == 0x02:
            i += 2 + extra[i + 1]
        elif tag == 0x00:
            i += 1
        else:
            return False
    return False


SHAPES = [
    ("mainnet_bpp_1in_2out", "mainnet", lambda j: rct_type(j) == 6 and len(j["vin"]) == 1 and len(j["vout"]) == 2, None),
    ("mainnet_bpp_2in_2out", "mainnet", lambda j: rct_type(j) == 6 and len(j["vin"]) == 2 and len(j["vout"]) == 2, None),
    ("mainnet_bpp_many_in", "mainnet", lambda j: rct_type(j) == 6 and len(j["vin"]) >= 4, None),
    ("mainnet_bpp_16_out", "mainnet", lambda j: rct_type(j) == 6 and len(j["vout"]) == 16, None),
    ("mainnet_bpp_3_out", "mainnet", lambda j: rct_type(j) == 6 and len(j["vout"]) == 3, None),
    ("mainnet_bpp_additional_keys", "mainnet", lambda j: rct_type(j) == 6 and has_additional_keys(j), None),
    ("mainnet_clsag_type5", "mainnet", lambda j: rct_type(j) == 5 and len(j["vin"]) <= 2, 2500000),
    ("stagenet_bpp", "stagenet", lambda j: rct_type(j) == 6 and len(j["vout"]) == 2, None),
]


def call(base, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": "0", "method": method, "params": params}).encode()
    req = urllib.request.Request(base + "/json_rpc", body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)["result"]


def other(base, path, params):
    req = urllib.request.Request(base + path, json.dumps(params).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def get_txs(base, hashes):
    txs = []
    for i in range(0, len(hashes), 20):  # restricted nodes cap the batch size
        res = other(base, "/get_transactions", {"txs_hashes": hashes[i:i + 20], "decode_as_json": True, "prune": False})
        if res.get("status") != "OK":
            raise RuntimeError(res)
        txs += res["txs"]
    return txs


BLOCK_CACHE = {}


def block_txs(net, base, h):
    if (net, h) not in BLOCK_CACHE:
        blk = call(base, "get_block", {"height": h})
        hashes = blk.get("tx_hashes", [])
        BLOCK_CACHE[(net, h)] = (blk, get_txs(base, hashes) if hashes else [])
    return BLOCK_CACHE[(net, h)]


def rings_for(base, j):
    rings = []
    for vin in j["vin"]:
        offs = vin["key"]["key_offsets"]
        absolute, acc = [], 0
        for o in offs:
            acc += o
            absolute.append(acc)
        outs = other(base, "/get_outs", {"outputs": [{"amount": 0, "index": i} for i in absolute], "get_txid": True})
        if outs.get("status") != "OK":
            raise RuntimeError(outs)
        rings.append([{"index": i, "key": o["key"], "mask": o["mask"], "txid": o["txid"], "height": o["height"]}
                      for i, o in zip(absolute, outs["outs"])])
    return rings


def full_hex(tx):
    # Nodes return miner transactions as pruned_as_hex + prunable_as_hex, not as_hex.
    return tx["as_hex"] or (tx["pruned_as_hex"] + tx["prunable_as_hex"])


def record(net, name, tx, base):
    j = json.loads(tx["as_json"]) if tx["as_json"] else None
    if j is None:  # miner tx: decode_as_json is not returned either
        j = {"vin": [{"gen": {}}], "vout": [None] * len(tx["output_indices"])}
    is_coinbase = "gen" in j["vin"][0]
    second = NODES[net][1]
    tx2 = get_txs(second, [tx["tx_hash"]])[0]
    if full_hex(tx2) != full_hex(tx) or not full_hex(tx):
        raise RuntimeError(f"{tx['tx_hash']}: nodes disagree or no hex")
    return {
        "name": name,
        "network": net,
        "hash": tx["tx_hash"],
        "block_height": tx["block_height"],
        "prunable_hash": tx.get("prunable_hash", ""),
        "rct_type": rct_type(j),
        "inputs": len(j["vin"]),
        "outputs": len(j["vout"]),
        "coinbase": is_coinbase,
        "hex": full_hex(tx),
        "rings": [] if is_coinbase else rings_for(base, j),
        "sources": NODES[net],
    }


def find(net, pred, start):
    base = NODES[net][0]
    top = call(base, "get_info", {})["height"] - 20
    h = start or top
    for _ in range(400):
        blk, txs = block_txs(net, base, h)
        for tx in txs:
            if pred(json.loads(tx["as_json"])):
                return tx, blk
        h = h + 1 if start else h - 1
    raise RuntimeError("shape not found")


def main():
    out = {"generator": "tools/fixtures/fetch_chain_fixtures.py", "txs": []}
    seen = set()
    coinbase_done = set()
    for name, net, pred, start in SHAPES:
        tx, blk = find(net, pred, start)
        if tx["tx_hash"] in seen:
            # Same tx satisfies several shapes: record the alias instead of dropping it.
            for rec in out["txs"]:
                if rec["hash"] == tx["tx_hash"]:
                    rec.setdefault("aliases", []).append(name)
            continue
        seen.add(tx["tx_hash"])
        out["txs"].append(record(net, name, tx, NODES[net][0]))
        sys.stderr.write(f"{name}: {tx['tx_hash']} @ {tx['block_height']}\n")
        if net not in coinbase_done:
            miner = blk["miner_tx_hash"]
            mtx = get_txs(NODES[net][0], [miner])[0]
            out["txs"].append(record(net, f"{net}_coinbase", mtx, NODES[net][0]))
            coinbase_done.add(net)
            sys.stderr.write(f"{net}_coinbase: {miner}\n")
    json.dump(out, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
