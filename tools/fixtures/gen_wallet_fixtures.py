#!/usr/bin/env python3
"""Generate address/seed fixtures with the official Monero wallet (wallet2).

Runs monero-wallet-rpc --offline (no network, no daemon) once per network, restores
each seed and records what the reference wallet reports. Output is JSON on stdout.

Usage:
  python3 -I tools/fixtures/gen_wallet_fixtures.py /path/to/monero-wallet-rpc > \
      internal/testvectors/data/wallet_fixtures.json

The seeds are the public test seeds from monero tests/functional_tests/transfer.py.
They hold no funds of value; never reuse them.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

SEEDS = [
    "velvet lymph giddy number token physics poetry unquoted nibs useful sabotage limits benches lifestyle eden nitrogen anvil fewest avoid batch vials washing fences goat unquoted",
    "peeled mixture ionic radar utopia puddle buying illness nuns gadget river spout cavernous bounced paradise drunk looking cottage jump tequila melting went winter adjust spout",
    "dilute gutter certain antics pamphlet macro enjoy left slid guarded bogeys upload nineteen bomb jubilee enhanced irritate turnip eggs swung jukebox loudly reduce sedan slid",
]
NETWORKS = ["mainnet", "testnet", "stagenet"]
PAYMENT_ID = "1234567890abcdef"
PORT = 38199


def rpc(method, params=None):
    body = json.dumps({"jsonrpc": "2.0", "id": "0", "method": method, "params": params or {}}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/json_rpc", body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        resp = json.load(r)
    if "error" in resp:
        raise RuntimeError(f"{method}: {resp['error']}")
    return resp["result"]


def wait_ready(proc):
    for _ in range(120):
        if proc.poll() is not None:
            raise RuntimeError("monero-wallet-rpc exited early")
        try:
            rpc("get_version")
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("monero-wallet-rpc did not start")


def collect(net, seed, i):
    name = f"w{i}"
    rpc("restore_deterministic_wallet", {"filename": name, "seed": seed, "password": "", "restore_height": 0, "language": "English"})
    version = rpc("get_version")["version"]
    out = {
        "seed": seed,
        "spend_key": rpc("query_key", {"key_type": "spend_key"})["key"],
        "view_key": rpc("query_key", {"key_type": "view_key"})["key"],
        "mnemonic": rpc("query_key", {"key_type": "mnemonic"})["key"],
        "addresses": [],
    }
    # (0,1..5)
    for _ in range(5):
        rpc("create_address", {"account_index": 0})
    # (1,0..2)
    rpc("create_account")
    for _ in range(2):
        rpc("create_address", {"account_index": 1})
    for major, minors in ((0, range(0, 6)), (1, range(0, 3))):
        res = rpc("get_address", {"account_index": major, "address_index": list(minors)})
        for a in res["addresses"]:
            out["addresses"].append({"major": major, "minor": a["address_index"], "address": a["address"]})
    integ = rpc("make_integrated_address", {"payment_id": PAYMENT_ID})
    out["integrated"] = {"payment_id": PAYMENT_ID, "address": integ["integrated_address"]}
    rpc("close_wallet")
    return out, version


def main():
    binary = sys.argv[1]
    result = {"generator": "tools/fixtures/gen_wallet_fixtures.py", "networks": {}}
    for net in NETWORKS:
        with tempfile.TemporaryDirectory() as wdir:
            args = [binary, "--offline", "--disable-rpc-login", "--non-interactive",
                    f"--rpc-bind-port={PORT}", f"--wallet-dir={wdir}",
                    f"--shared-ringdb-dir={os.path.join(wdir, 'ringdb')}", "--log-level=0"]
            if net != "mainnet":
                args.append(f"--{net}")
            proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=wdir)
            try:
                wait_ready(proc)
                wallets = []
                for i, seed in enumerate(SEEDS):
                    w, version = collect(net, seed, i)
                    wallets.append(w)
                result["wallet_rpc_version"] = version
                result["networks"][net] = wallets
            finally:
                proc.terminate()
                proc.wait(timeout=30)
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
