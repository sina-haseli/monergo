#!/usr/bin/env python3
"""Extract the test cases in monero tests/unit_tests/base58.cpp into JSON.

Usage:
  python3 -I tools/fixtures/extract_base58_tests.py base58.cpp > \
      internal/testvectors/data/base58_unit_tests.json

Byte strings are emitted as hex. Only the macro-table tests are extracted; the
get_account_address_* tests at the end are reproduced by hand in address_test.go.
"""
import json
import re
import sys


def cstr(lits):
    """Concatenate adjacent C string literals and decode \\xHH and \\0 escapes."""
    out = bytearray()
    for lit in re.findall(r'"((?:[^"\\]|\\.)*)"', lits):
        i = 0
        while i < len(lit):
            c = lit[i]
            if c == "\\":
                n = lit[i + 1]
                if n == "x":
                    m = re.match(r"[0-9A-Fa-f]{1,2}", lit[i + 2:])
                    out.append(int(m.group(0), 16))
                    i += 2 + len(m.group(0))
                    continue
                if n == "0":
                    out.append(0)
                    i += 2
                    continue
                raise ValueError(f"unsupported escape \\{n}")
            out.append(ord(c))
            i += 1
    return out


def main():
    src = open(sys.argv[1], encoding="utf-8").read()
    # Join macro invocations that span several lines.
    calls = re.findall(r"^(TEST_\w+)\((.*?)\);", src, re.M | re.S)
    res = {k: [] for k in ("encode_block", "decode_block_pos", "decode_block_neg", "encode",
                           "decode_pos", "decode_neg", "encode_decode_addr", "decode_addr_neg")}
    for name, args in calls:
        name = name[len("TEST_"):]
        if name not in res:
            continue
        if name == "encode_block":
            data, enc = args.rsplit(",", 1)
            res[name].append({"data": cstr(data).hex(), "enc": enc.strip()})
        elif name in ("decode_block_pos", "decode_pos"):
            enc, data = args.split(",", 1)
            res[name].append({"enc": enc.strip(), "data": cstr(data).hex()})
        elif name in ("decode_block_neg", "decode_neg"):
            res[name].append({"enc": args.strip()})
        elif name == "encode":
            enc, data = args.split(",", 1)
            res[name].append({"enc": enc.strip(), "data": cstr(data).hex()})
        elif name == "encode_decode_addr":
            addr, tag, data = args.split(",", 2)
            res[name].append({"addr": addr.strip(), "tag": str(int(tag.strip(), 0)), "data": cstr(data).hex()})
        elif name == "decode_addr_neg":
            lit, test = args.rsplit(",", 1)
            res[name].append({"addr_hex": cstr(lit).hex(), "name": test.strip()})
    json.dump(res, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
